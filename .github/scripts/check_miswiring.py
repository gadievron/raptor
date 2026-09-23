#!/usr/bin/env python3
"""Dead-code / miswiring detector for the RAPTOR tree (daily CI scan).

Self-contained, stdlib-only.  Six detector classes over the checkout:

  kwargs     kwarg/signature mismatches at conservatively-resolved call
             sites (unknown kwarg, missing required arg, too many
             positionals, call through a missing method/attr)
  imports    ``from x import name`` where the in-repo module ``x`` has
             no such name (the classic silently-swallowed ImportError)
  dead       defs with zero references anywhere (AST names/attrs,
             string literals, imports, non-Python text corpus)
  artifacts  write-only / reader-orphan run-artifact filenames
  swallowed  silently-swallowed-exception census (informational; the
             cross-referenced miswirings fail via kwargs/imports)
  plumbing   config fields / CLI flags / env vars parsed but never read

Extraction is SINGLE-PASS and parallel: one AST visitor per file
collects every fact the six detectors consume (see the fact schema
above ``Module``), fanned out across worker processes; the detectors
are pure joins over the per-file fact tables in the parent.  Detector
logic and output are unchanged from the walk-per-detector version.

CI semantics (baseline pattern, cf. ``sarif_known_fp_suppressions.py``):
findings are keyed WITHOUT line numbers (class + file + symbol) and
compared against ``miswiring_baseline.json`` next to this script.  A
finding not in the baseline fails the run — fix it or (deliberately,
with a note) add it to the baseline.  Baseline entries that no longer
fire are reported as stale warnings and do not fail.

Usage:
    python3 .github/scripts/check_miswiring.py            # CI mode
    python3 .github/scripts/check_miswiring.py --root <tree>
    python3 .github/scripts/check_miswiring.py --write-baseline
    python3 .github/scripts/check_miswiring.py --census   # swallow census
    python3 .github/scripts/check_miswiring.py --json out.json
    python3 .github/scripts/check_miswiring.py --jobs 1   # in-process

Exit codes: 0 clean (stale-only is clean), 1 new findings, 2 usage error.
Precision over recall: anything ambiguous is suppressed and counted.
"""

import argparse
import ast
import json
import os
import pickle
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path

# ---------------------------------------------------------------- walking

SKIP_DIR_NAMES = {
    ".git", "__pycache__", "node_modules", "out", ".out", ".tox", ".venv",
    "venv", "build", "dist", "fixtures", "seeds", ".claude/worktrees",
    "data",  # packaged datasets (packages/sca/data is 35MB of JSON)
}

# Artifact-name dirs that are also legitimate RUNTIME PACKAGE names.
# A bare-name skip on "build" silently dropped core/build (~2k lines
# of build detection) from the whole liveness index — symbols only
# core/build consumes looked dead, and its own fields could never be
# flagged. Same disambiguation the env-docs gate uses: a dir carrying
# __init__.py is a tracked source package, not an artifact tree.
# Failure direction is safe both ways: a stray artifact tree that
# happens to carry a top-level __init__.py fails toward over-scanning
# (more corpus), never toward suppressing a finding — and CI scans a
# clean checkout.
PACKAGE_AMBIGUOUS_SKIP_NAMES = {"build", "dist", "out"}


def _is_skipped_dir_part(root: Path, rel_parts: tuple, i: int) -> bool:
    part = rel_parts[i]
    if part not in SKIP_DIR_NAMES:
        return False
    if part in PACKAGE_AMBIGUOUS_SKIP_NAMES:
        d = root.joinpath(*rel_parts[: i + 1])
        if (d / "__init__.py").is_file():
            return False
    return True
MAX_TEXT_FILE = 262_144   # text-corpus per-file cap (reference scanning only)
# text corpus extensions for reference scanning (non-Python)
TEXT_EXTS = {".sh", ".md", ".yml", ".yaml", ".toml", ".json", ".cfg", ".ini",
             ".txt", ".sql", ".service", ""}

PY_ROOTS = ["core", "packages", "plugins", "libexec", "engine"]

# Reference-text-only roots: files here never join the Python index,
# but their text joins the reference corpus so symbols invoked from
# skill instructions, docs, launcher shims or CI scripts are not
# misclassified as dead (e.g. a method the exploit-dev skill tells
# the LLM to call, or a function documented in docs/architecture.md).
TEXT_ROOTS = ["docs", ".claude", "bin", "tiers", ".github"]
TEXT_ROOT_SKIP = SKIP_DIR_NAMES | {"worktrees"}

# The baseline must never join the reference corpus: its keys name every
# baselined symbol and artifact, so indexing it would self-suppress
# exactly the findings it records — a baselined dead symbol or orphan
# config field could never fire (or go genuinely stale) again, and the
# census would silently go vacuous.
CORPUS_EXCLUDE_NAMES = {"miswiring_baseline.json"}


def iter_text_root_files(root: Path):
    for sub in TEXT_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            rel_parts = p.relative_to(root).parts
            if any(part in TEXT_ROOT_SKIP for part in rel_parts):
                continue
            yield p


def iter_files(root: Path):
    for sub in PY_ROOTS + ["."]:
        base = root / sub if sub != "." else root
        if not base.is_dir():
            continue
        if sub == ".":
            for p in sorted(base.glob("*.py")):
                yield p
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            rel_parts = p.relative_to(root).parts
            if any(
                _is_skipped_dir_part(root, rel_parts, i)
                for i in range(len(rel_parts) - 1)
            ):
                continue
            yield p


def is_python_file(p: Path) -> bool:
    if p.suffix == ".py":
        return True
    if p.suffix == "" and p.parent.name == "libexec":
        try:
            head = p.open("rb").read(64)
        except OSError:
            return False
        return b"python" in head.split(b"\n", 1)[0]
    return False


# ---------------------------------------------------------------- indexing

class FuncDef:
    __slots__ = (
        "args",
        "cls",
        "decorators",
        "defaults",
        "end_lineno",
        "is_method",
        "kw_defaults",
        "kwarg",
        "kwonly",
        "lineno",
        "module",
        "name",
        "nested",
        "own_refs",
        "path",
        "posonly",
        "qualname",
        "vararg",
    )

    def __init__(self, module, qualname, name, node, cls, path, nested) -> None:
        self.module = module
        self.qualname = qualname
        self.name = name
        self.cls = cls          # enclosing ClassInfo or None
        self.path = path
        self.lineno = node.lineno
        self.end_lineno = node.end_lineno
        self.nested = nested
        a = node.args
        self.posonly = [x.arg for x in a.posonlyargs]
        self.args = [x.arg for x in a.args]
        self.vararg = a.vararg.arg if a.vararg else None
        self.kwonly = [x.arg for x in a.kwonlyargs]
        self.kwarg = a.kwarg.arg if a.kwarg else None
        self.defaults = len(a.defaults)
        self.kw_defaults = [d is not None for d in a.kw_defaults]
        self.decorators = [dec_name(d) for d in node.decorator_list]
        self.is_method = cls is not None
        # references to this def's own name (Name loads / Attribute attrs)
        # inside its own body, decorators included — mirrors what
        # ``ast.walk(fd.node)`` used to count for the dead-symbol pass
        self.own_refs = 0

    # -- signature helpers ------------------------------------------------
    def positional_params(self, bound: bool):
        params = self.posonly + self.args
        if bound and params and params[0] in ("self", "cls"):
            params = params[1:]
        return params

    def required_params(self, bound: bool):
        pos = self.posonly + self.args
        n_opt = self.defaults
        req = pos[: len(pos) - n_opt] if n_opt else pos
        if bound and req and req[0] in ("self", "cls"):
            req = req[1:]
        req_kw = [k for k, has in zip(self.kwonly, self.kw_defaults) if not has]
        return req, req_kw

    def all_kw_names(self, bound: bool):
        names = set(self.posonly) | set(self.args) | set(self.kwonly)
        # posonly can't be passed by keyword, but flagging kw that matches a
        # posonly name as "unknown" would be wrong-ish; treat as known.
        if bound:
            names.discard("self")
            names.discard("cls")
        return names


class ClassInfo:
    __slots__ = (
        "bases",
        "decorators",
        "field_ann_words",
        "fields",
        "lineno",
        "methods",
        "module",
        "name",
        "own_refs",
        "path",
        "qualname",
    )

    def __init__(self, module, name, qualname, node, path) -> None:
        self.module = module
        self.name = name
        self.qualname = qualname
        self.lineno = node.lineno
        self.path = path
        self.bases = [dec_name(b) for b in node.bases]
        self.methods = {}       # name -> FuncDef
        self.decorators = [dec_name(d) for d in node.decorator_list]
        self.fields = []        # (name, lineno) AnnAssign class fields
        # identifier words in direct-body AnnAssign annotations (raw,
        # unfiltered) — the nested-dataclass serialization closure
        # intersects them with the global class-name set
        self.field_ann_words = set()
        # references to this class's own name inside its own subtree —
        # mirrors what ``ast.walk(ci.node)`` used to count
        self.own_refs = 0


def dec_name(node) -> str:
    """Dotted name of a decorator/base expression, '' if not a simple name."""
    if isinstance(node, ast.Call):
        return dec_name(node.func)
    if isinstance(node, ast.Attribute):
        base = dec_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Subscript):
        return dec_name(node.value)
    return ""


# ------------------------------------------------------------ fact schema
#
# One visitor pass per file collects every fact the detectors consume.
# All facts are plain picklable values (no AST nodes cross the process
# boundary).  Where the old per-detector ``ast.walk`` order was output-
# visible (findings order, dict-insertion order of suppression
# counters), facts carry a (depth, dfs_seq) key and are sorted with it:
# ``ast.walk`` is breadth-first, and for nodes of equal depth BFS order
# equals DFS pre-order, so sorting DFS-collected facts by (depth, seq)
# reproduces the walk order exactly.
#
# Detector -> facts consumed (old traversal -> fact kind):
#   kwargs     call_sites (call shape, arg shape, enclosing-class
#              binding for self/cls), assigned_attrs (attribute
#              assignments, setattr literals, class-body bindings),
#              plus defs/imports/classes below
#   imports    import_uses, top_names, star_import, has_module_getattr
#   dead       funcs/classes (+ per-def own_refs), name_load_counts,
#              attr_load_counts, str_words, import_uses, text corpus
#   artifacts  artifact_occs (string-literal artifact names classified
#              write/read/mention in the worker, incl. the atomic-write
#              and locator-idiom expansions), text corpus
#   swallowed  swallow_findings (fully classified in the worker except
#              the kwargs/imports cross-reference, joined in the
#              parent), swallow_not_silent suppression count
#   plumbing   classes/fields, ser_events + ser_marks (wholesale-
#              serialization evidence), add_arg_sites (argparse flags),
#              env_read_names / env_write_events (regex over source),
#              word_tokens (\bNAME\b word-search equivalence set),
#              attr/name/str counters, text corpus

class Module:
    __slots__ = (
        "add_arg_sites",
        "all_exports",
        "artifact_occs",
        "assigned_attrs",
        "attr_load_counts",
        "call_sites",
        "classes",
        "env_read_names",
        "env_write_events",
        "funcs",
        "has_module_getattr",
        "import_modules",
        "import_uses",
        "imports",
        "modnames",
        "name_load_counts",
        "ser_events",
        "ser_marks",
        "star_import",
        "str_words",
        "swallow_findings",
        "swallow_not_silent",
        "top_names",
        "word_tokens",
        "path",
    )

    def __init__(self, path, modnames) -> None:
        self.path = path
        self.modnames = modnames        # list of dotted aliases
        self.funcs = []                 # all FuncDefs (incl. methods, nested)
        self.classes = {}               # name -> ClassInfo
        self.imports = {}               # local alias -> ("mod"|"sym", target)
        self.import_modules = {}        # alias -> dotted module
        self.top_names = set()          # all top-level bindings
        self.star_import = False
        self.has_module_getattr = False
        self.all_exports = None
        self.name_load_counts = Counter()   # Name loads per identifier
        self.attr_load_counts = Counter()   # Attribute attr per identifier
        self.str_words = Counter()      # identifier-ish words in str constants
        self.import_uses = []           # (imported symbol name, from module)
        self.assigned_attrs = set()     # attr names ever assigned (kwargs)
        self.call_sites = []            # walk-ordered call-site facts
        self.artifact_occs = []         # (base, lineno, cls, is_test)
        self.swallow_findings = []      # walk-ordered dicts, xref placeholder
        self.swallow_not_silent = 0
        self.ser_events = []            # walk-ordered ident-type events
        self.ser_marks = []             # serialization-argument descriptors
        self.add_arg_sites = []         # (lineno, opt, dest)
        self.env_read_names = set()
        self.env_write_events = []      # (name, "global"|"child_env")
        self.word_tokens = frozenset()  # \bWORD\b-equivalent token set


IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
UPPER_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9_]+\b")


# --------------------------------------------------- single-pass extraction

class _FactVisitor(ast.NodeVisitor):
    """One traversal collecting every per-file fact (schema above)."""

    def __init__(self, m: Module, lines: list, rel_noext_parts: tuple) -> None:
        self.m = m
        self.lines = lines
        self.rel_noext_parts = rel_noext_parts
        self.class_stack = []
        self.func_stack = []
        self._depth = 0
        self._seq = 0
        self.is_test = ("tests" in m.path.parts
                        or m.path.name.startswith("test_"))
        # (depth, seq)-keyed buffers, sorted to walk order after the pass
        self.art_raw = []       # (depth, seq, lineno, base)
        self.call_raw = []      # (depth, seq, site-tuple)
        self.swallow_raw = []   # (depth, seq, [finding, ...])
        self.ser_ev_raw = []    # (depth, seq, event-tuple)
        self.addarg_raw = []    # (depth, seq, (lineno, opt, dest))
        self._dispatch = {
            ast.ClassDef: self.handle_classdef,
            ast.FunctionDef: self.handle_def,
            ast.AsyncFunctionDef: self.handle_def,
            ast.Import: self.handle_import,
            ast.ImportFrom: self.handle_importfrom,
            ast.Assign: self.handle_assign,
            ast.AugAssign: self.handle_augassign,
            ast.AnnAssign: self.handle_annassign,
            ast.Name: self.handle_name,
            ast.Attribute: self.handle_attribute,
            ast.Constant: self.handle_constant,
            ast.Call: self.handle_call,
            ast.With: self.handle_with,
            ast.Try: self.handle_try,
        }

    def visit(self, node) -> None:
        self._seq += 1
        self._depth += 1
        handler = self._dispatch.get(type(node))
        if handler is not None:
            handler(node)
        else:
            self.generic_visit(node)
        self._depth -= 1

    # -- defs / classes ---------------------------------------------------

    def handle_classdef(self, node) -> None:
        m = self.m
        qual = ".".join([c.name for c in self.class_stack] + [node.name])
        ci = ClassInfo(m, node.name, qual, node, m.path)
        if not self.class_stack and not self.func_stack:
            m.classes[node.name] = ci
            m.top_names.add(node.name)
        self.class_stack.append(ci)
        for stmt in node.body:
            if isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name):
                    ci.fields.append((stmt.target.id, stmt.lineno))
                    m.assigned_attrs.add(stmt.target.id)
                ci.field_ann_words |= _ann_words(stmt.annotation)
            elif isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name):
                        m.assigned_attrs.add(t.id)
            elif isinstance(stmt, (ast.ClassDef, ast.FunctionDef,
                                   ast.AsyncFunctionDef)):
                # Nested classes (and methods of NESTED classes, which
                # ClassInfo.methods does not model) are class attributes
                # too — `self._Session(self)` on a class-body
                # `class _Session:` is valid.  This runs for EVERY
                # ClassDef, so it also admits the method names of all
                # top-level classes repo-wide into the missing_method
                # suppression set: `self.X()` is suppressed when X is a
                # method of ANY class, not just this one.  Deliberately
                # conservative — a false missing_method finding in the
                # daily gate costs more than a suppressed true one.
                m.assigned_attrs.add(stmt.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def handle_def(self, node) -> None:
        m = self.m
        cls = self.class_stack[-1] if self.class_stack else None
        nested = bool(self.func_stack) or len(self.class_stack) > 1
        prefix = ".".join([c.name for c in self.class_stack]
                          + [f.name for f in self.func_stack])
        qual = f"{prefix}.{node.name}" if prefix else node.name
        fd = FuncDef(m, qual, node.name, node,
                     cls if not self.func_stack else None, m.path, nested)
        m.funcs.append(fd)
        if cls is not None and not self.func_stack and len(self.class_stack) == 1:
            cls.methods[node.name] = fd
        if not self.class_stack and not self.func_stack:
            m.top_names.add(node.name)
        # serialization ident-typing: annotated parameters
        a = node.args
        arg_words = tuple(
            (arg.arg, frozenset(_ann_words(arg.annotation)))
            for arg in a.posonlyargs + a.args + a.kwonlyargs
            if arg.annotation is not None)
        if arg_words:
            self.ser_ev_raw.append(
                (self._depth, self._seq, ("args", arg_words)))
        self.func_stack.append(fd)
        self.generic_visit(node)
        self.func_stack.pop()

    # -- imports ------------------------------------------------------------

    def handle_import(self, node) -> None:
        m = self.m
        for al in node.names:
            alias = al.asname or al.name.split(".")[0]
            target = al.name if al.asname else al.name.split(".")[0]
            m.imports[alias] = ("mod", al.name if al.asname else target)
            m.import_modules[alias] = al.name if al.asname else target
            if not self.class_stack and not self.func_stack:
                m.top_names.add(alias)
        self.generic_visit(node)

    def handle_importfrom(self, node) -> None:
        m = self.m
        if node.level:      # relative import: resolve against file path
            # parts[:-level] is correct for both plain modules and
            # __init__.py: with_suffix("") already strips the
            # filename component that distinguishes them.
            base_parts = self.rel_noext_parts[:-node.level]
            mod = ".".join(base_parts + tuple((node.module or "").split(".")
                                              if node.module else ()))
        else:
            mod = node.module or ""
        for al in node.names:
            if al.name == "*":
                m.star_import = True
                continue
            alias = al.asname or al.name
            m.imports[alias] = ("sym", f"{mod}.{al.name}")
            m.import_uses.append((al.name, mod, node.lineno))
            if not self.class_stack and not self.func_stack:
                m.top_names.add(alias)
        self.generic_visit(node)

    # -- assignments ----------------------------------------------------

    def _attr_targets(self, targets) -> None:
        for t in targets:
            if isinstance(t, (ast.Tuple, ast.List)):
                for elt in t.elts:
                    if isinstance(elt, ast.Attribute):
                        self.m.assigned_attrs.add(elt.attr)
            elif isinstance(t, ast.Attribute):
                self.m.assigned_attrs.add(t.attr)

    def handle_assign(self, node) -> None:
        m = self.m
        for t in node.targets:
            if isinstance(t, ast.Name):
                if not self.class_stack and not self.func_stack:
                    m.top_names.add(t.id)
                if t.id == "__all__" and isinstance(node.value, (ast.List, ast.Tuple)):
                    m.all_exports = [e.value for e in node.value.elts
                                     if isinstance(e, ast.Constant)
                                     and isinstance(e.value, str)]
            elif isinstance(t, (ast.Tuple, ast.List)):
                # tuple-unpack: A, B, C = 0, 1, 2
                for el in t.elts:
                    if isinstance(el, ast.Name) and not self.class_stack \
                            and not self.func_stack:
                        m.top_names.add(el.id)
        self._attr_targets(node.targets)
        # serialization ident-typing: x = ClassName(...)
        if isinstance(node.value, ast.Call):
            cname = dec_name(node.value.func).rsplit(".", 1)[-1]
            if cname:
                idents = tuple(
                    t.id if isinstance(t, ast.Name) else t.attr
                    for t in node.targets
                    if isinstance(t, (ast.Name, ast.Attribute)))
                if idents:
                    self.ser_ev_raw.append(
                        (self._depth, self._seq, ("assign", idents, cname)))
        self.generic_visit(node)

    def handle_augassign(self, node) -> None:
        self._attr_targets([node.target])
        self.generic_visit(node)

    def handle_annassign(self, node) -> None:
        m = self.m
        if (isinstance(node.target, ast.Name) and not self.class_stack
                and not self.func_stack):
            m.top_names.add(node.target.id)
        self._attr_targets([node.target])
        # serialization ident-typing: x: ClassName / self.x: ClassName
        if isinstance(node.target, (ast.Name, ast.Attribute)):
            ident = (node.target.id if isinstance(node.target, ast.Name)
                     else node.target.attr)
            self.ser_ev_raw.append(
                (self._depth, self._seq,
                 ("ann", ident, frozenset(_ann_words(node.annotation)))))
        self.generic_visit(node)

    # -- reference counting ----------------------------------------------

    def handle_name(self, node) -> None:
        if isinstance(node.ctx, ast.Load):
            n = node.id
            self.m.name_load_counts[n] += 1
            for fd in self.func_stack:
                if fd.name == n:
                    fd.own_refs += 1
            for ci in self.class_stack:
                if ci.name == n:
                    ci.own_refs += 1
        self.generic_visit(node)

    def handle_attribute(self, node) -> None:
        n = node.attr
        self.m.attr_load_counts[n] += 1
        for fd in self.func_stack:
            if fd.name == n:
                fd.own_refs += 1
        for ci in self.class_stack:
            if ci.name == n:
                ci.own_refs += 1
        if n == "__dict__":
            d = _mark_desc(node.value, self.class_stack)
            if d is not None:
                self.m.ser_marks.append(d)   # json.dumps(cfg.__dict__)
        self.generic_visit(node)

    def handle_constant(self, node) -> None:
        v = node.value
        if isinstance(v, str):
            if len(v) < 4000:
                sw = self.m.str_words
                for w in IDENT_RE.findall(v):
                    sw[w] += 1
            base = v.strip().rsplit("/", 1)[-1]
            if ARTIFACT_RE.match(base) and base not in COMMON_NONARTIFACTS:
                if "{" in base or "*" in base:
                    base = re.sub(r"\{[^}]*\}", "*", base)
                self.art_raw.append(
                    (self._depth, self._seq, node.lineno, base))
        # Constant nodes have no AST children; no recursion needed.

    # -- calls -------------------------------------------------------------

    def handle_call(self, node) -> None:
        m = self.m
        f = node.func
        # `self`/`cls` binds to the NEAREST enclosing function that
        # declares it as first parameter; only resolve against the
        # class when that function is the direct method (outermost
        # function level).  A nested `def do_POST(self)` closure
        # attached to some other class must not have its `self` calls
        # resolved against the lexically-enclosing class.
        cname = None
        if len(self.class_stack) == 1 and self.func_stack:
            owner = None
            for fd in reversed(self.func_stack):
                first = (fd.posonly + fd.args)[:1]
                if first in (["self"], ["cls"]):
                    owner = fd
                    break
            if owner is not None and owner is self.func_stack[0]:
                cname = self.class_stack[-1].name
        if isinstance(f, ast.Name):
            shape = ("name", f.id, None)
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            shape = ("attr", f.value.id, f.attr)
        else:
            shape = ("complex", None, None)
        has_star = any(isinstance(a, ast.Starred) for a in node.args)
        has_dstar = any(k.arg is None for k in node.keywords)
        kw_names = tuple(k.arg for k in node.keywords if k.arg is not None)
        npos = sum(1 for a in node.args if not isinstance(a, ast.Starred))
        self.call_raw.append(
            (self._depth, self._seq,
             (node.lineno, shape, cname, kw_names, has_star, has_dstar, npos)))
        # assigned-attr fact: setattr(obj, "attr", ...) with a literal name
        if (isinstance(f, ast.Name) and f.id == "setattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)):
            m.assigned_attrs.add(node.args[1].value)
        # argparse flag fact
        if isinstance(f, ast.Attribute) and f.attr == "add_argument":
            opt = None
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) \
                        and a.value.startswith("--"):
                    opt = a.value
            dest = None
            for k in node.keywords:
                if k.arg == "dest" and isinstance(k.value, ast.Constant):
                    dest = k.value.value
            if opt is not None or dest is not None:
                dest = dest or opt.lstrip("-").replace("-", "_")
                self.addarg_raw.append(
                    (self._depth, self._seq, (node.lineno, opt, dest)))
        # wholesale-serialization marks
        if isinstance(f, ast.Name) and f.id in _SERIALIZE_FREE_FNS \
                and node.args:
            self._mark(node.args[0])
        elif isinstance(f, ast.Attribute):
            base = dec_name(f.value).rsplit(".", 1)[-1]
            if (base, f.attr) in _SERIALIZE_MOD_FNS and node.args:
                self._mark(node.args[0])
            elif f.attr in _SERIALIZE_METHODS:
                self._mark(f.value)     # cfg.model_dump() / ._asdict()
        for kw in node.keywords:
            if kw.arg is None:
                self._mark(kw.value)    # writer(**cfg)
        self.generic_visit(node)

    def _mark(self, e) -> None:
        d = _mark_desc(e, self.class_stack)
        if d is not None:
            self.m.ser_marks.append(d)

    # -- swallowed exceptions ----------------------------------------------

    def handle_with(self, node) -> None:
        found = []
        for item in node.items:
            ce = item.context_expr
            if isinstance(ce, ast.Call) and dec_name(ce.func).endswith("suppress"):
                types = [dec_name(a) or "<expr>" for a in ce.args]
                broad = any(t in ("Exception", "BaseException") for t in types)
                span = (node.body[0].lineno,
                        node.body[-1].end_lineno or node.body[0].lineno)
                calls = []
                for b in node.body:
                    calls.extend(dec_name(n.func) or "<complex>"
                                 for n in ast.walk(b) if isinstance(n, ast.Call))
                found.append({
                    "kind": "swallowed_exception",
                    "file": str(self.m.path), "line": node.lineno,
                    "func_span": span,
                    "types": types, "broad": broad,
                    "category": "contextlib_suppress",
                    "in_test": self.is_test,
                    "would_eat_miswire": broad or any(
                        t in ("TypeError", "AttributeError", "KeyError",
                              "ImportError")
                        for t in types),
                    "miswire_xref_lines": [],   # joined in the parent
                    "try_calls": sorted(set(calls))[:12],
                })
        if found:
            self.swallow_raw.append((self._depth, self._seq, found))
        self.generic_visit(node)

    def handle_try(self, node) -> None:
        found = []
        try_span = (node.body[0].lineno,
                    node.body[-1].end_lineno or node.body[0].lineno)
        for h in node.handlers:
            res = classify_handler(h, self.lines)
            if res is None:
                self.m.swallow_not_silent += 1
                continue
            cat, _stmts = res
            types, broad = exc_types(h)
            # calls made in try body (for triage aid)
            calls = []
            for b in node.body:
                for n in ast.walk(b):
                    if isinstance(n, ast.Call):
                        calls.append(dec_name(n.func) or "<complex>")
            found.append({
                "kind": "swallowed_exception",
                "file": str(self.m.path), "line": h.lineno,
                "func_span": try_span,
                "types": types, "broad": broad, "category": cat,
                "in_test": self.is_test,
                "would_eat_miswire": broad or any(
                    t in ("TypeError", "AttributeError", "KeyError")
                    for t in types),
                "miswire_xref_lines": [],       # joined in the parent
                "try_calls": sorted(set(calls))[:12],
            })
        if found:
            self.swallow_raw.append((self._depth, self._seq, found))
        self.generic_visit(node)


def _ann_words(node) -> set:
    """Raw identifier words in a type annotation (incl. string forms).

    The unfiltered counterpart of the old ``_annotation_classes``: the
    parent intersects with the global class-name set, which is only
    known after every file is parsed.
    """
    found = set()
    if node is None:
        return found
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            found.add(n.id)
        elif isinstance(n, ast.Attribute):
            found.add(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            found.update(IDENT_RE.findall(n.value))
    return found


def _mark_desc(e, class_stack):
    """Picklable descriptor for a wholesale-serialization argument.

    Mirrors the old ``Ser._type_of`` shape analysis; the parent resolves
    the descriptor against the module's replayed ident-type map and the
    global class-name set.
    """
    if isinstance(e, ast.Name):
        if e.id in ("self", "cls") and class_stack:
            return ("const", class_stack[-1].name)
        return ("name", e.id)
    if isinstance(e, ast.Attribute):
        if e.attr == "__dict__":
            return _mark_desc(e.value, class_stack)
        return ("attrname", e.attr)
    if isinstance(e, ast.Call):
        cname = dec_name(e.func).rsplit(".", 1)[-1]
        if cname:
            return ("call", cname)
    return None


def parse_module(path: Path, root: Path):
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except (SyntaxError, ValueError, OSError):
        return None
    rel = path.relative_to(root)
    modnames = []
    if path.suffix == ".py":
        dotted = ".".join(rel.with_suffix("").parts)
        modnames.append(dotted)
        parts = rel.with_suffix("").parts
        # packages/<pkg>/... is importable as <pkg>... in this repo
        if parts[0] == "packages" and len(parts) > 1:
            modnames.append(".".join(parts[1:]))
    else:
        modnames.append(str(rel))
    m = Module(path, modnames)
    lines = src.splitlines()

    v = _FactVisitor(m, lines, rel.with_suffix("").parts)
    v.visit(tree)
    if "__getattr__" in m.top_names:
        m.has_module_getattr = True

    # ast.walk-ordered fact lists (see the fact-schema note: BFS order
    # == sort of DFS pre-order by (depth, seq))
    m.call_sites = [t[2] for t in sorted(v.call_raw)]
    m.ser_events = [t[2] for t in sorted(v.ser_ev_raw)]
    m.add_arg_sites = [t[2] for t in sorted(v.addarg_raw)]
    for _d, _s, found in sorted(v.swallow_raw):
        m.swallow_findings.extend(found)

    # -- artifact occurrences (write/read/mention classification) --------
    raw = []
    n_lines = len(lines)
    for _d, _s, lineno, base in sorted(v.art_raw):
        line = lines[lineno - 1] if lineno <= n_lines else ""
        ctx = "\n".join(lines[max(0, lineno - 2): lineno + 2])
        if WRITE_HINTS.search(line) or WRITE_HINTS.search(ctx):
            cls = "write"
        elif READ_HINTS.search(line) or READ_HINTS.search(ctx):
            cls = "read"
        else:
            cls = "mention"
        raw.append((base, lineno, cls, v.is_test))
    write_lines = defaultdict(list)     # base -> write-classified linenos
    for base, lineno, cls, _t in raw:
        if cls == "write":
            write_lines[base].append(lineno)
    for base, lineno, cls, is_test in raw:
        m.artifact_occs.append((base, lineno, cls, is_test))
        if cls != "write" and _in_atomic_write_fn(m.funcs, lines, lineno):
            # The literal names the DESTINATION of a tempfile-then-
            # rename write; the accumulate-guard window classified it
            # read/mention.  Record the write as well — the occurrence
            # is both.
            m.artifact_occs.append((base, lineno, "write", is_test))
        if cls == "mention" and _locator_reads(m.funcs, lines, lineno,
                                               write_lines[base]):
            # The literal builds a candidate path inside a small
            # parsing helper; the open/parse sits below the window.
            # Record the read as well (the mention is kept, so this
            # can only suppress a write-only report, never mint an
            # orphan-reader finding).
            m.artifact_occs.append((base, lineno, "read", is_test))

    # -- env plumbing (regex over raw source) -----------------------------
    for m_ in ENVGET_RE.finditer(src):
        m.env_read_names.add(m_.group(1))
    for m_ in SHELLREAD_RE.finditer(src):
        m.env_read_names.add(m_.group(1))
    for m_ in ENVSET_PY_RE.finditer(src):
        name = next(g for g in m_.groups() if g)
        m.env_write_events.append(
            (name, "child_env" if m_.group(3) else "global"))
    m.word_tokens = frozenset(UPPER_TOKEN_RE.findall(src))
    return m


# ---------------------------------------------------- worker-pool plumbing

_WORKER_ROOT: Path = Path(".")


def _pool_init(root: str) -> None:
    global _WORKER_ROOT
    _WORKER_ROOT = Path(root)


def _extract_one(path_str: str) -> "Module | None":
    return parse_module(Path(path_str), _WORKER_ROOT)


def default_jobs() -> int:
    """Extraction worker count: available CPUs, capped at 8.

    The cap: past ~8 workers the run is dominated by the serial join
    phase and result-pickle IPC, not extraction — and the CI runners
    this gate lives on have 4 vCPUs anyway.  ``process_cpu_count``
    (3.13+) respects affinity masks; older floors fall back to
    ``cpu_count``.
    """
    cpus = getattr(os, "process_cpu_count", os.cpu_count)() or 1
    return max(1, min(cpus, 8))


# ---------------------------------------------------------------- repo index

class RepoIndex:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.modules = {}           # dotted name -> Module (first alias wins)
        self.module_list = []
        self.text_files = []        # (path, text) non-python corpus
        self.text_idents = set()    # all identifier-ish words in text corpus
        self.suppressions = Counter()

    def build(self, jobs: int = 1) -> None:
        py_paths = []
        text_paths = []
        for p in iter_files(self.root):
            if is_python_file(p):
                py_paths.append(p)
            elif p.suffix in TEXT_EXTS and p.stat().st_size < MAX_TEXT_FILE:
                text_paths.append(p)
        for p in iter_text_root_files(self.root):
            if (p.suffix in TEXT_EXTS or p.suffix == ".py") \
                    and p.stat().st_size < MAX_TEXT_FILE:
                text_paths.append(p)
        mods = None
        if jobs > 1 and len(py_paths) > 1:
            try:
                with ProcessPoolExecutor(
                        max_workers=jobs, initializer=_pool_init,
                        initargs=(str(self.root),)) as ex:
                    mods = list(ex.map(_extract_one,
                                       [str(p) for p in py_paths],
                                       chunksize=16))
            except (OSError, ImportError, BrokenProcessPool,
                    pickle.PicklingError) as exc:
                # Startup-shaped pool failures only (ImportError covers
                # platforms without sem_open) -> sequential.  The
                # pool is a wall-time optimisation: extraction is
                # per-file-deterministic, so falling back keeps the gate
                # alive (and output-identical) in environments where
                # worker processes cannot start.  A per-file exception
                # inside a worker is NOT caught here — it propagates
                # exactly as the in-process path would raise it.
                print(f"[miswiring] worker pool unavailable "
                      f"({exc.__class__.__name__}: {exc}); "
                      f"extracting in-process", file=sys.stderr)
                mods = None
        if mods is None:
            mods = [parse_module(p, self.root) for p in py_paths]
        for mod in mods:
            if mod is None:
                self.suppressions["unparseable_python"] += 1
                continue
            self.module_list.append(mod)
            for name in mod.modnames:
                self.modules.setdefault(name, mod)
            # package __init__ also answers for the package name
            if mod.path.name == "__init__.py":
                for name in mod.modnames:
                    pkg = name.rsplit(".", 1)[0] if "." in name else name
                    self.modules.setdefault(pkg, mod)
        for p in text_paths:
            self._add_text_file(p)

    def _add_text_file(self, p: Path) -> None:
        if p.name in CORPUS_EXCLUDE_NAMES:
            return
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        self.text_files.append((p, text))
        self.text_idents.update(IDENT_RE.findall(text))

    def resolve_module(self, dotted: str):
        if dotted in self.modules:
            return self.modules[dotted]
        return None

    def resolve_symbol(self, dotted: str):
        """dotted = mod.path.name -> (Module, name) if module in-repo."""
        if "." not in dotted:
            return None
        mod, name = dotted.rsplit(".", 1)
        m = self.resolve_module(mod)
        if m is not None:
            return (m, name)
        return None


# ------------------------------------------------------- (a) kwarg matcher

SAFE_DECORATORS = {
    "staticmethod", "classmethod", "property", "abstractmethod",
    "abc.abstractmethod", "functools.lru_cache", "lru_cache", "cache",
    "functools.cache", "override", "typing.override", "dataclass",
    "functools.wraps", "cached_property", "functools.cached_property",
    "contextmanager", "contextlib.contextmanager",
}
# contextmanager keeps the signature; wraps-decorated wrappers usually do too.
# NOTE: pytest.fixture is deliberately NOT safe — tests call the *yielded
# value*, not the fixture function, so its signature does not apply.


def _assigned_attribute_names(idx: RepoIndex) -> set:
    """Repo-wide set of attribute names that are ever ASSIGNED.

    Collected shapes (per-file, by the extraction visitor):
      * ``obj.attr = ...`` / ``obj.attr += ...`` / annotated form
        (any base object, not just self/cls — instance attributes are
        routinely attached from factory/setup code in other modules)
      * ``setattr(obj, "attr", ...)`` with a literal name
      * class-body bindings (``attr = callable`` / ``attr: T``) —
        class attributes may hold callables

    Consumed by the missing_method suppression: ``self.X()`` where X
    resolves to no method is only flagged when X is never assigned as
    an attribute anywhere. Repo-wide (not per-module) on purpose —
    a false missing_method finding in the daily gate costs more than
    a suppressed true positive.
    """
    names: set = set()
    for mod in idx.module_list:
        names |= mod.assigned_attrs
    return names


def check_calls(idx: RepoIndex):
    findings = []
    sup = Counter()
    assigned_attrs = _assigned_attribute_names(idx)

    # top-level plain-function defs by name, per module (join accelerator;
    # same first-match / candidate-count semantics as the old linear scan)
    top_funcs: dict = {}

    def module_top_funcs(mod: Module) -> dict:
        d = top_funcs.get(mod)
        if d is None:
            d = {}
            for fd in mod.funcs:
                if not fd.nested and fd.cls is None:
                    d.setdefault(fd.name, []).append(fd)
            top_funcs[mod] = d
        return d

    def resolve_name_target(mod: Module, name: str):
        """Resolve a bare name in `mod` to (kind, obj, bound)."""
        if name in mod.classes:
            return ("class", mod.classes[name])
        own = module_top_funcs(mod).get(name)
        if own:
            return ("func", own[0])
        if name in mod.imports:
            kind, target = mod.imports[name]
            if kind == "sym":
                r = idx.resolve_symbol(target)
                if r:
                    tmod, tname = r
                    if tname in tmod.classes:
                        return ("class", tmod.classes[tname])
                    cands = module_top_funcs(tmod).get(tname, [])
                    if len(cands) == 1:
                        return ("func", cands[0])
                    # re-exported through __init__? follow one hop
                    if tname in tmod.imports:
                        k2, t2 = tmod.imports[tname]
                        if k2 == "sym":
                            r2 = idx.resolve_symbol(t2)
                            if r2:
                                m2, n2 = r2
                                if n2 in m2.classes:
                                    return ("class", m2.classes[n2])
                                c2 = module_top_funcs(m2).get(n2, [])
                                if len(c2) == 1:
                                    return ("func", c2[0])
                    return None
        return None

    def class_init(ci: ClassInfo, seen=None):
        seen = seen or set()
        if ci.qualname in seen:
            return "ambiguous"
        seen.add(ci.qualname)
        if "__init__" in ci.methods:
            return ci.methods["__init__"]
        # walk in-repo bases; unresolvable base -> ambiguous
        for b in ci.bases:
            if b in ("object", "Exception", "ValueError", "RuntimeError"):
                continue
            target = None
            if b in ci.module.classes:
                target = ci.module.classes[b]
            elif b in ci.module.imports:
                k, t = ci.module.imports[b]
                if k == "sym":
                    r = idx.resolve_symbol(t)
                    if r and r[1] in r[0].classes:
                        target = r[0].classes[r[1]]
            if target is None:
                return "ambiguous"
            got = class_init(target, seen)
            if got != "no-init":
                return got
        return "no-init"

    def find_method(ci: ClassInfo, name: str, seen=None):
        seen = seen or set()
        if id(ci) in seen:
            return "ambiguous"
        seen.add(id(ci))
        if name in ci.methods:
            return ci.methods[name]
        for b in ci.bases:
            if b == "object":
                continue
            target = None
            if b in ci.module.classes:
                target = ci.module.classes[b]
            elif b in ci.module.imports:
                k, t = ci.module.imports[b]
                if k == "sym":
                    r = idx.resolve_symbol(t)
                    if r and r[1] in r[0].classes:
                        target = r[0].classes[r[1]]
            if target is None:
                return "ambiguous"
            got = find_method(target, name, seen)
            if got != "missing":
                return got
        return "missing"

    for mod in idx.module_list:
        for (lineno, shape, encl_cname, kw_names, has_star, has_dstar,
                npos) in mod.call_sites:
            target = None
            bound = False
            label = None
            skind, sbase, sattr = shape
            if skind == "name":
                r = resolve_name_target(mod, sbase)
                if r is None:
                    sup["unresolved_name"] += 1
                    continue
                kind, obj = r
                if kind == "class":
                    fd = class_init(obj, None)
                    if fd == "ambiguous":
                        sup["class_init_ambiguous"] += 1
                        continue
                    if fd == "no-init":
                        sup["class_no_init"] += 1
                        continue
                    target, bound, label = fd, True, f"{obj.name}()"
                else:
                    target, bound, label = obj, False, sbase
            elif skind == "attr":
                base = sbase
                if base in ("self", "cls"):
                    cname = encl_cname
                    if cname and cname in mod.classes:
                        got = find_method(mod.classes[cname], sattr)
                        if got == "ambiguous":
                            sup["self_method_base_unresolvable"] += 1
                            continue
                        if got == "missing":
                            # could be an attribute holding a callable; only
                            # flag if no attribute of that name is assigned
                            # anywhere in the repo and the class chain has
                            # no __getattr__ hook. (Pre-fix this searched
                            # for the SUBSTRING f"self.{attr}" in the module
                            # source — the call site itself contains it, so
                            # every self-call was suppressed and the
                            # detector was vacuous for its dominant shape.)
                            if (sattr in assigned_attrs
                                    or find_method(mod.classes[cname],
                                                   "__getattr__") != "missing"):
                                sup["self_attr_callable"] += 1
                                continue
                            findings.append({
                                "kind": "missing_method",
                                "file": str(mod.path), "line": lineno,
                                "sym": f"{cname}.{sattr}",
                                "detail": f"self.{sattr}() but no such method on {cname} or resolvable bases"})
                            continue
                        target, bound, label = got, True, f"self.{sattr}"
                    else:
                        sup["self_outside_known_class"] += 1
                        continue
                elif base in mod.import_modules:
                    tmod = idx.resolve_module(mod.import_modules[base])
                    if tmod is None:
                        sup["external_module_attr"] += 1
                        continue
                    if sattr in tmod.classes:
                        fd = class_init(tmod.classes[sattr], None)
                        if isinstance(fd, FuncDef):
                            target, bound, label = fd, True, f"{base}.{sattr}()"
                        else:
                            sup["class_init_ambiguous"] += 1
                            continue
                    else:
                        cands = module_top_funcs(tmod).get(sattr, [])
                        if len(cands) == 1:
                            target, bound, label = cands[0], False, f"{base}.{sattr}"
                        elif sattr not in tmod.top_names and not tmod.star_import \
                                and not tmod.has_module_getattr:
                            findings.append({
                                "kind": "missing_module_attr",
                                "file": str(mod.path), "line": lineno,
                                "sym": f"{tmod.modnames[0]}.{sattr}",
                                "detail": f"{base}.{sattr}() but {tmod.modnames[0]} has no top-level '{sattr}'"})
                            continue
                        else:
                            sup["module_attr_not_function"] += 1
                            continue
                else:
                    sup["attr_call_unresolved_base"] += 1
                    continue
            else:
                sup["complex_callee"] += 1
                continue

            if target is None:
                continue
            # decorator gate
            bad_dec = [d for d in target.decorators if d and d not in SAFE_DECORATORS]
            if bad_dec:
                sup["decorated_callee"] += 1
                continue
            if target.name != "__init__" and any(
                    d in ("classmethod",) for d in target.decorators):
                bound = True

            # unknown kwarg
            if not has_dstar and target.kwarg is None:
                known = target.all_kw_names(bound)
                findings.extend({
                            "kind": "unknown_kwarg",
                            "file": str(mod.path), "line": lineno,
                            "sym": f"{target.module.modnames[0]}:{target.qualname}:{kw}",
                            "detail": f"{label}(... {kw}=...) — callee "
                                   f"{target.module.modnames[0]}:{target.qualname} "
                                   f"accepts {sorted(known)}"} for kw in kw_names if kw not in known)
            elif has_dstar or target.kwarg is not None:
                sup["kwargs_open"] += 1

            # too many positionals
            if not has_star:
                pos_params = target.positional_params(bound)
                if target.vararg is None and npos > len(pos_params):
                    findings.append({
                        "kind": "too_many_positional",
                        "file": str(mod.path), "line": lineno,
                        "sym": f"{target.module.modnames[0]}:{target.qualname}",
                        "detail": f"{label}: {npos} positional args, callee "
                               f"{target.module.modnames[0]}:{target.qualname} "
                               f"takes {len(pos_params)}"})
                # missing required
                if not has_dstar:
                    req, req_kw = target.required_params(bound)
                    covered = set(req[:npos]) | set(kw_names)
                    missing = [p for p in req[npos:] if p not in covered]
                    missing += [p for p in req_kw if p not in kw_names]
                    if missing:
                        findings.append({
                            "kind": "missing_required",
                            "file": str(mod.path), "line": lineno,
                            "sym": f"{target.module.modnames[0]}:{target.qualname}:"
                                + ",".join(missing),
                            "detail": f"{label}: missing required {missing} of "
                                   f"{target.module.modnames[0]}:{target.qualname}"})
            else:
                sup["star_args"] += 1

    return findings, sup


# ------------------------------------------------- (a2) bad import targets

def check_imports(idx: RepoIndex):
    findings = []
    sup = Counter()
    for mod in idx.module_list:
        for name, from_mod, lineno in mod.import_uses:
            tmod = idx.resolve_module(from_mod)
            if tmod is None:
                sup["external_or_unresolved_module"] += 1
                continue
            if tmod.star_import or tmod.has_module_getattr:
                sup["dynamic_exporter"] += 1
                continue
            if name in tmod.top_names:
                continue
            # package __init__ may re-export submodules
            if tmod.path.name == "__init__.py":
                pkg_dir = tmod.path.parent
                if (pkg_dir / f"{name}.py").exists() or (pkg_dir / name).is_dir():
                    continue
            findings.append({
                "kind": "import_missing_symbol",
                "file": str(mod.path), "line": lineno,
                "sym": f"{from_mod}:{name}",
                "detail": f"from {from_mod} import {name} — not defined in "
                       f"{tmod.path}"})
    return findings, sup


# ---------------------------------------------------------- (b) dead symbols

PROTOCOL_NAMES = {
    "main", "setUp", "tearDown", "setUpClass", "tearDownClass",
    # unittest + pytest xunit lifecycle hooks: resolved by name by the
    # test runner, never referenced in code.
    "setUpModule", "tearDownModule",
    "setup_module", "teardown_module",
    "setup_function", "teardown_function",
    "setup_class", "teardown_class",
    "setup_method", "teardown_method",
    "do_GET", "do_POST", "do_HEAD", "do_PUT", "do_CONNECT",
    # socketserver hooks: dispatched by name from the stdlib serve loop
    "process_request", "process_request_thread", "finish_request",
    "verify_request", "handle_timeout", "shutdown_request",
    "log_message", "log_error", "log_request",
    "default", "emit", "filter", "format", "handle", "handle_error",
    "run", "close", "flush", "readable", "writable", "seekable",
    "get", "post", "put",
}
REGISTRATION_DECORATOR_HINTS = (
    "fixture", "hookimpl", "register", "route", "command", "group",
    "option", "argument", "app.", "cli.", "task", "subscribe", "listens",
    "validator", "field_validator", "model_validator", "overrides",
    "override", "singledispatch", "atexit",
)


def find_dead(idx: RepoIndex):
    findings = []
    sup = Counter()

    # global usage maps
    name_use = Counter()        # Name loads per identifier
    attr_use = Counter()        # Attribute attr per identifier
    str_use = Counter()         # identifier words inside string constants
    import_use = Counter()      # ImportFrom of the symbol name
    for mod in idx.module_list:
        name_use.update(mod.name_load_counts)
        attr_use.update(mod.attr_load_counts)
        str_use.update(mod.str_words)
        for n, _mod, _ln in mod.import_uses:
            import_use[n] += 1

    # candidate defs
    cands = []
    for mod in idx.module_list:
        for fd in mod.funcs:
            n = fd.name
            if fd.nested:
                continue
            if n.startswith("__") and n.endswith("__"):
                continue
            if n.startswith(("test_", "pytest_")) or n in PROTOCOL_NAMES:
                continue
            if fd.cls is not None and n.startswith("visit_"):
                sup["visitor_dispatch_method"] += 1     # NodeVisitor et al.
                continue
            if "negative_controls" in mod.path.parts:
                sup["negative_control_corpus"] += 1     # deliberate dead code
                continue
            if any(h in (d or "") for d in fd.decorators
                   for h in REGISTRATION_DECORATOR_HINTS):
                sup["registration_decorator"] += 1
                continue
            cands.append(fd)

    # decorator references: @foo counts as a Name load already.
    for fd in cands:
        n = fd.name
        uses = name_use[n] + attr_use[n] + str_use[n] + import_use[n]
        # every def of a method with same name contributes 0 (def isn't a
        # load); own-body self-references (recursion) were pre-counted by
        # the extraction pass.
        uses -= fd.own_refs
        # sibling defs with the same name (overrides / same-named funcs
        # elsewhere): their own-body recursion also inflates; ignore (rare).
        if uses > 0:
            continue
        if n in idx.text_idents:
            sup["text_corpus_reference"] += 1
            continue
        exported = bool(fd.module.all_exports and n in fd.module.all_exports)
        in_test = ("tests" in fd.path.parts or "test" in fd.path.parts
                   or fd.path.name.startswith(("test_", "conftest")))
        findings.append({
            "kind": "dead_function" if fd.cls is None else "dead_method",
            "file": str(fd.path), "line": fd.lineno,
            "name": fd.qualname,
            "in_test": in_test,
            "exported_in_all": exported,
            "detail": f"{fd.module.modnames[0]}:{fd.qualname} — zero references "
                   f"(AST names/attrs, strings, imports, text corpus)"})
    # dead classes
    for mod in idx.module_list:
        mod_is_test = ("tests" in mod.path.parts or "test" in mod.path.parts
                       or mod.path.name.startswith(("test_", "conftest")))
        for cname, ci in mod.classes.items():
            if cname.startswith("Test") and mod_is_test:
                continue        # pytest-collected
            def _is_testcase_base(name, _seen=None):
                # transitive: a same-module base that is itself a test
                # class makes the subclass one (local shared-fixture
                # bases like RunContentionBase are the common case)
                if name is None:
                    return False
                if "unittest" in name or name.endswith("TestCase"):
                    return True
                _seen = _seen or set()
                if name in _seen:
                    return False
                _seen.add(name)
                parent = mod.classes.get(name)
                return parent is not None and any(
                    _is_testcase_base(b, _seen) for b in parent.bases)
            if mod_is_test and any(_is_testcase_base(b) for b in ci.bases):
                continue
            uses = name_use[cname] + attr_use[cname] + str_use[cname] + import_use[cname]
            # own-subtree self references (factory classmethods, nested
            # mentions) were pre-counted by the extraction pass
            uses -= ci.own_refs
            if uses > 0:
                continue
            if cname in idx.text_idents:
                sup["text_corpus_reference"] += 1
                continue
            # Mirror the function loop's gate: a decorated registration
            # (e.g. @registry.register(...)) consumes the class as a
            # registry VALUE — its name never appears as a load/string/
            # import even though every scan run instantiates it.
            if any(h in (d or "") for d in ci.decorators
                   for h in REGISTRATION_DECORATOR_HINTS):
                sup["registration_decorator"] += 1
                continue
            findings.append({
                "kind": "dead_class", "file": str(mod.path), "line": ci.lineno,
                "name": ci.qualname,
                "detail": f"{mod.modnames[0]}:{ci.qualname} — zero references"})
    return findings, sup


# ------------------------------------------------- (c) write-only artifacts

ARTIFACT_RE = re.compile(
    r"^[A-Za-z0-9._\-{}*]+\.(json|jsonl|sarif|md|csv|ya?ml|log|txt)$")
COMMON_NONARTIFACTS = {
    "README.md", "CLAUDE.md", "MEMORY.md", "requirements.txt",
    "requirements-dev.txt", "pyproject.toml", "package.json",
    "settings.json", "settings.local.json", "config.yaml", "config.yml",
    "compile_commands.json", "Dockerfile", "docker-compose.yml", "index.md",
    "SKILL.md", "PIPELINE.md",
}
WRITE_HINTS = re.compile(
    r"""(open\([^)]*["'](w|a|wb|ab|w\+)["']|write_text|json\.dump\b|\.dump\(|
        atomic_write|_write|write_json|save_|dump_json|writestr|
        NamedTemporaryFile|to_csv|writelines|\.write\()""", re.VERBOSE)
READ_HINTS = re.compile(
    r"""(open\([^)]*["']rb?["']|open\((?![^)]*["'][wa])|read_text|json\.load\b|
        \.load\(|read_json|load_json|loads\(|_read|parse_|exists\(\)|
        is_file\(\)|glob|iterdir|from_file)""", re.VERBOSE)
# Atomic-write idiom: the artifact literal names the DESTINATION of a
# tempfile-then-rename write. The dump lands on the temp fd many lines
# below the literal, so the +/-2-line window sees only the is_file()
# accumulation guard and misclassifies the writer as a reader.
ATOMIC_TMP_HINT = re.compile(r"mkstemp|mkdtemp|NamedTemporaryFile")
ATOMIC_RENAME_HINT = re.compile(r"\.rename\(|os\.replace\(|\.replace\(")


def _in_atomic_write_fn(funcs: list, lines: list, lineno: int) -> bool:
    """True when *lineno* sits in a function using tempfile+rename."""
    for fd in funcs:
        if fd.lineno <= lineno <= (fd.end_lineno or fd.lineno):
            body = "\n".join(lines[fd.lineno - 1: fd.end_lineno or fd.lineno])
            if ATOMIC_TMP_HINT.search(body) and ATOMIC_RENAME_HINT.search(body):
                return True
    return False


# Locator-function idiom: the artifact literal only builds a candidate
# path (candidates = [run_dir / "x.json"]); the actual open/parse sits
# several lines below, outside the +/-2-line window, so the occurrence
# classifies as a bare mention and the writer looks write-only.  Three
# guards keep this surgical:
#   - strong read hints only — exists()/glob-style probes are NOT
#     enough, or every writer's overwrite guard would count as a reader;
#   - innermost enclosing function, capped at LOCATOR_FN_MAX_LINES —
#     locator/loader helpers are small; a mention inside a hundreds-of-
#     lines pipeline function that happens to read OTHER files (path
#     echoes, report path listings) must not count;
#   - the function must not also write the same artifact — a writer
#     that prints its output path is not that artifact's reader.
STRONG_READ_HINTS = re.compile(
    r"read_text|read_bytes|json\.loads?\b|read_json|load_json|from_file")
LOCATOR_FN_MAX_LINES = 60


def _innermost_fn(funcs: list, lineno: int):
    """Innermost FuncDef containing *lineno*, or None at module level."""
    inner = None
    for fd in funcs:
        if fd.lineno <= lineno <= (fd.end_lineno or fd.lineno) \
                and (inner is None or fd.lineno > inner.lineno):
            inner = fd
    return inner


def _locator_reads(funcs: list, lines: list, lineno: int,
                   write_linenos: list) -> bool:
    """True when the mention at *lineno* sits in a small parsing helper
    that does not itself write the artifact."""
    fd = _innermost_fn(funcs, lineno)
    if fd is None:
        return False
    end = fd.end_lineno or fd.lineno
    if end - fd.lineno + 1 > LOCATOR_FN_MAX_LINES:
        return False
    if any(fd.lineno <= wl <= end for wl in write_linenos):
        return False
    body = "\n".join(lines[fd.lineno - 1: end])
    return bool(STRONG_READ_HINTS.search(body))


def find_artifacts(idx: RepoIndex):
    sup = Counter()
    occ = defaultdict(list)     # basename -> [(path, line_no, cls)]
    for mod in idx.module_list:
        for base, lineno, cls, is_test in mod.artifact_occs:
            occ[base].append((str(mod.path), lineno, cls, is_test))
    # non-python corpus: shell readers (jq, cat) & docs
    for p, text in idx.text_files:
        for i, line in enumerate(text.splitlines(), 1):
            for w in re.findall(r"[A-Za-z0-9._\-*]+\.(?:json|jsonl|sarif|csv)\b", line):
                base = w.rsplit("/", 1)[-1]
                if base in occ:
                    cls = "read" if re.search(r"\bjq\b|\bcat\b|read|load", line) else "mention"
                    is_doc = p.suffix == ".md"
                    occ[base].append((str(p), i, cls, is_doc))

    findings = []
    for base, entries in sorted(occ.items()):
        prod = [e for e in entries if not e[3]]
        writes = [e for e in prod if e[2] == "write"]
        reads = [e for e in prod if e[2] == "read"]
        mentions = [e for e in prod if e[2] == "mention"]
        test_reads = [e for e in entries if e[3] and e[2] in ("read", "mention")]
        if writes and not reads:
            findings.append({
                "kind": "write_only_artifact", "name": base,
                "writers": [f"{e[0]}:{e[1]}" for e in writes],
                "mentions": [f"{e[0]}:{e[1]}" for e in mentions],
                "test_refs": len(test_reads),
                "detail": f"'{base}' written but never read in production code"})
        elif reads and not writes and not mentions:
            findings.append({
                "kind": "orphan_reader", "name": base,
                "readers": [f"{e[0]}:{e[1]}" for e in reads],
                "detail": f"'{base}' read but never written anywhere in repo"})
        else:
            sup["artifact_has_both_or_ambiguous"] += 1
    return findings, sup


# --------------------------------------------- (d) swallowed exceptions

LOUD_LOG = re.compile(r"\.(error|exception|critical|warning)\(")
QUIET_LOG = re.compile(r"\.(debug|trace|info)\(")


def classify_handler(handler: ast.ExceptHandler, lines: list):
    """Return (category, detail) or None if not a swallow."""
    body = handler.body
    has_raise = any(isinstance(n, ast.Raise) for n in ast.walk(handler))
    if has_raise:
        return None
    src_seg = "\n".join(lines[handler.lineno - 1: (handler.end_lineno or handler.lineno)])
    if LOUD_LOG.search(src_seg):
        return None                      # logged loudly -> not silent
    if re.search(r"print\(", src_seg) or "sys.stderr" in src_seg or "sys.exit" in src_seg:
        return None                      # visible or fail-closed
    kinds = []
    only_stmts = [type(s).__name__ for s in body]
    if all(isinstance(s, ast.Pass) for s in body):
        kinds.append("pass_only")
    elif all(isinstance(s, (ast.Continue, ast.Break, ast.Pass)) for s in body):
        kinds.append("continue_break")
    elif all(isinstance(s, (ast.Return, ast.Pass)) for s in body):
        kinds.append("return_default")
    elif QUIET_LOG.search(src_seg):
        kinds.append("quiet_log_only")
    # assignments-to-default / result=None then fallthrough
    elif all(isinstance(s, (ast.Assign, ast.AugAssign, ast.AnnAssign,
                          ast.Pass, ast.Expr, ast.Continue, ast.Return,
                          ast.Break)) for s in body):
        # Expr could be a call doing real fallback work — count those
        calls = [s for s in body if isinstance(s, ast.Expr)
                 and isinstance(s.value, ast.Call)]
        if calls:
            return ("fallback_action", only_stmts)
        kinds.append("assign_default")
    else:
        return None                  # substantial handler; not a swallow
    return (kinds[0], only_stmts)


def exc_types(handler: ast.ExceptHandler):
    if handler.type is None:
        return ["<bare>"], True
    names = []
    t = handler.type
    elts = t.elts if isinstance(t, ast.Tuple) else [t]
    broad = False
    for e in elts:
        nm = dec_name(e)
        names.append(nm or "<expr>")
        if nm in ("Exception", "BaseException"):
            broad = True
    return names, broad


def find_swallowed(idx: RepoIndex, kwarg_findings):
    findings = []
    sup = Counter()
    kwarg_lines = defaultdict(set)
    for f in kwarg_findings:
        if "line" in f:
            kwarg_lines[f["file"]].add(f["line"])
    for mod in idx.module_list:
        for fact in mod.swallow_findings:
            f = dict(fact)      # keep the module's fact table pristine
            span = f["func_span"]
            # cross-ref: does a kwarg/miswire finding sit inside this
            # try/suppress block?
            f["miswire_xref_lines"] = sorted(
                ln for ln in kwarg_lines.get(f["file"], set())
                if span[0] <= ln <= span[1])
            findings.append(f)
        if mod.swallow_not_silent:
            sup["handler_not_silent"] += mod.swallow_not_silent
    return findings, sup


# ------------------------------------------------- (e) plumbing orphans

# Wholesale-serialization consumption.  A config/result dataclass often
# has no per-field attribute read anywhere: the whole instance flows
# through asdict()/astuple()/vars()/dataclasses.fields()/json.dump()/
# .model_dump()/**-unpacking, and the serialized form is consumed
# downstream (report artifacts, LLM prompts, operators, jq).  Fields of
# such a class are consumed via serialization, not orphaned.  Tracked at
# class granularity: once the owning class is observed flowing through a
# wholesale serializer anywhere, every field of it counts as consumed —
# the per-field string-key case is already covered by the str-constant
# reference counter.  The result only ever moves a field from a failing
# orphan finding to an informational classification, never the reverse.

_SERIALIZE_FREE_FNS = {"asdict", "astuple", "vars", "fields"}
_SERIALIZE_MOD_FNS = {
    ("dataclasses", "asdict"), ("dataclasses", "astuple"),
    ("dataclasses", "fields"), ("attr", "asdict"), ("attrs", "asdict"),
    ("json", "dump"), ("json", "dumps"),
}
_SERIALIZE_METHODS = {"model_dump", "model_dump_json", "_asdict", "dict",
                      "json"}


def _resolve_mark(desc: tuple, ident_types: dict, all_classes: set):
    """Resolve a serialization-argument descriptor to a class name.

    The parent half of the old ``Ser._type_of``: shape analysis
    happened in the extraction pass, class-name membership and the
    ident-type map are only known here.
    """
    kind, val = desc
    if kind == "const":
        return val                      # self/cls inside a class body
    if kind == "name":
        if val in all_classes:
            return val                  # fields(ClassName)
        return ident_types.get(val)
    if kind == "attrname":
        return ident_types.get(val)
    # kind == "call": ClassName(...) serialized directly
    return val if val in all_classes else None


def find_serialized_classes(idx: RepoIndex) -> set:
    """Names of in-repo classes that flow through wholesale serialization."""
    all_classes = set()
    for mod in idx.module_list:
        all_classes.update(mod.classes)
    serialized = set()

    for mod in idx.module_list:
        # identifier -> class name, from constructor assignments, variable/
        # attribute annotations and function parameters.  Flat per-module
        # scope: deliberately generous — the map is only ever consulted to
        # RECLASSIFY an orphan as consumed, never to create a finding.
        # Replayed from the walk-ordered event list (last write wins,
        # exactly as the old single-dict build over ``ast.walk``).
        ident_types = {}
        for ev in mod.ser_events:
            tag = ev[0]
            if tag == "assign":
                _, idents, cname = ev
                if cname in all_classes:
                    for ident in idents:
                        ident_types[ident] = cname
            elif tag == "ann":
                _, ident, words = ev
                cands = words & all_classes
                if len(cands) == 1:
                    ident_types[ident] = next(iter(cands))
            else:       # "args"
                for argname, words in ev[1]:
                    cands = words & all_classes
                    if len(cands) == 1:
                        ident_types[argname] = next(iter(cands))
        for desc in mod.ser_marks:
            t = _resolve_mark(desc, ident_types, all_classes)
            if t:
                serialized.add(t)

    # Nested-dataclass closure: asdict()/model_dump()/json recurse into
    # dataclass-typed fields, so serializing the parent serializes every
    # nested class too (incl. through List[...]/Dict[...] containers).
    nested = defaultdict(set)       # class name -> field-annotation classes
    for mod in idx.module_list:
        for ci in mod.classes.values():
            nested[ci.name] |= ci.field_ann_words & all_classes
    queue = list(serialized)
    while queue:
        for child in nested.get(queue.pop(), ()):
            if child not in serialized:
                serialized.add(child)
                queue.append(child)
    return serialized


# env-var plumbing regexes (applied to raw source in the extraction pass)
ENVGET_RE = re.compile(
    r"(?:os\.environ\.get|os\.getenv|os\.environ\[)\s*\(?\s*[\"']([A-Z][A-Z0-9_]+)[\"']")
ENVSET_PY_RE = re.compile(
    r"os\.environ\[\s*[\"']([A-Z][A-Z0-9_]+)[\"']\s*\]\s*=|"
    r"os\.environ\.setdefault\(\s*[\"']([A-Z][A-Z0-9_]+)[\"']|"
    r"env\[\s*[\"']([A-Z][A-Z0-9_]+)[\"']\s*\]\s*=")
# Shell-variable expansion inside Python sources: launchers embed
# bash -c wrapper scripts that read the vars they were spawned with
# (e.g. exec "$@" > "$RAPTOR_BO_OUT") — those are in-repo readers.
SHELLREAD_RE = re.compile(r"\$\{?([A-Z][A-Z0-9_]{2,})\b")


def find_plumbing(idx: RepoIndex):
    findings = []
    info = []           # non-failing classifications (census stays honest)
    sup = Counter()
    attr_use = Counter()
    str_use = Counter()
    name_use = Counter()
    for mod in idx.module_list:
        attr_use.update(mod.attr_load_counts)
        str_use.update(mod.str_words)
        name_use.update(mod.name_load_counts)

    # dataclass/config fields
    serialized_classes = find_serialized_classes(idx)
    for mod in idx.module_list:
        for ci in mod.classes.values():
            is_dc = any("dataclass" in (d or "") for d in ci.decorators)
            looks_config = re.search(r"(Config|Settings|Options|Params)$", ci.name)
            if not (is_dc or looks_config):
                continue
            if "tests" in mod.path.parts:
                continue
            for fname, lineno in ci.fields:
                if fname.startswith("_"):
                    continue
                # attr accesses of the field name anywhere, minus the AnnAssign
                uses = attr_use[fname] + str_use[fname]
                # subtract accesses within the class body itself? cheap: no.
                if uses > 0:
                    continue
                if fname in idx.text_idents:
                    sup["text_corpus_reference"] += 1
                    continue
                if ci.name in serialized_classes:
                    # owning class flows through wholesale serialization —
                    # the field is read by the serializer, not orphaned.
                    info.append({
                        "kind": "config_field_consumed_via_serialization",
                        "file": str(mod.path), "line": lineno,
                        "name": f"{ci.name}.{fname}",
                        "detail": f"no direct reference, but {ci.name} is "
                               "serialized wholesale (asdict/vars/fields/"
                               "json.dump/model_dump/** unpack)"})
                    continue
                findings.append({
                    "kind": "orphan_config_field",
                    "file": str(mod.path), "line": lineno,
                    "name": f"{ci.name}.{fname}",
                    "detail": "field defined but no attribute/string reference anywhere"})

    # argparse flags
    for mod in idx.module_list:
        if "tests" in mod.path.parts:
            continue
        for lineno, opt, dest in mod.add_arg_sites:
            uses = attr_use[dest] + str_use[dest] + name_use[dest]
            # the add_argument line itself contributes via str constant "--x"
            # (different token) — dest as identifier only counts real reads.
            if uses > 0:
                continue
            if dest in idx.text_idents:
                sup["text_corpus_reference"] += 1
                continue
            findings.append({
                "kind": "orphan_cli_flag", "file": str(mod.path), "line": lineno,
                "name": opt or dest,
                "detail": f"parsed into .{dest} but never read"})

    # env vars set in-repo but never read in-repo
    env_reads = set()
    env_writes = defaultdict(list)
    env_write_forms = defaultdict(set)  # name -> {"global", "child_env"}
    for mod in idx.module_list:
        env_reads |= mod.env_read_names
        if "tests" in mod.path.parts or mod.path.name.startswith("test_"):
            # test fixtures set env for the tool under test, not for
            # production plumbing — same test-skip as the other passes
            continue
        for name, form in mod.env_write_events:
            env_writes[name].append(str(mod.path))
            env_write_forms[name].add(form)
    for p, text in idx.text_files:
        if p.suffix in {".sh", ""}:
            for m_ in re.finditer(r"export\s+([A-Z][A-Z0-9_]+)=", text):
                env_writes[m_.group(1)].append(str(p))
                env_write_forms[m_.group(1)].add("global")
            for m_ in re.finditer(r"\$\{?([A-Z][A-Z0-9_]{2,})\b", text):
                env_reads.add(m_.group(1))
    WELL_KNOWN = {
        "PATH", "HOME", "LANG", "TERM", "PYTHONPATH", "LD_LIBRARY_PATH",
        "http_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "TMPDIR",
        "PYTEST_ADDOPTS", "CLAUDECODE", "SHELL", "USER", "DISPLAY",
        "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED", "SOURCE_DATE_EPOCH",
    }
    for name, writers in sorted(env_writes.items()):
        if name in env_reads or name in WELL_KNOWN:
            continue
        # word search across whole corpus (reader may use a var-built name).
        # ``name in word_tokens`` == the old ``\bname\b`` regex search:
        # the var name is all word-chars, so a boundary-flanked occurrence
        # is exactly a maximal word token equal to the name.
        pat = re.compile(rf"\b{re.escape(name)}\b")
        py_hits = sum(1 for mod in idx.module_list if name in mod.word_tokens)
        txt_hits = sum(1 for _, t in idx.text_files if pat.search(t))
        if py_hits + txt_hits > len(set(writers)):
            sup["env_referenced_elsewhere"] += 1
            continue
        if env_write_forms.get(name) == {"child_env"}:
            # written only into a spawned process's env mapping — the
            # consumer is the external tool; unverifiable in-repo but
            # not orphaned plumbing.  Reported, not failed.
            info.append({
                "kind": "env_var_consumed_externally", "name": name,
                "writers": sorted(set(writers)),
                "detail": "set only in a child-process env mapping — "
                       "consumed by the spawned tool"})
            continue
        findings.append({
            "kind": "orphan_env_var", "name": name,
            "writers": sorted(set(writers)),
            "detail": "set/exported but never read in-repo (external consumers possible)"})
    return findings, sup, info


# ---------------------------------------------------------------- driver

FAILING_CLASSES = ("kwargs", "imports", "dead", "artifacts", "plumbing")
DEFAULT_BASELINE = Path(__file__).resolve().parent / "miswiring_baseline.json"


def finding_key(cls: str, f: dict, root: Path) -> str:
    """Stable baseline key: class + kind + relative file + symbol.

    Deliberately excludes line numbers so unrelated edits do not
    invalidate the baseline.
    """
    file = f.get("file", "")
    if file:
        try:
            file = str(Path(file).resolve().relative_to(root))
        except ValueError:
            pass
    sym = f.get("sym") or f.get("name") or ""
    return f"{cls}:{f.get('kind', '')}:{file}:{sym}"


def load_baseline(path: Path) -> dict:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("entries", {})


def write_baseline(path: Path, keys: dict) -> None:
    payload = {
        "_comment": (
            "Accepted miswiring-detector findings. Keys are "
            "class:kind:file:symbol (no line numbers). Add an entry "
            "ONLY with a note explaining why the finding is accepted; "
            "prefer fixing. check_miswiring.py fails CI on any finding "
            "not listed here and warns on stale entries."
        ),
        "version": 1,
        "entries": dict(sorted(keys.items())),
    }
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def _default_root() -> Path:
    """Script-anchored repo root (.github/scripts/<this> -> parents[2]).

    Anchoring to the script keeps a wrong-cwd invocation (a workflow
    step with ``working-directory``, a local runner) from silently
    indexing zero modules and passing vacuously — same pattern as
    check_vocab_lists.py / check_env_docs.py.
    """
    return Path(__file__).resolve().parents[2]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=_default_root(),
                    help="repo root to scan (default: the repo containing "
                         "this script)")
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--write-baseline", action="store_true",
                    help="write the current findings as the new baseline "
                         "(preserves notes of surviving entries)")
    ap.add_argument("--only", default="all",
                    help="comma list: kwargs,imports,dead,artifacts,"
                         "swallowed,plumbing")
    ap.add_argument("--json", type=Path, default=None,
                    help="dump the full structured report")
    ap.add_argument("--census", action="store_true",
                    help="print the full swallowed-exception census")
    ap.add_argument("--jobs", type=int, default=0,
                    help="extraction worker processes (0 = auto: "
                         "CPUs capped at 8; 1 = in-process)")
    args = ap.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    if args.jobs < 0:
        print(f"error: --jobs must be >= 0, got {args.jobs}", file=sys.stderr)
        return 2

    only = set(args.only.split(",")) if args.only != "all" else {
        "kwargs", "imports", "dead", "artifacts", "swallowed", "plumbing"}

    idx = RepoIndex(root)
    idx.build(jobs=args.jobs if args.jobs > 0 else default_jobs())
    print(f"[miswiring] indexed {len(idx.module_list)} python modules, "
          f"{len(idx.text_files)} text files", file=sys.stderr)

    report = {"root": str(root), "classes": {}}
    kwarg_findings = []
    if "kwargs" in only or "swallowed" in only:
        f, s = check_calls(idx)
        kwarg_findings = f
        if "kwargs" in only:
            report["classes"]["kwargs"] = {"findings": f,
                                           "suppressions": dict(s)}
    if "imports" in only or "swallowed" in only:
        f, s = check_imports(idx)
        kwarg_findings = kwarg_findings + f
        if "imports" in only:
            report["classes"]["imports"] = {"findings": f,
                                            "suppressions": dict(s)}
    if "dead" in only:
        f, s = find_dead(idx)
        report["classes"]["dead"] = {"findings": f, "suppressions": dict(s)}
    if "artifacts" in only:
        f, s = find_artifacts(idx)
        report["classes"]["artifacts"] = {"findings": f,
                                          "suppressions": dict(s)}
    if "swallowed" in only:
        f, s = find_swallowed(idx, kwarg_findings)
        report["classes"]["swallowed"] = {"findings": f,
                                          "suppressions": dict(s)}
    if "plumbing" in only:
        f, s, info = find_plumbing(idx)
        report["classes"]["plumbing"] = {"findings": f,
                                         "suppressions": dict(s),
                                         "informational": info}

    for cls, data in report["classes"].items():
        line = f"== {cls}: {len(data['findings'])} findings"
        if data.get("informational"):
            counts = Counter(i["kind"] for i in data["informational"])
            line += " (info: " + ", ".join(
                f"{k}={v}" for k, v in sorted(counts.items())) + ")"
        print(f"{line}, suppressions: {data['suppressions']}")

    # -- swallowed census (informational) --------------------------------
    swallowed = report["classes"].get("swallowed", {}).get("findings", [])
    if swallowed:
        prod = [f for f in swallowed if not f["in_test"]]
        broad = sum(1 for f in prod if f["broad"])
        xref = [f for f in prod if f["miswire_xref_lines"]]
        print(f"[census] swallowed handlers: {len(prod)} production "
              f"({broad} broad); {len(xref)} wrap a detected miswiring")
        if args.census:
            for f in swallowed:
                mark = " <== WRAPS MISWIRING" if f["miswire_xref_lines"] else ""
                print(f"  {f['file']}:{f['line']} [{','.join(f['types'])}] "
                      f"{f['category']}{mark}")

    if args.json:
        args.json.write_text(json.dumps(report, indent=1),
                             encoding="utf-8")
        print(f"[miswiring] wrote {args.json}", file=sys.stderr)

    # -- baseline compare -------------------------------------------------
    current: dict[str, dict] = {}
    for cls in FAILING_CLASSES:
        for f in report["classes"].get(cls, {}).get("findings", []):
            current[finding_key(cls, f, root)] = f

    if args.write_baseline:
        old = load_baseline(args.baseline)
        entries = {}
        for key in current:
            note = (old.get(key) or {}).get("note") or "accepted (triaged)"
            entries[key] = {"note": note}
        write_baseline(args.baseline, entries)
        print(f"[miswiring] wrote baseline with {len(entries)} entries "
              f"to {args.baseline}")
        return 0

    baseline = load_baseline(args.baseline)
    new = {k: f for k, f in current.items() if k not in baseline}
    stale = [k for k in baseline if k not in current]

    for k in stale:
        print(f"[miswiring] STALE baseline entry (finding no longer "
              f"fires — consider removing): {k}", file=sys.stderr)

    if new:
        print(f"\n[miswiring] {len(new)} NEW finding(s) not in "
              f"{args.baseline.name}:")
        for k, f in sorted(new.items()):
            line = f.get("line")
            loc = f"{f.get('file', '')}:{line}" if line else f.get("file", "")
            print(f"  {k}\n      at {loc}\n      {f.get('detail', '')[:200]}")
        print(
            "\nFix the miswiring (preferred), or if the finding is a "
            "triaged false positive / deliberate design, add its key to "
            f"{args.baseline} with a note explaining why.")
        return 1

    print(f"[miswiring] clean: {len(current)} finding(s), all baselined"
          + (f"; {len(stale)} stale baseline entrie(s)" if stale else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
