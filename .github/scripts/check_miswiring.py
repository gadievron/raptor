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

Exit codes: 0 clean (stale-only is clean), 1 new findings, 2 usage error.
Precision over recall: anything ambiguous is suppressed and counted.
"""

import argparse
import ast
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------- walking

SKIP_DIR_NAMES = {
    ".git", "__pycache__", "node_modules", "out", ".out", ".tox", ".venv",
    "venv", "build", "dist", "fixtures", "seeds", ".claude/worktrees",
    "data",  # packaged datasets (packages/sca/data is 35MB of JSON)
}
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
            if any(part in SKIP_DIR_NAMES for part in rel_parts):
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
        "node",
        "path",
        "posonly",
        "qualname",
        "vararg",
    )

    def __init__(self, module, qualname, name, node, cls, path, nested):
        self.module = module
        self.qualname = qualname
        self.name = name
        self.node = node
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
        "fields",
        "methods",
        "module",
        "name",
        "node",
        "path",
        "qualname",
    )

    def __init__(self, module, name, qualname, node, path):
        self.module = module
        self.name = name
        self.qualname = qualname
        self.node = node
        self.path = path
        self.bases = [dec_name(b) for b in node.bases]
        self.methods = {}       # name -> FuncDef
        self.decorators = [dec_name(d) for d in node.decorator_list]
        self.fields = []        # (name, lineno) AnnAssign class fields


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


class Module:
    __slots__ = (
        "all_exports",
        "attr_loads",
        "classes",
        "funcs",
        "has_module_getattr",
        "import_modules",
        "import_uses",
        "imports",
        "lines",
        "modnames",
        "name_loads",
        "path",
        "src",
        "star_import",
        "str_words",
        "top_names",
        "tree",
    )

    def __init__(self, path, modnames):
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
        self.name_loads = []            # (name, lineno)
        self.attr_loads = []            # (attr, lineno)
        self.str_words = Counter()      # identifier-ish words in str constants
        self.import_uses = []           # (imported symbol name, from module)


IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


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
    m.src = src
    m.lines = src.splitlines()

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.class_stack = []
            self.func_stack = []

        def visit_ClassDef(self, node):
            qual = ".".join([c.name for c in self.class_stack] + [node.name])
            ci = ClassInfo(m, node.name, qual, node, path)
            if not self.class_stack and not self.func_stack:
                m.classes[node.name] = ci
                m.top_names.add(node.name)
            self.class_stack.append(ci)
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    ci.fields.append((stmt.target.id, stmt.lineno))
            self.generic_visit(node)
            self.class_stack.pop()

        def _def(self, node):
            cls = self.class_stack[-1] if self.class_stack else None
            nested = bool(self.func_stack) or len(self.class_stack) > 1
            prefix = ".".join([c.name for c in self.class_stack]
                              + [f.name for f in self.func_stack])
            qual = f"{prefix}.{node.name}" if prefix else node.name
            fd = FuncDef(m, qual, node.name, node, cls if not self.func_stack else None,
                         path, nested)
            m.funcs.append(fd)
            if cls is not None and not self.func_stack and len(self.class_stack) == 1:
                cls.methods[node.name] = fd
            if not self.class_stack and not self.func_stack:
                m.top_names.add(node.name)
            self.func_stack.append(fd)
            self.generic_visit(node)
            self.func_stack.pop()

        visit_FunctionDef = _def
        visit_AsyncFunctionDef = _def

        def visit_Import(self, node):
            for al in node.names:
                alias = al.asname or al.name.split(".")[0]
                target = al.name if al.asname else al.name.split(".")[0]
                m.imports[alias] = ("mod", al.name if al.asname else target)
                m.import_modules[alias] = al.name if al.asname else target
                if not self.class_stack and not self.func_stack:
                    m.top_names.add(alias)
            self.generic_visit(node)

        def visit_ImportFrom(self, node):
            if node.level:      # relative import: resolve against file path
                base_parts = rel.with_suffix("").parts[:-node.level]
                if rel.name == "__init__.py":
                    base_parts = rel.with_suffix("").parts[:-(node.level)]
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

        def visit_Assign(self, node):
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
            self.generic_visit(node)

        def visit_AnnAssign(self, node):
            if (isinstance(node.target, ast.Name) and not self.class_stack
                    and not self.func_stack):
                m.top_names.add(node.target.id)
            self.generic_visit(node)

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load):
                m.name_loads.append((node.id, node.lineno))
            self.generic_visit(node)

        def visit_Attribute(self, node):
            m.attr_loads.append((node.attr, node.lineno))
            self.generic_visit(node)

        def visit_Constant(self, node):
            if isinstance(node.value, str) and len(node.value) < 4000:
                for w in IDENT_RE.findall(node.value):
                    m.str_words[w] += 1
            self.generic_visit(node)

    Visitor().visit(tree)
    m.tree = tree
    if "__getattr__" in m.top_names:
        m.has_module_getattr = True
    return m


# ---------------------------------------------------------------- repo index

class RepoIndex:
    def __init__(self, root: Path):
        self.root = root
        self.modules = {}           # dotted name -> Module (first alias wins)
        self.module_list = []
        self.text_files = []        # (path, text) non-python corpus
        self.text_idents = set()    # all identifier-ish words in text corpus
        self.suppressions = Counter()

    def build(self):
        for p in iter_files(self.root):
            if is_python_file(p):
                mod = parse_module(p, self.root)
                if mod is None:
                    self.suppressions["unparseable_python"] += 1
                    continue
                self.module_list.append(mod)
                for name in mod.modnames:
                    self.modules.setdefault(name, mod)
                # package __init__ also answers for the package name
                if p.name == "__init__.py":
                    for name in mod.modnames:
                        pkg = name.rsplit(".", 1)[0] if "." in name else name
                        self.modules.setdefault(pkg, mod)
            elif p.suffix in TEXT_EXTS and p.stat().st_size < MAX_TEXT_FILE:
                self._add_text_file(p)
        for p in iter_text_root_files(self.root):
            if (p.suffix in TEXT_EXTS or p.suffix == ".py") \
                    and p.stat().st_size < MAX_TEXT_FILE:
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


def check_calls(idx: RepoIndex):
    findings = []
    sup = Counter()

    def resolve_name_target(mod: Module, name: str):
        """Resolve a bare name in `mod` to (kind, obj, bound)."""
        if name in mod.classes:
            return ("class", mod.classes[name])
        for fd in mod.funcs:
            if not fd.nested and fd.cls is None and fd.name == name:
                return ("func", fd)
        if name in mod.imports:
            kind, target = mod.imports[name]
            if kind == "sym":
                r = idx.resolve_symbol(target)
                if r:
                    tmod, tname = r
                    if tname in tmod.classes:
                        return ("class", tmod.classes[tname])
                    cands = [fd for fd in tmod.funcs
                             if not fd.nested and fd.cls is None and fd.name == tname]
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
                                c2 = [fd for fd in m2.funcs if not fd.nested
                                      and fd.cls is None and fd.name == n2]
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
        # map lineno -> enclosing class for self-resolution
        encl = {}

        class Encl(ast.NodeVisitor):
            def __init__(self, out):
                self.stack = []
                self.out = out

            def visit_ClassDef(self, node):
                self.stack.append(node.name)
                self.generic_visit(node)
                self.stack.pop()

            def visit_Call(self, node):
                self.out[id(node)] = (
                    self.stack[-1] if len(self.stack) == 1 else None
                )
                self.generic_visit(node)

        Encl(encl).visit(mod.tree)

        for node in ast.walk(mod.tree):
            if not isinstance(node, ast.Call):
                continue
            target = None
            bound = False
            label = None
            f = node.func
            if isinstance(f, ast.Name):
                r = resolve_name_target(mod, f.id)
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
                    target, bound, label = obj, False, f.id
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                base = f.value.id
                if base in ("self", "cls"):
                    cname = encl.get(id(node))
                    if cname and cname in mod.classes:
                        got = find_method(mod.classes[cname], f.attr)
                        if got == "ambiguous":
                            sup["self_method_base_unresolvable"] += 1
                            continue
                        if got == "missing":
                            # could be an attribute holding a callable; only
                            # flag if no instance attr of that name assigned
                            if f"self.{f.attr}" in mod.src or f"cls.{f.attr}" in mod.src.replace(f"cls.{f.attr}(", "", 1):
                                sup["self_attr_callable"] += 1
                                continue
                            findings.append({
                                "kind": "missing_method",
                                "file": str(mod.path), "line": node.lineno,
                                "sym": f"{cname}.{f.attr}",
                                "detail": f"self.{f.attr}() but no such method on {cname} or resolvable bases"})
                            continue
                        target, bound, label = got, True, f"self.{f.attr}"
                    else:
                        sup["self_outside_known_class"] += 1
                        continue
                elif base in mod.import_modules:
                    tmod = idx.resolve_module(mod.import_modules[base])
                    if tmod is None:
                        sup["external_module_attr"] += 1
                        continue
                    if f.attr in tmod.classes:
                        fd = class_init(tmod.classes[f.attr], None)
                        if isinstance(fd, FuncDef):
                            target, bound, label = fd, True, f"{base}.{f.attr}()"
                        else:
                            sup["class_init_ambiguous"] += 1
                            continue
                    else:
                        cands = [fd for fd in tmod.funcs
                                 if not fd.nested and fd.cls is None and fd.name == f.attr]
                        if len(cands) == 1:
                            target, bound, label = cands[0], False, f"{base}.{f.attr}"
                        elif f.attr not in tmod.top_names and not tmod.star_import \
                                and not tmod.has_module_getattr:
                            findings.append({
                                "kind": "missing_module_attr",
                                "file": str(mod.path), "line": node.lineno,
                                "sym": f"{tmod.modnames[0]}.{f.attr}",
                                "detail": f"{base}.{f.attr}() but {tmod.modnames[0]} has no top-level '{f.attr}'"})
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
            if target.node.name != "__init__" and any(
                    d in ("classmethod",) for d in target.decorators):
                bound = True

            has_star = any(isinstance(a, ast.Starred) for a in node.args)
            has_dstar = any(k.arg is None for k in node.keywords)
            kw_names = [k.arg for k in node.keywords if k.arg is not None]
            npos = sum(1 for a in node.args if not isinstance(a, ast.Starred))

            # unknown kwarg
            if not has_dstar and target.kwarg is None:
                known = target.all_kw_names(bound)
                for kw in kw_names:
                    if kw not in known:
                        findings.append({
                            "kind": "unknown_kwarg",
                            "file": str(mod.path), "line": node.lineno,
                            "sym": f"{target.module.modnames[0]}:{target.qualname}:{kw}",
                            "detail": f"{label}(... {kw}=...) — callee "
                                   f"{target.module.modnames[0]}:{target.qualname} "
                                   f"accepts {sorted(known)}"})
            elif has_dstar or target.kwarg is not None:
                sup["kwargs_open"] += 1

            # too many positionals
            if not has_star:
                pos_params = target.positional_params(bound)
                if target.vararg is None and npos > len(pos_params):
                    findings.append({
                        "kind": "too_many_positional",
                        "file": str(mod.path), "line": node.lineno,
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
                            "file": str(mod.path), "line": node.lineno,
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
        for n, _ in mod.name_loads:
            name_use[n] += 1
        for n, _ in mod.attr_loads:
            attr_use[n] += 1
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
            if "tests" in mod.path.parts or "test" == mod.path.parts[-2:-1]:
                # helper defs inside test dirs: only flag module-level funcs
                pass
            if any(h in (d or "") for d in fd.decorators
                   for h in REGISTRATION_DECORATOR_HINTS):
                sup["registration_decorator"] += 1
                continue
            if fd.cls is not None:
                # skip likely-interface methods: class has non-object bases
                # that we can't resolve (framework subclass)
                pass
            cands.append(fd)
        for ci in mod.classes.values():
            pass

    # count self-references inside own body per def (recursion)
    def own_body_refs(fd: FuncDef):
        c = 0
        for n in ast.walk(fd.node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id == fd.name or isinstance(n, ast.Attribute) and n.attr == fd.name:
                c += 1
        return c

    # decorator references: @foo counts as a Name load already.
    for fd in cands:
        n = fd.name
        uses = name_use[n] + attr_use[n] + str_use[n] + import_use[n]
        # every def of a method with same name contributes 0 (def isn't a load)
        uses -= own_body_refs(fd)
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
            if mod_is_test and any("unittest" in (b or "") or b == "TestCase"
                                   for b in ci.bases):
                continue
            uses = name_use[cname] + attr_use[cname] + str_use[cname] + import_use[cname]
            # subtract own-module self refs inside the class (e.g., factory
            # classmethods returning cls) are attr/name loads of 'cls', fine.
            for n in ast.walk(ci.node):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id == cname or isinstance(n, ast.Attribute) and n.attr == cname:
                    uses -= 1
            if uses > 0:
                continue
            if cname in idx.text_idents:
                sup["text_corpus_reference"] += 1
                continue
            findings.append({
                "kind": "dead_class", "file": str(mod.path), "line": ci.node.lineno,
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


def _in_atomic_write_fn(mod: Module, lineno: int) -> bool:
    """True when *lineno* sits in a function using tempfile+rename."""
    for fd in mod.funcs:
        if fd.lineno <= lineno <= (fd.end_lineno or fd.lineno):
            body = "\n".join(mod.lines[fd.lineno - 1: fd.end_lineno or fd.lineno])
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


def _innermost_fn(mod: Module, lineno: int):
    """Innermost FuncDef containing *lineno*, or None at module level."""
    inner = None
    for fd in mod.funcs:
        if fd.lineno <= lineno <= (fd.end_lineno or fd.lineno) \
                and (inner is None or fd.lineno > inner.lineno):
            inner = fd
    return inner


def _locator_reads(mod: Module, lineno: int, write_linenos) -> bool:
    """True when the mention at *lineno* sits in a small parsing helper
    that does not itself write the artifact."""
    fd = _innermost_fn(mod, lineno)
    if fd is None:
        return False
    end = fd.end_lineno or fd.lineno
    if end - fd.lineno + 1 > LOCATOR_FN_MAX_LINES:
        return False
    if any(fd.lineno <= wl <= end for wl in write_linenos):
        return False
    body = "\n".join(mod.lines[fd.lineno - 1: end])
    return bool(STRONG_READ_HINTS.search(body))


def find_artifacts(idx: RepoIndex):
    sup = Counter()
    occ = defaultdict(list)     # basename -> [(path, line_no, cls)]
    for mod in idx.module_list:
        raw = []
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value.strip()
                base = v.rsplit("/", 1)[-1]
                if not ARTIFACT_RE.match(base) or base in COMMON_NONARTIFACTS:
                    continue
                if "{" in base or "*" in base:
                    base = re.sub(r"\{[^}]*\}", "*", base)
                line = mod.lines[node.lineno - 1] if node.lineno <= len(mod.lines) else ""
                ctx = "\n".join(mod.lines[max(0, node.lineno - 2): node.lineno + 2])
                is_test = "tests" in mod.path.parts or mod.path.name.startswith("test_")
                if WRITE_HINTS.search(line) or WRITE_HINTS.search(ctx):
                    cls = "write"
                elif READ_HINTS.search(line) or READ_HINTS.search(ctx):
                    cls = "read"
                else:
                    cls = "mention"
                raw.append((base, node.lineno, cls, is_test))
        write_lines = defaultdict(list)     # base -> write-classified linenos
        for base, lineno, cls, _t in raw:
            if cls == "write":
                write_lines[base].append(lineno)
        for base, lineno, cls, is_test in raw:
            occ[base].append((str(mod.path), lineno, cls, is_test))
            if cls != "write" and _in_atomic_write_fn(mod, lineno):
                # The literal names the DESTINATION of a
                # tempfile-then-rename write; the accumulate-guard
                # window classified it read/mention. Record the
                # write as well — the occurrence is both.
                occ[base].append(
                    (str(mod.path), lineno, "write", is_test))
            if cls == "mention" and _locator_reads(mod, lineno,
                                                   write_lines[base]):
                # The literal builds a candidate path inside a small
                # parsing helper; the open/parse sits below the window.
                # Record the read as well (the mention is kept, so this
                # can only suppress a write-only report, never mint an
                # orphan-reader finding).
                occ[base].append(
                    (str(mod.path), lineno, "read", is_test))
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


def classify_handler(handler: ast.ExceptHandler, mod: Module):
    """Return (category, detail) or None if not a swallow."""
    body = handler.body
    has_raise = any(isinstance(n, ast.Raise) for n in ast.walk(handler))
    if has_raise:
        return None
    src_seg = "\n".join(mod.lines[handler.lineno - 1: (handler.end_lineno or handler.lineno)])
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
    else:
        # assignments-to-default / result=None then fallthrough
        if all(isinstance(s, (ast.Assign, ast.AugAssign, ast.AnnAssign,
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
        is_test = "tests" in mod.path.parts or mod.path.name.startswith("test_")
        for node in ast.walk(mod.tree):
            # -- contextlib.suppress(...) blocks: pure silent swallow --
            if isinstance(node, ast.With):
                for item in node.items:
                    ce = item.context_expr
                    if isinstance(ce, ast.Call) and dec_name(ce.func).endswith("suppress"):
                        types = [dec_name(a) or "<expr>" for a in ce.args]
                        broad = any(t in ("Exception", "BaseException") for t in types)
                        span = (node.body[0].lineno,
                                node.body[-1].end_lineno or node.body[0].lineno)
                        xref = sorted(
                            ln for ln in kwarg_lines.get(str(mod.path), set())
                            if span[0] <= ln <= span[1])
                        calls = []
                        for b in node.body:
                            for n in ast.walk(b):
                                if isinstance(n, ast.Call):
                                    calls.append(dec_name(n.func) or "<complex>")
                        findings.append({
                            "kind": "swallowed_exception",
                            "file": str(mod.path), "line": node.lineno,
                            "func_span": span,
                            "types": types, "broad": broad,
                            "category": "contextlib_suppress",
                            "in_test": is_test,
                            "would_eat_miswire": broad or any(
                                t in ("TypeError", "AttributeError", "KeyError",
                                      "ImportError")
                                for t in types),
                            "miswire_xref_lines": xref,
                            "try_calls": sorted(set(calls))[:12],
                        })
                continue
            if not isinstance(node, ast.Try):
                continue
            try_span = (node.body[0].lineno, node.body[-1].end_lineno or node.body[0].lineno)
            for h in node.handlers:
                res = classify_handler(h, mod)
                if res is None:
                    sup["handler_not_silent"] += 1
                    continue
                cat, _stmts = res
                types, broad = exc_types(h)
                # cross-ref: does a kwarg/miswire finding sit inside this try?
                xref = sorted(
                    ln for ln in kwarg_lines.get(str(mod.path), set())
                    if try_span[0] <= ln <= try_span[1])
                # calls made in try body (for triage aid)
                calls = []
                for b in node.body:
                    for n in ast.walk(b):
                        if isinstance(n, ast.Call):
                            calls.append(dec_name(n.func) or "<complex>")
                findings.append({
                    "kind": "swallowed_exception",
                    "file": str(mod.path), "line": h.lineno,
                    "func_span": try_span,
                    "types": types, "broad": broad, "category": cat,
                    "in_test": is_test,
                    "would_eat_miswire": broad or any(
                        t in ("TypeError", "AttributeError", "KeyError")
                        for t in types),
                    "miswire_xref_lines": xref,
                    "try_calls": sorted(set(calls))[:12],
                })
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


def _annotation_classes(node, all_classes: set) -> set:
    """Class names referenced by a type annotation (incl. string forms)."""
    found = set()
    if node is None:
        return found
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in all_classes:
            found.add(n.id)
        elif isinstance(n, ast.Attribute) and n.attr in all_classes:
            found.add(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            found.update(w for w in IDENT_RE.findall(n.value)
                         if w in all_classes)
    return found


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
        ident_types = {}
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                cname = dec_name(node.value.func).rsplit(".", 1)[-1]
                if cname in all_classes:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            ident_types[t.id] = cname
                        elif isinstance(t, ast.Attribute):
                            ident_types[t.attr] = cname
            elif isinstance(node, ast.AnnAssign):
                cands = _annotation_classes(node.annotation, all_classes)
                if len(cands) == 1:
                    cname = cands.pop()
                    if isinstance(node.target, ast.Name):
                        ident_types[node.target.id] = cname
                    elif isinstance(node.target, ast.Attribute):
                        ident_types[node.target.attr] = cname
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = node.args
                for arg in a.posonlyargs + a.args + a.kwonlyargs:
                    cands = _annotation_classes(arg.annotation, all_classes)
                    if len(cands) == 1:
                        ident_types[arg.arg] = cands.pop()

        class Ser(ast.NodeVisitor):
            def __init__(self, ident_types):
                self.class_stack = []
                self.ident_types = ident_types

            def visit_ClassDef(self, node):
                self.class_stack.append(node.name)
                self.generic_visit(node)
                self.class_stack.pop()

            def _type_of(self, e):
                if isinstance(e, ast.Name):
                    if e.id in ("self", "cls") and self.class_stack:
                        return self.class_stack[-1]
                    if e.id in all_classes:
                        return e.id             # fields(ClassName)
                    return self.ident_types.get(e.id)
                if isinstance(e, ast.Attribute):
                    if e.attr == "__dict__":
                        return self._type_of(e.value)
                    return self.ident_types.get(e.attr)
                if isinstance(e, ast.Call):
                    cname = dec_name(e.func).rsplit(".", 1)[-1]
                    if cname in all_classes:
                        return cname
                return None

            def _mark(self, e):
                t = self._type_of(e)
                if t:
                    serialized.add(t)

            def visit_Attribute(self, node):
                if node.attr == "__dict__":
                    self._mark(node.value)      # json.dumps(cfg.__dict__)
                self.generic_visit(node)

            def visit_Call(self, node):
                f = node.func
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

        Ser(ident_types).visit(mod.tree)

    # Nested-dataclass closure: asdict()/model_dump()/json recurse into
    # dataclass-typed fields, so serializing the parent serializes every
    # nested class too (incl. through List[...]/Dict[...] containers).
    nested = defaultdict(set)       # class name -> field-annotation classes
    for mod in idx.module_list:
        for ci in mod.classes.values():
            for stmt in ci.node.body:
                if isinstance(stmt, ast.AnnAssign):
                    nested[ci.name] |= _annotation_classes(
                        stmt.annotation, all_classes)
    queue = list(serialized)
    while queue:
        for child in nested.get(queue.pop(), ()):
            if child not in serialized:
                serialized.add(child)
                queue.append(child)
    return serialized


def find_plumbing(idx: RepoIndex):
    findings = []
    info = []           # non-failing classifications (census stays honest)
    sup = Counter()
    attr_use = Counter()
    str_use = Counter()
    name_use = Counter()
    for mod in idx.module_list:
        for n, _ in mod.attr_loads:
            attr_use[n] += 1
        str_use.update(mod.str_words)
        for n, _ in mod.name_loads:
            name_use[n] += 1

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
        for node in ast.walk(mod.tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_argument"):
                continue
            opt = None
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) \
                        and a.value.startswith("--"):
                    opt = a.value
            dest = None
            for k in node.keywords:
                if k.arg == "dest" and isinstance(k.value, ast.Constant):
                    dest = k.value.value
            if opt is None and dest is None:
                continue
            dest = dest or opt.lstrip("-").replace("-", "_")
            uses = attr_use[dest] + str_use[dest] + name_use[dest]
            # the add_argument line itself contributes via str constant "--x"
            # (different token) — dest as identifier only counts real reads.
            if uses > 0:
                continue
            if dest in idx.text_idents:
                sup["text_corpus_reference"] += 1
                continue
            findings.append({
                "kind": "orphan_cli_flag", "file": str(mod.path), "line": node.lineno,
                "name": opt or dest,
                "detail": f"parsed into .{dest} but never read"})

    # env vars set in-repo but never read in-repo
    env_reads = set()
    env_writes = defaultdict(list)
    env_write_forms = defaultdict(set)  # name -> {"global", "child_env"}
    envget = re.compile(
        r"(?:os\.environ\.get|os\.getenv|os\.environ\[)\s*\(?\s*[\"']([A-Z][A-Z0-9_]+)[\"']")
    envset_py = re.compile(
        r"os\.environ\[\s*[\"']([A-Z][A-Z0-9_]+)[\"']\s*\]\s*=|"
        r"os\.environ\.setdefault\(\s*[\"']([A-Z][A-Z0-9_]+)[\"']|"
        r"env\[\s*[\"']([A-Z][A-Z0-9_]+)[\"']\s*\]\s*=")
    # Shell-variable expansion inside Python sources: launchers embed
    # bash -c wrapper scripts that read the vars they were spawned with
    # (e.g. exec "$@" > "$RAPTOR_BO_OUT") — those are in-repo readers.
    shellread = re.compile(r"\$\{?([A-Z][A-Z0-9_]{2,})\b")
    for mod in idx.module_list:
        for m_ in envget.finditer(mod.src):
            env_reads.add(m_.group(1))
        for m_ in shellread.finditer(mod.src):
            env_reads.add(m_.group(1))
        if "tests" in mod.path.parts or mod.path.name.startswith("test_"):
            # test fixtures set env for the tool under test, not for
            # production plumbing — same test-skip as the other passes
            continue
        for m_ in envset_py.finditer(mod.src):
            name = next(g for g in m_.groups() if g)
            env_writes[name].append(str(mod.path))
            env_write_forms[name].add(
                "child_env" if m_.group(3) else "global")
    for p, text in idx.text_files:
        if p.suffix == ".sh" or p.suffix == "":
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
        # word search across whole corpus (reader may use a var-built name)
        pat = re.compile(rf"\b{re.escape(name)}\b")
        py_hits = sum(1 for mod in idx.module_list if pat.search(mod.src))
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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path.cwd(),
                    help="repo root to scan (default: cwd — CI runs "
                         "from the checkout root)")
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
    args = ap.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    only = set(args.only.split(",")) if args.only != "all" else {
        "kwargs", "imports", "dead", "artifacts", "swallowed", "plumbing"}

    idx = RepoIndex(root)
    idx.build()
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
