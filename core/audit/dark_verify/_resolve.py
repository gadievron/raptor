"""Resolution-direction module-binding engine.

ONE question, asked identically in every language lane: does the module
reference the harness will hand the language's loader RESOLVE to the
finding's file under that loader's real resolution rules?  The engine
answers it through per-language resolution adapters over a shared
first-hit search core — never through spelling similarity.  A reference
whose resolution cannot be established (no readable go.mod, a dotted
Lua stem, a Perl ``.pl`` finding that bareword ``require`` can never
load, an unreadable Java package declaration) is REFUSED: the witness
declines to verify rather than executing whatever the loader happens
to bind.

Registry: every language in ``_SUPPORTED_LANGS`` has a
``_LANE_BINDINGS`` entry — either a resolver adapter or a
``structural`` declaration naming the mechanism that binds the load
without any loader search (C/C++ compile spec.file directly; Rust
splices it via ``include!``).  ``TestLaneBindingClosure`` in
core/audit/tests/test_dark_verify.py enumerates the registry against
``_SUPPORTED_LANGS`` and drives a plantable lookalike through every
resolver lane.

The harness-side reference derivations live here too: the engine must
check exactly the reference the harness generators will feed the
loader, so both sides call the same derivation function — a generator
deriving one spelling while the engine validates another would reopen
the gap by drift.

Adapters take the finding's ``target_root`` when the caller has one
(``execute_witness`` always does).  Filesystem-dependent shadow checks
REFUSE without it; pure-mapping checks (exact-path references, the
Perl ``.pm`` rule) need no tree and behave identically either way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from ._types import _SUPPORTED_LANGS

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._types import DarkWitnessSpec

# Cap on the source prefix scanned for the Java package declaration —
# the declaration legally precedes every type declaration, so it lives
# in the first kilobytes of any real file; the cap keeps a pathological
# file from costing an unbounded read.
_JAVA_DECL_SCAN_BYTES = 65536

# Line comments plus the block-comment OPENER only: the closer is
# located with str.find in _strip_java_comments. The previous
# spelling (`/\*.*?\*/`) re-scanned the rest of the window from
# every ``/*`` that never closes — quadratic even inside the 64 KiB
# read cap.
_JAVA_COMMENT_TOKEN_RE = re.compile(r"//[^\n]*|/\*")


def _strip_java_comments(head: str) -> str:
    """Replace ``//`` and ``/* ... */`` comments with a space.

    Single left-to-right token scan: each character is visited once,
    a ``/*`` looks up its closer with ``str.find``, and once one
    opener has no closer no later opener can have one either, so the
    failed end-of-window lookup happens at most once.
    """
    out: list[str] = []
    pos = 0
    no_closer = False
    while True:
        m = _JAVA_COMMENT_TOKEN_RE.search(head, pos)
        if m is None:
            out.append(head[pos:])
            return "".join(out)
        out.append(head[pos : m.start()])
        if m.group() != "/*":
            out.append(" ")  # // comment
            pos = m.end()
            continue
        end = -1 if no_closer else head.find("*/", m.end())
        if end == -1:
            # Never closes: not a comment. Keep the chars and keep
            # scanning after the opener (no token starts at '*').
            no_closer = True
            out.append("/*")
            pos = m.end()
        else:
            out.append(" ")
            pos = end + 2
_JAVA_PACKAGE_RE = re.compile(
    r"^\s*package\s+"
    r"([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*;",
)

# Lua package.path templates the harness installs (in order) ahead of
# the interpreter's inherited default.  Single-homed: the generator
# renders package.path from this tuple and the Lua adapter derives its
# candidate slots from it, so search order can never drift between the
# validator and the harness.  ``?.lua`` before ``?/init.lua`` (the
# standard order): an ``init.lua`` finding therefore binds only when
# the earlier ``<dir>.lua`` slot is verified vacant — occupied or
# unverifiable means the loader would pick the plantable sibling.
_LUA_PATH_TEMPLATES: tuple[str, ...] = ("?.lua", "?/init.lua")


def _norm(file_path: str) -> str:
    return file_path.replace("\\", "/")


# ---------------------------------------------------------------------------
# Reference derivations shared with the harness generators
# ---------------------------------------------------------------------------


def file_to_import_path(file_path: str, _target_root: Path) -> str | None:
    """``core/audit/gate.py`` → ``core.audit.gate``. None for non-Python."""
    rel = _norm(file_path)
    p = PurePosixPath(rel)
    if p.suffix != ".py":
        return None
    parts = list(p.parts)
    parts[-1] = p.stem
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return None
    return ".".join(parts)


def derive_js_require_path(spec: DarkWitnessSpec) -> str:
    """Resolve require path from spec or file.

    The derived default is the EXACT file path with extension: a
    stripped stem inherits Node's resolution ambiguity (the
    extensionless path is tried first, so a repo-planted `src/auth`
    file would shadow `src/auth.js`), and the exact spelling is the
    one require() resolves unambiguously.
    """
    rp = spec.lang_config.get("require_path", "")
    if rp:
        return rp
    return "./" + spec.file


def derive_ruby_require_path(spec: DarkWitnessSpec) -> str:
    rp = spec.lang_config.get("require_path", "")
    if rp:
        return rp
    return spec.file.removesuffix(".rb")


def derive_php_require_path(spec: DarkWitnessSpec) -> str:
    return spec.lang_config.get("require_path", "") or spec.file


def derive_lua_require_path(spec: DarkWitnessSpec) -> str:
    rp = spec.lang_config.get("require_path", "")
    if rp:
        return rp
    rel = spec.file.removesuffix(".lua")
    return rel.replace("/", ".")


def derive_perl_use_module(spec: DarkWitnessSpec) -> str:
    um = spec.lang_config.get("use_module", "")
    if um:
        return um
    rel = spec.file
    if rel.endswith((".pl", ".pm")):
        rel = rel[:-3]
    return rel.replace("/", "::")


# ---------------------------------------------------------------------------
# Shared first-hit search core
# ---------------------------------------------------------------------------


def _reject(field: str, value: str, file: str) -> str:
    return f"{field} {value!r} not bound to the finding's file {file!r}"


def _slot_hit(target_root: Path, slot: str) -> str | None:
    """Relative path occupying *slot*, or None when vacant.

    A slot containing ``*`` is a glob over the target tree (used for
    ABI-tagged extension suffixes like ``mod.cpython-*.so``); glob
    metacharacters can only come from the engine's own suffix tables —
    the identifier-shaped reference components never contain them.
    """
    if "*" in slot:
        hit = next(iter(target_root.glob(slot)), None)
        return str(hit.relative_to(target_root)) if hit is not None else None
    return slot if (target_root / slot).exists() else None


def _first_hit_binding_error(
    field: str,
    ref: str,
    candidates: list[str],
    file: str,
    target_root: Path | None,
) -> str | None:
    """Bind *ref* to *file* in the loader's search order.

    *candidates* are the target-root-relative paths the loader tries
    for *ref*, in the loader's real search order (entries may be globs
    for ABI-tagged suffixes, see ``_slot_hit``).  The reference binds
    only when the finding's file is a candidate AND every earlier slot
    is vacant — an occupied earlier slot means the loader picks that
    file (a plantable lookalike) instead.  Earlier slots can only be
    checked against a real tree, so a shadowed reference without a
    *target_root* is refused, never assumed vacant.
    """
    if file not in candidates:
        return _reject(field, ref, file)
    shadows = candidates[: candidates.index(file)]
    if not shadows:
        return None
    if target_root is None:
        return (
            f"{field} {ref!r} resolves through earlier loader slots "
            f"({', '.join(repr(s) for s in shadows)}) that cannot be "
            f"verified vacant without the target tree"
        )
    for slot in shadows:
        hit = _slot_hit(target_root, slot)
        if hit is not None:
            return (
                f"{field} {ref!r} resolves to {hit!r} before the "
                f"finding's file {file!r} — plantable shadow slot occupied"
            )
    return None


# ---------------------------------------------------------------------------
# Per-language resolution adapters
# ---------------------------------------------------------------------------

# Module-artifact suffixes CPython's FileFinder tries for one name, in
# loader-priority order: EXTENSION modules first (EXTENSION_SUFFIXES —
# every real member ends in .so or .pyd, matched by glob to stay
# ABI-tag agnostic across builds), then SOURCE (.py), then sourceless
# BYTECODE (.pyc).  Occupancy of any slot EARLIER than the finding's
# refuses, so ordering among the extension globs themselves is
# immaterial.
_PY_EXT_SUFFIX_GLOBS: tuple[str, ...] = (".so", ".*.so", ".pyd", ".*.pyd")
_PY_SUFFIX_GLOBS: tuple[str, ...] = (*_PY_EXT_SUFFIX_GLOBS, ".py", ".pyc")


def _py_init_slots(dir_path: str, suffixes: tuple[str, ...]) -> list[str]:
    """``__init__`` slots that make *dir_path* a regular package."""
    return [f"{dir_path}/__init__{s}" for s in suffixes]


def _py_module_slots(base: str, suffixes: tuple[str, ...]) -> list[str]:
    """Module-file slots FileFinder tries for the name at *base*."""
    return [base + s for s in suffixes]


def _resolve_python(spec: DarkWitnessSpec, target_root: Path | None) -> str | None:
    mp = spec.module_path
    if not mp:
        # Presence is enforced at the Python executor
        # (validate_import_path); validate_spec may legitimately see a
        # spec before module_path derivation.
        return None
    file = _norm(spec.file)
    expected = file_to_import_path(file, target_root or Path("."))
    if expected is None:
        return f"non-Python file: {spec.file}"
    if mp != expected:
        return (
            f"module_path mismatch: LLM said {mp!r} "
            f"but file {spec.file!r} implies {expected!r}"
        )
    parts = mp.split(".")
    base = "/".join(parts)
    # CPython resolves ONE name per path level, trying in order: a
    # directory holding any ``__init__`` artifact (regular package,
    # extension init before source init), then module files
    # (extension before source before bytecode), and only LAST a
    # bare directory as a PEP 420 namespace portion.  So intermediate
    # components DO carry hijack direction: when the finding's own
    # path implies a namespace level (no ``__init__.py``), a planted
    # module file at that level (``pkg.py`` beside the ``pkg/`` dir)
    # outranks the whole subtree — its import-time code owns
    # ``sys.modules`` before the finding's module is ever considered.
    # A regular-package level is bound by its own ``__init__.py``
    # ahead of any same-named module file; only the earlier
    # extension-init slots remain plantable there.
    candidates: list[str] = []
    for i in range(1, len(parts)):
        level = "/".join(parts[:i])
        candidates += _py_init_slots(level, _PY_EXT_SUFFIX_GLOBS)
        if target_root is not None and (
                target_root / level / "__init__.py").is_file():
            continue  # regular package: module-file slots rank later
        candidates += _py_init_slots(level, (".py", ".pyc"))
        candidates += _py_module_slots(level, _PY_SUFFIX_GLOBS)
    if file == base + "/__init__.py":
        # A package finding is outranked only by an extension-init
        # artifact in its own directory.
        candidates += _py_init_slots(base, _PY_EXT_SUFFIX_GLOBS)
        candidates.append(file)
    else:
        # A module finding is outranked by ANY ``__init__`` artifact
        # in a same-named sibling directory (dir-with-init wins over
        # module files regardless of suffix) and by extension-module
        # files for the same name; bytecode ranks after source.
        candidates += _py_init_slots(base, _PY_SUFFIX_GLOBS)
        candidates += _py_module_slots(base, _PY_EXT_SUFFIX_GLOBS)
        candidates.append(base + ".py")
    return _first_hit_binding_error(
        "module_path", mp, candidates, file, target_root,
    )


def _resolve_js(spec: DarkWitnessSpec, target_root: Path | None) -> str | None:
    rp = spec.lang_config.get("require_path", "")
    if not rp:
        return None  # derived default is the exact file spelling
    file = _norm(spec.file)
    # Only the exact file path (with extension) resolves unambiguously:
    # for a stem spelling Node's LOAD_AS_FILE tries the extensionless
    # path FIRST (a repo-planted file named `src/auth` shadows
    # `src/auth.js`) and tries `.js` before `.ts` under the TS loaders;
    # the directory/index spelling consults a repo-plantable
    # package.json "main" before index files.  The exact spelling is
    # Node's step-1 file hit — resolution is unique by construction,
    # with or without a tree — so every other spelling is refused
    # rather than order-simulated.  Node's suffix ladder (`.js`,
    # `.json`, `.node`) only starts AFTER the exact path misses, so a
    # planted `auth.json`/`auth.node` never outranks an accepted
    # exact-path reference.
    cand = rp[2:] if rp.startswith("./") else rp
    if cand != file:
        return _reject("require_path", rp, file)
    return None


def _resolve_ruby(spec: DarkWitnessSpec, target_root: Path | None) -> str | None:
    rp = spec.lang_config.get("require_path", "")
    if not rp:
        return None
    file = _norm(spec.file)
    # require resolves an extensionless feature by appending ``.rb``
    # across the whole $LOAD_PATH before it falls back to native
    # extension suffixes, and the harness unshifts the target root to
    # $LOAD_PATH[0] — so both accepted spellings (exact path, stem)
    # have the finding's file in the first slot the loader tries; a
    # planted ``.so`` never outranks the ``.rb``.
    stem = file.removesuffix(".rb")
    if rp not in (file, stem):
        return _reject("require_path", rp, file)
    return None


def _resolve_php(spec: DarkWitnessSpec, target_root: Path | None) -> str | None:
    rp = spec.lang_config.get("require_path", "")
    if not rp:
        return None
    file = _norm(spec.file)
    # require_once() receives the target-root-joined path verbatim —
    # no include-path search, no extension probing: the exact file
    # path is the only spelling that resolves, uniquely.
    if rp != file:
        return _reject("require_path", rp, file)
    return None


def _resolve_lua(spec: DarkWitnessSpec, target_root: Path | None) -> str | None:
    file = _norm(spec.file)
    explicit = bool(spec.lang_config.get("require_path", ""))
    rp = derive_lua_require_path(spec)
    # require() maps EVERY dot in the module name to a directory
    # separator and substitutes the result into the package.path
    # templates in order — the harness installs _LUA_PATH_TEMPLATES
    # ahead of the interpreter's inherited (cwd-dependent) default, so
    # those templates ARE the loader's deterministic search order.
    # Native lookalikes cannot outrank them: the package.path searcher
    # runs BEFORE the C-library searcher (package.cpath ``?.so``) and
    # the all-in-one loader in Lua's package.searchers order, so a
    # planted ``.so`` beside the finding never wins while a
    # package.path template hits.
    resolved = rp.replace(".", "/")
    candidates = [resolved + t.removeprefix("?") for t in _LUA_PATH_TEMPLATES]
    if file not in candidates:
        if explicit:
            return _reject("require_path", rp, file)
        # The derived default inherits the same dot→separator mapping,
        # so a finding whose own path needs a dot that must NOT map
        # (dotted dirname or filename stem) has no unambiguous
        # spelling at all.
        return (
            f"finding file {spec.file!r} has no unambiguous Lua require "
            f"spelling (require maps dots to directory separators)"
        )
    return _first_hit_binding_error(
        "require_path", rp, candidates, file, target_root,
    )


def _resolve_perl(spec: DarkWitnessSpec, target_root: Path | None) -> str | None:
    file = _norm(spec.file)
    um = derive_perl_use_module(spec)
    # Bareword ``require Foo::Bar`` maps ``::`` to ``/`` and appends
    # ``.pm`` ONLY (perlfunc) — and the harness puts the target root
    # first on @INC, so the single candidate slot is deterministic.
    resolved = um.replace("::", "/") + ".pm"
    if file != resolved:
        if file.endswith(".pl"):
            # No bareword spelling can EVER load a ``.pl`` file; the
            # loader would bind a same-stem ``.pm`` plant (or nothing).
            # Decline to verify rather than execute the wrong code.
            return (
                f"finding file {spec.file!r} cannot be loaded by Perl's "
                f"bareword require (it resolves 'require {um}' to "
                f"{resolved!r} — .pm only); declining to verify"
            )
        return _reject("use_module", um, file)
    return None


def _go_module_path(target_root: Path | None) -> str | None:
    """Module path declared by the target's root go.mod, or None when
    unreadable/undeclared."""
    if target_root is None:
        return None
    try:
        text = (target_root / "go.mod").read_text(
            encoding="utf-8", errors="replace",
        )
    except OSError:
        return None
    for line in text.splitlines():
        m = re.match(r'\s*module\s+"?([^\s"]+)"?\s*(?://.*)?$', line)
        if m:
            return m.group(1)
    return None


def _resolve_go(spec: DarkWitnessSpec, target_root: Path | None) -> str | None:
    ip = spec.lang_config.get("import_path", "")
    if not ip:
        return None  # package-main findings compile the target source directly
    file = _norm(spec.file)
    # Go resolves an import path by stripping the module prefix (from
    # go.mod) and mapping the remainder to a directory — a suffix check
    # would accept "example.com/m/x/a/b" for a finding in a/b/ (Go
    # resolves it to x/a/b, a plantable lookalike package), and leave
    # root-package findings unchecked.  The one import path that loads
    # the finding's package is the module path joined with its
    # directory.  No readable go.mod = no resolution to verify —
    # refuse; GOPATH-mode imports could not resolve inside the
    # harness's scratch GOPATH anyway.
    pkg_dir = str(PurePosixPath(file).parent)
    module = _go_module_path(target_root)
    if module is None:
        return (
            f"cannot bind import_path {ip!r} to the finding's file "
            f"{spec.file!r}: no readable module declaration in "
            f"go.mod at the target root"
        )
    expected = module if pkg_dir in (".", "") else f"{module}/{pkg_dir}"
    if ip != expected:
        return _reject("import_path", ip, file)
    return None


def _java_package_decl(source_file: Path) -> str | None:
    """Package declared by *source_file*: ``""`` for the default
    package, None when the file cannot be read (refuse upstream)."""
    try:
        with source_file.open("r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(_JAVA_DECL_SCAN_BYTES)
    except OSError:
        return None
    stripped = _strip_java_comments(head)
    m = _JAVA_PACKAGE_RE.match(stripped.lstrip())
    return m.group(1) if m else ""


def _java_import_terminal(imp: str) -> str:
    body = imp[len("static"):].strip() if imp.startswith("static") else imp
    return body.rsplit(".", 1)[-1]


def _resolve_java(spec: DarkWitnessSpec, target_root: Path | None) -> str | None:
    lc = spec.lang_config
    file = _norm(spec.file)
    stem = PurePosixPath(file).stem
    # Bind the harness to the finding's FILE: the compile classpath
    # spans the whole target tree, so an unbound class_name reaches any
    # class in the repo.  Java's public-class rule ties the file stem
    # to the class; nested classes keep the stem as their outer prefix.
    cn = lc.get("class_name", "")
    if cn and cn != stem and not cn.startswith(stem + "."):
        return (
            f"class_name {cn!r} not bound to the finding's file "
            f"({spec.file!r} implies {stem!r})"
        )
    imports = [str(i).strip() for i in lc.get("imports", []) if str(i).strip()]
    # A single-type import whose terminal simple name is the finding's
    # class stem wins the simple-name lookup over both the harness's
    # own (default) package and every on-demand import (JLS 6.4.1) —
    # it re-binds EVERY `Stem` reference in the harness to whatever
    # class it names on the whole-tree classpath, a plantable
    # lookalike.  The one legitimate stem import is the finding's own
    # package-qualified name, derived from the file's package
    # declaration in the resolution direction.
    stem_imports = [i for i in imports if _java_import_terminal(i) == stem]
    if target_root is None:
        if stem_imports:
            return (
                f"import {stem_imports[0]!r} names the finding's class "
                f"stem {stem!r} but cannot be verified against the "
                f"file's package declaration without the target tree"
            )
        return None
    pkg = _java_package_decl(target_root / file)
    if pkg is None:
        return (
            f"cannot read the package declaration of {spec.file!r} to "
            f"bind the harness's class reference; declining to verify"
        )
    if not pkg:
        if stem_imports:
            # The default package cannot be imported (JLS 7.5.1): any
            # import naming the stem binds a lookalike, never the
            # finding's class.
            return (
                f"import {stem_imports[0]!r} not bound to the finding's "
                f"file {spec.file!r} (its class is in the default "
                f"package, which cannot be imported)"
            )
        return None
    expected = f"{pkg}.{stem}"
    for imp in stem_imports:
        if imp != expected:
            return (
                f"import {imp!r} not bound to the finding's file "
                f"{spec.file!r} (its package declaration implies "
                f"{expected!r})"
            )
    if expected not in imports:
        # Without the single-type import the harness's `Stem` reference
        # can only resolve through an on-demand import — a channel a
        # planted package on the whole-tree classpath can serve.
        return (
            f"class {stem!r} is declared in package {pkg!r}; the "
            f"harness needs the single-type import {expected!r} to bind "
            f"it to the finding's file"
        )
    return None


# ---------------------------------------------------------------------------
# Lane registry + public entry point
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LaneBinding:
    """How one language lane binds the loaded artifact to the finding.

    ``resolver`` lanes answer through a resolution adapter above;
    ``structural`` lanes bind without any loader search and carry a
    rationale naming the mechanism instead.
    """

    mode: str  # "resolver" | "structural"
    resolver: Callable[[DarkWitnessSpec, Path | None], str | None] | None = None
    rationale: str = ""


_LANE_BINDINGS: dict[str, LaneBinding] = {
    "python": LaneBinding("resolver", _resolve_python),
    "javascript": LaneBinding("resolver", _resolve_js),
    "typescript": LaneBinding("resolver", _resolve_js),
    "ruby": LaneBinding("resolver", _resolve_ruby),
    "php": LaneBinding("resolver", _resolve_php),
    "lua": LaneBinding("resolver", _resolve_lua),
    "perl": LaneBinding("resolver", _resolve_perl),
    "go": LaneBinding("resolver", _resolve_go),
    "java": LaneBinding("resolver", _resolve_java),
    "c": LaneBinding(
        "structural",
        rationale=(
            "harness and spec.file are compiled together — cc receives "
            "the finding's path on its command line; no loader search"
        ),
    ),
    "cpp": LaneBinding(
        "structural",
        rationale=(
            "harness and spec.file are compiled together — c++ receives "
            "the finding's path on its command line; no loader search"
        ),
    ),
    "rust": LaneBinding(
        "structural",
        rationale=(
            "the executor copies spec.file to target_source.rs and the "
            "harness splices it via include! — no loader search "
            "(use_path only names items within that spliced crate root)"
        ),
    ),
}


def binding_error(
    spec: DarkWitnessSpec,
    lang: str,
    target_root: Path | None = None,
) -> str | None:
    """Refusal reason when the spec's module reference does not resolve
    to the finding's file under *lang*'s loader rules; None when bound.

    Unregistered languages are refused — a lane without a declared
    binding mode must never execute (the registry closure test pins
    the registry to ``_SUPPORTED_LANGS``).
    """
    lane = _LANE_BINDINGS.get(lang)
    if lane is None:
        return f"no module-binding lane registered for language: {lang or '(unknown)'!r}"
    if lane.mode == "structural":
        return None
    assert lane.resolver is not None
    return lane.resolver(spec, target_root)


__all__ = [
    "LaneBinding",
    "_LANE_BINDINGS",
    "_SUPPORTED_LANGS",
    "binding_error",
    "derive_js_require_path",
    "derive_lua_require_path",
    "derive_perl_use_module",
    "derive_php_require_path",
    "derive_ruby_require_path",
    "file_to_import_path",
]
