"""Resolve a Rust crate's module tree → the set of compiled ``.rs`` files.

Rust only compiles a source file if it is reachable from a crate root through
explicit ``mod`` declarations (or ``#[path]`` / ``include!``). A ``.rs`` file in
the project that no crate root reaches via the mod tree is **not part of the
crate** — never compiled, so every function in it is dead. This is the Rust
analog of C/C++ translation-unit membership (compile_commands).

:func:`extract_rust_crate_modules` returns the set of absolute ``.rs`` paths
reachable from the crate's roots, or ``None`` when membership can't be
determined (no ``Cargo.toml``, or no recognizable crate root — e.g. a bare
workspace root). ``None`` means UNKNOWN: the build-membership witness must not
fire.

Heuristic / surface-only, like the C/C++ counterpart. The mod scan is regex
based (no tree-sitter dependency, so it works on every CI path), and errs
toward INCLUSION: a missed ``mod`` edge under-counts the reachable set, which
at worst marks a genuinely-compiled file build_excluded — and since the witness
only demotes/surfaces (never hard-suppresses), that is noise, not a false
negative. ``#[path]`` and per-target path overrides in ``Cargo.toml`` and
workspaces are best-effort; unresolved cases stay conservative. All candidate
files are confined to the repo root (symlink-aware): analysed sources cannot
direct probes or reads outside the tree.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# A FILE module declaration: ``mod foo;`` (ends with ``;``), optionally preceded
# by an inline ``#[path = "…"]`` and visibility. Inline modules (``mod foo {``)
# declare no file, so the trailing ``;`` is required. Attributes/visibility
# before ``mod`` are tolerated by anchoring only on the ``mod NAME ;`` shape.
_MOD_DECL = re.compile(
    r'(?:#\[\s*path\s*=\s*"([^"]*)"\s*\]\s*)?'      # optional #[path="..."]
    r'(?:pub\s*(?:\([^)]*\)\s*)?)?'                  # optional pub / pub(...)
    r'\bmod\s+([A-Za-z_]\w*)\s*;',
)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_SPECIAL_ROOT_NAMES = frozenset({"lib.rs", "main.rs", "mod.rs"})


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", text))


def _crate_roots(target: Path) -> list[Path]:
    """Default-layout crate roots. Path overrides in Cargo.toml and workspace
    members are not resolved (best-effort); missing a root only causes
    conservative noise, never a false negative."""
    roots: list[Path] = []
    src = target / "src"
    for name in ("lib.rs", "main.rs"):
        p = src / name
        if p.is_file():
            roots.append(p)
    for sub in ("bin",):
        d = src / sub
        if d.is_dir():
            roots.extend(sorted(d.glob("*.rs")))
    for d_name in ("examples", "tests", "benches"):
        d = target / d_name
        if d.is_dir():
            roots.extend(sorted(d.glob("*.rs")))
    build_rs = target / "build.rs"
    if build_rs.is_file():
        roots.append(build_rs)
    return roots


def _module_base_dir(parent_file: Path) -> Path:
    """Directory Rust searches for a child ``mod`` of ``parent_file``.
    ``lib.rs`` / ``main.rs`` / ``mod.rs`` search their own directory; any other
    module file ``foo.rs`` searches the ``foo/`` subdirectory."""
    if parent_file.name in _SPECIAL_ROOT_NAMES:
        return parent_file.parent
    return parent_file.parent / parent_file.stem


def _in_root(cand: Path, root: Path) -> bool:
    """True when ``cand`` resolves inside ``root`` (the resolved repo root).
    ``#[path = "…"]`` values come from the analysed (untrusted) sources: an
    absolute value discards the join base and ``../`` escapes the crate tree,
    so every candidate is confined BEFORE any filesystem probe — otherwise
    ``is_file`` is a host file-existence oracle and out-of-tree files get
    read. Symlinks are followed by ``resolve``, so a link pointing out of the
    repo is rejected too."""
    try:
        resolved = cand.resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved.is_relative_to(root)


def _resolve_child(parent_file: Path, mod_name: str,
                   path_attr: str | None, root: Path) -> Path | None:
    if path_attr:
        cand = parent_file.parent / path_attr
        return cand if _in_root(cand, root) and cand.is_file() else None
    base = _module_base_dir(parent_file)
    for cand in (base / f"{mod_name}.rs", base / mod_name / "mod.rs"):
        if _in_root(cand, root) and cand.is_file():
            return cand
    return None


def _file_mods(file: Path) -> list[tuple[str | None, str]]:
    try:
        text = _strip_comments(file.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []
    return [(m.group(1), m.group(2)) for m in _MOD_DECL.finditer(text)]


def extract_rust_crate_modules(target: Path) -> frozenset | None:
    """Set of absolute ``.rs`` paths compiled into the crate(s) under
    ``target`` (resolved to match the inventory builder's paths), or ``None``
    when membership is unknown (no ``Cargo.toml`` / no crate root found)."""
    target = Path(target)
    if not target.is_dir() or not (target / "Cargo.toml").is_file():
        return None
    try:
        root = target.resolve()
    except OSError:
        return None  # can't confine candidates → membership unknown
    roots = _crate_roots(target)
    if not roots:
        return None
    reachable = set()
    queue: list[Path] = list(roots)
    while queue:
        f = queue.pop()
        try:
            rf = f.resolve()
        except OSError:
            continue  # unresolvable → containment unverifiable, skip
        key = str(rf)
        if key in reachable or not rf.is_relative_to(root) or not f.is_file():
            continue
        reachable.add(key)
        for path_attr, mod_name in _file_mods(f):
            child = _resolve_child(f, mod_name, path_attr, root)
            if child is not None:
                queue.append(child)
    return frozenset(reachable) if reachable else None


__all__ = ["extract_rust_crate_modules"]
