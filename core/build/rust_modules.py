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
    # (visibility span bounded: unbounded, every planted "pub(" re-scans
    # the rest of hostile source — quadratic; real visibility paths are
    # tiny)
    r'(?:pub\s*(?:\([^)]{0,200}\)\s*)?)?'            # optional pub / pub(...)
    r'\bmod\s+([A-Za-z_]\w*)\s*;',
)
_SPECIAL_ROOT_NAMES = frozenset({"lib.rs", "main.rs", "mod.rs"})

# Non-code region openers for the fallback scanner: comments, raw
# strings with the FULL prefix family from the Rust reference grammar
# — ``r`` (raw), ``br`` (raw byte, RFC 1552), ``cr`` (raw C-string,
# Rust 1.77) at any # count — plain / byte / C strings, char / byte
# literals. The family must be complete: a missing raw prefix
# (``cr#"…"#``) half-matches as identifier + plain string, and the
# phantom string swallows trailing code — dropping real ``mod`` edges
# (demote-direction for the consumer's witness). Longer alternatives
# first so ``br#"`` never half-matches as its shorter forms.
_NONCODE_OPEN = re.compile(r'//|/\*|(?:br|cr|r)#*"|[bc]?"|b?\'')
_CHAR_LIT = re.compile(r"'(?:\\[^\n]|[^\\'\n])'")
_NON_NL = re.compile(r"[^\n]")


def _blank(span: str) -> str:
    """Spaces for everything but newlines — offsets and line counts
    survive blanking."""
    return _NON_NL.sub(" ", span)


def _strip_noncode(text: str) -> str:  # noqa: C901 — one lexer, one home
    """Blank comments and string/char-literal interiors to spaces.

    Linear fallback scanner for when the validated shared lexer can't
    vouch a view: every region is skipped with ``str.find`` from its
    opener — no lazy-dotall backtracking (the regex stripper this
    replaces re-scanned to end-of-string once per ``/*`` on
    unclosed-comment input: quadratic, extrapolating to ~an hour per
    planted 2 MiB file in the unsandboxed parent), and the
    nested-comment loop memoizes its forward-only delimiter scans so
    a run of openers against one far closer costs one pass, not one
    scan per depth level. Rust block comments
    NEST; ``//`` inside a string is data (it used to delete a
    same-line ``mod`` decl); a ``mod x;`` inside a string is not a
    module edge. Unterminated regions blank to end-of-file (rustc
    rejects such a file anyway; blanking errs toward fewer edges —
    inclusion-tier noise, never suppression, because the consumer's
    witness is demote-only).
    """
    out: list = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _NONCODE_OPEN.search(text, pos)
        if m is None:
            out.append(text[pos:])
            break
        start, tok = m.start(), m.group()
        if (tok[0] in "brc" and start > 0
                and (text[start - 1].isalnum() or text[start - 1] == "_")):
            # Identifier tail (``abr#"…``): not a literal prefix.
            out.append(text[pos:start + 1])
            pos = start + 1
            continue
        out.append(text[pos:start])
        if tok == "//":
            end = text.find("\n", start)
            end = n if end == -1 else end
            out.append(" " * (end - start))
            pos = end
        elif tok == "/*":
            depth, p = 1, start + 2
            # Memoized delimiter positions: both only ever move
            # FORWARD (str.find returns the first occurrence at or
            # after p, and p only advances), so one cached scan
            # serves every depth iteration. Recomputing per
            # iteration is quadratic in both directions — a far
            # closer behind a run of openers re-scans toward the
            # closer once per opener, and a run of closers re-scans
            # to end-of-string for the absent opener once per
            # closer. -1 is terminal (no later occurrence exists).
            nxt_close = nxt_open = -2  # -2: not yet computed
            while depth:
                if nxt_close != -1 and nxt_close < p:
                    nxt_close = text.find("*/", p)
                if nxt_close == -1:
                    p = n
                    break
                if nxt_open != -1 and nxt_open < p:
                    nxt_open = text.find("/*", p)
                if nxt_open != -1 and nxt_open < nxt_close:
                    depth += 1
                    p = nxt_open + 2
                else:
                    depth -= 1
                    p = nxt_close + 2
            out.append(_blank(text[start:p]))
            pos = p
        elif tok.endswith('"') and tok not in ('"', 'b"', 'c"'):
            # Raw string: closes only on `"` + the opener's # count.
            # Delimiters survive blanking (the shared lexer's edges
            # mode does the same) so shapes like ``#[path = "…"]``
            # keep their structure in the view.
            closer = '"' + "#" * tok.count("#")
            end = text.find(closer, m.end())
            if end == -1:
                out.append(tok + _blank(text[m.end():]))
                pos = n
            else:
                out.append(tok + _blank(text[m.end():end]) + closer)
                pos = end + len(closer)
        elif tok.endswith('"'):
            p = m.end()
            closed = False
            while True:
                q = text.find('"', p)
                if q == -1:
                    p = n
                    break
                backslashes = 0
                k = q - 1
                while k >= 0 and text[k] == "\\":
                    backslashes += 1
                    k -= 1
                p = q + 1
                if backslashes % 2 == 0:
                    closed = True
                    break
            if closed:
                out.append(tok + _blank(text[m.end():p - 1]) + '"')
            else:
                out.append(tok + _blank(text[m.end():p]))
            pos = p
        else:  # ' or b' — char/byte literal vs lifetime
            quote = start + tok.index("'")
            lit = _CHAR_LIT.match(text, quote)
            if lit is None:
                # Lifetime (``'a``) or stray quote: code, keep it.
                out.append(text[start:quote + 1])
                pos = quote + 1
            else:
                out.append(text[start:quote])
                out.append("'" + _blank(lit.group()[1:-1]) + "'")
                pos = lit.end()
    return "".join(out)


def _code_view(text: str) -> str:
    """Comments + literal interiors blanked, code preserved.

    The shared validated lexer first (nested-block-comment- and
    string-aware by grammar — replacing hand-rolled strippers of
    exactly this class is what it exists for); the linear fallback
    scanner when no grammar is installed or the file doesn't parse.
    """
    from core.inventory.lexical_view import LexicalRefusal, blank_noncode

    try:
        view = blank_noncode("rust", text)
    except LexicalRefusal:
        view = None
    if view is not None:
        return view
    return _strip_noncode(text)


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


# Per-file read budget for untrusted .rs sources (the module set's
# bounded-read doctrine: the walk runs in the unsandboxed parent, so a
# planted multi-GB .rs file must not be loaded whole; real crate roots
# are orders of magnitude smaller). Truncation only costs mod decls
# past the cap — under-detection, membership stays sound-or-unknown.
_MAX_RS_BYTES = 2 * 1024 * 1024

# Reachable-file cap: a hostile crate fanning out to an unbounded
# module tree must not keep the parent walking forever. Past the cap
# membership is UNKNOWN (None) — the conservative direction, no
# module-based suppression rather than a truncated (wrong) set.
_MAX_REACHABLE_FILES = 20_000


def _file_mods(file: Path) -> list[tuple[str | None, str]]:
    from core.source import read_text_capped

    # Resolve first: the caller already confined the RESOLVED path,
    # and the capped reader refuses a symlink at the final component.
    try:
        file = file.resolve()
    except (OSError, RuntimeError, ValueError):
        return []
    got = read_text_capped(file, _MAX_RS_BYTES)
    if got is None:
        return []
    text = got[0]
    view = _code_view(text)
    if len(view) != len(text):
        # The shared lexer blanks per BYTE, so multi-byte characters
        # can shift decoded offsets; the fallback scanner is
        # char-length-preserving by construction and keeps the
        # span-recovery below sound.
        view = _strip_noncode(text)
    mods: list = []
    for m in _MOD_DECL.finditer(view):
        # The VIEW decides which declarations are code (strings and
        # comments blanked); the ORIGINAL text supplies the values —
        # a ``#[path = "…"]`` attribute value is itself a string
        # literal the view blanked. Spans align (length-preserving
        # blanking), so re-matching the original slice recovers it.
        m_orig = _MOD_DECL.search(text, m.start(), m.end())
        use = m_orig if m_orig is not None else m
        mods.append((use.group(1), use.group(2)))
    return mods


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
        if len(reachable) > _MAX_REACHABLE_FILES:
            return None
        for path_attr, mod_name in _file_mods(f):
            child = _resolve_child(f, mod_name, path_attr, root)
            if child is not None:
                queue.append(child)
    return frozenset(reachable) if reachable else None


__all__ = ["extract_rust_crate_modules"]
