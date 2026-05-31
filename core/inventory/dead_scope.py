"""Detect lexically dead scopes — blocks guarded by an always-false
condition or build gate, inside which function definitions never bind.

A function defined inside ``if False:`` (Python), ``if (false) {…}``
(JS/TS), or behind ``#[cfg(any())]`` (Rust) is never created: the
guard's body never executes / compiles. The substrate's call-graph
analysis can't see this — two dead-scope functions that call each
other read as mutually CALLED, masking that the whole scope is dead.

This module returns the *line ranges* of dead scopes. The inventory
builder maps function ``line_start`` values into those ranges and tags
the matching items ``lexical_dead=True``; the reachability prepass
then demotes them regardless of in-scope call edges.

Conservative bias (same as :mod:`core.inventory.module_load_abort`):
only fire on unambiguously-constant guards. ``if DEBUG:`` is NOT dead
(DEBUG is a runtime name); ``if False:`` IS. ``#[cfg(test)]`` is NOT
dead (it compiles under the test profile); ``#[cfg(any())]`` IS
(an empty ``any()`` is the canonical always-false cfg). False
negatives are cheap (miss a deferral); false positives are expensive
(silence a real finding in live code).

Per-language detection currently handled:

  * Python: ``if <falsey-constant>:`` / ``while <falsey-constant>:``
    — the BODY only (``else`` / ``elif`` branches stay live). Falsey
    constants: ``False``, ``0``, ``0.0``, ``""``, ``None``.
  * JavaScript / TypeScript: ``if (false) {…}`` / ``if (0) {…}`` at
    any brace depth — the guarded block range.
  * Rust: ``if false {…}`` blocks, and ``#[cfg(any())]`` /
    ``#[cfg(all(any()))]`` attributes — the following ``fn`` block.

Other languages return ``[]`` (no detector wired) — graceful
degradation; the consumer treats absence as "no dead scope found",
never as "everything is live".
"""

from __future__ import annotations

import ast
import logging
import re
from typing import List, Tuple

logger = logging.getLogger(__name__)

# A dead scope is reported as an inclusive ``(start_line, end_line)``
# 1-indexed range. A function whose ``line_start`` falls within any
# returned range is lexically dead.
DeadRange = Tuple[int, int]


def detect_dead_scopes(language: str, content: str) -> List[DeadRange]:
    """Per-language dispatch. Returns inclusive 1-indexed line ranges
    of lexically dead scopes, or ``[]`` when none found (or the
    language has no detector wired).

    Best-effort: any parse failure returns ``[]``; the caller treats
    absence as "no dead scope".
    """
    if not content:
        return []
    try:
        if language == "python":
            return _detect_python(content)
        if language in ("javascript", "typescript", "tsx"):
            return _detect_javascript(content)
        if language == "rust":
            return _detect_rust(content)
        if language == "php":
            return _detect_php(content)
        if language == "ruby":
            return _detect_ruby(content)
    except Exception:  # noqa: BLE001
        return []
    return []


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _detect_python(content: str) -> List[DeadRange]:
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(content)
    except SyntaxError:
        return []
    ranges: List[DeadRange] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While)) and _py_test_is_false(
            node.test
        ):
            # Only the guard's BODY is dead — orelse (else / elif)
            # stays live and is walked separately by ast.walk, so a
            # const-false elif nested in orelse is still caught on its
            # own iteration.
            body = node.body
            if not body:
                continue
            start = body[0].lineno
            end = max(_py_end_line(s) for s in body)
            ranges.append((start, end))
    return ranges


def _py_test_is_false(test: ast.expr) -> bool:
    """True iff the guard expression is an unambiguous falsey literal
    (``False`` / ``0`` / ``0.0`` / ``""`` / ``None``). Runtime names
    (``if DEBUG:``) and any non-literal expression are NOT dead."""
    if not isinstance(test, ast.Constant):
        return False
    return not bool(test.value)


def _py_end_line(stmt: ast.stmt) -> int:
    return getattr(stmt, "end_lineno", None) or stmt.lineno


# ---------------------------------------------------------------------------
# JavaScript / TypeScript — brace-tracked ``if (false) {…}`` blocks.
# Regex finds the guard header; manual brace matching finds the block
# extent (no stdlib JS AST; tree-sitter would be heavier than needed).
# ---------------------------------------------------------------------------


_JS_LINE_COMMENT = re.compile(r"//[^\n]*")
_JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_JS_DEAD_IF = re.compile(r"\bif\s*\(\s*(?:false|0)\s*\)\s*\{")


def _detect_javascript(content: str) -> List[DeadRange]:
    stripped = _js_strip_comments(content)
    ranges: List[DeadRange] = []
    for m in _JS_DEAD_IF.finditer(stripped):
        # The opening brace is the last char of the match.
        brace_pos = m.end() - 1
        close = _match_brace(stripped, brace_pos)
        if close is None:
            continue
        start_line = stripped.count("\n", 0, m.start()) + 1
        end_line = stripped.count("\n", 0, close) + 1
        ranges.append((start_line, end_line))
    return ranges


def _js_strip_comments(content: str) -> str:
    def _spaces(m: "re.Match[str]") -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    out = _JS_BLOCK_COMMENT.sub(_spaces, content)
    out = _JS_LINE_COMMENT.sub(_spaces, out)
    return out


# ---------------------------------------------------------------------------
# Rust — ``if false {…}`` blocks plus ``#[cfg(any())]`` attributes
# (empty ``any()`` is the canonical always-false cfg) gating a fn.
# ---------------------------------------------------------------------------


_RUST_DEAD_IF = re.compile(r"\bif\s+false\s*\{")
# ``#[cfg(any())]`` or ``#[cfg(all(any()))]`` — empty any() is false,
# and all(false) is false. Whitespace-tolerant.
_RUST_DEAD_CFG = re.compile(
    r"#\s*\[\s*cfg\s*\(\s*(?:any\s*\(\s*\)|all\s*\(\s*any\s*\(\s*\)\s*\))\s*\)\s*\]"
)
# The IMMEDIATELY-following item, allowing chained attributes,
# visibility and fn qualifiers between the cfg and the keyword. An
# always-false cfg gates exactly the next item — so we only range it
# when that item is a ``fn`` or ``mod`` (whose body is then dead). If
# the cfg gates a non-fn/mod item (``struct`` / ``const`` / ``use`` /
# ``impl`` / ``static``) we must NOT grab an unrelated ``fn`` later in
# the file — that was a false positive flagging live code as dead.
_RUST_ITEM_AFTER_CFG = re.compile(
    r"\s*(?:#\s*\[[^\]]*\]\s*)*"                       # chained attrs
    r"(?:pub\s*(?:\([^)]*\)\s*)?)?"                    # visibility
    r"(?:(?:async|unsafe|const|extern(?:\s+\"[^\"]*\")?)\s+)*"  # qualifiers
    r"(fn|mod)\b"
)


def _detect_rust(content: str) -> List[DeadRange]:
    ranges: List[DeadRange] = []
    # ``if false { … }`` blocks.
    for m in _RUST_DEAD_IF.finditer(content):
        brace_pos = m.end() - 1
        close = _match_brace(content, brace_pos)
        if close is None:
            continue
        start_line = content.count("\n", 0, m.start()) + 1
        end_line = content.count("\n", 0, close) + 1
        ranges.append((start_line, end_line))
    # ``#[cfg(any())]`` gating the immediately-following fn / mod.
    for m in _RUST_DEAD_CFG.finditer(content):
        after = content[m.end():]
        if not _RUST_ITEM_AFTER_CFG.match(after):
            # cfg gates a non-fn/mod item — do not range (avoids the
            # false positive of grabbing an unrelated later fn).
            continue
        # First ``{`` after the attribute is the gated item's body —
        # nothing between the cfg and the body uses braces (attributes
        # use ``[]``, visibility uses ``()``, generics use ``<>``).
        brace_rel = after.find("{")
        if brace_rel == -1:
            continue
        close = _match_brace(content, m.end() + brace_rel)
        if close is None:
            continue
        # Range spans from the attribute to the item's closing brace,
        # so the fn/mod ``line_start`` is captured (and, for mod, every
        # nested fn inside the dead module).
        start_line = content.count("\n", 0, m.start()) + 1
        end_line = content.count("\n", 0, close) + 1
        ranges.append((start_line, end_line))
    return ranges


# ---------------------------------------------------------------------------
# Shared — brace matcher with string / char / line-comment skipping.
# ---------------------------------------------------------------------------


def _match_brace(source: str, open_pos: int) -> "int | None":
    """Given the index of an opening ``{``, return the index of the
    matching ``}``. Skips string / template / char literals and line
    comments so braces inside them don't unbalance the count. Returns
    None on malformed input."""
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != "{":
        return None
    depth = 1
    i = open_pos + 1
    n = len(source)
    while i < n:
        c = source[i]
        if c in "\"'`":
            j = _skip_string(source, i)
            if j is None:
                return None
            i = j
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            nl = source.find("\n", i)
            if nl == -1:
                return None
            i = nl + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _skip_string(source: str, start: int) -> "int | None":
    """Advance past a string / template / char literal starting at
    ``start``. Handles backslash escapes."""
    quote = source[start]
    i = start + 1
    n = len(source)
    while i < n:
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return None


# ---------------------------------------------------------------------------
# PHP — ``if (false) {…}`` / ``if (0)`` / ``if (null)`` blocks. Same brace
# shape as JS, so the JS block-matching is reused; PHP adds ``#`` line
# comments. Conservative: only literal always-false constants (NOT
# ``if ($flag)`` — a runtime name). Mutually-recursive functions inside the
# block otherwise read CALLED, masking that the whole block is dead.
# ---------------------------------------------------------------------------


_PHP_HASH_COMMENT = re.compile(r"#[^\n]*")
_PHP_DEAD_IF = re.compile(r"\bif\s*\(\s*(?:false|0|null)\s*\)\s*\{")


def _detect_php(content: str) -> List[DeadRange]:
    # Strip /* */, // and # comments so a brace/keyword inside one doesn't
    # mislead the matcher (mirrors the JS detector + PHP's extra # comments).
    def _spaces(m: "re.Match[str]") -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    stripped = _JS_BLOCK_COMMENT.sub(_spaces, content)
    stripped = _JS_LINE_COMMENT.sub(_spaces, stripped)
    stripped = _PHP_HASH_COMMENT.sub(_spaces, stripped)
    ranges: List[DeadRange] = []
    for m in _PHP_DEAD_IF.finditer(stripped):
        close = _match_brace(stripped, m.end() - 1)
        if close is None:
            continue
        ranges.append((stripped.count("\n", 0, m.start()) + 1,
                       stripped.count("\n", 0, close) + 1))
    return ranges


# ---------------------------------------------------------------------------
# Ruby — ``if false`` / ``if nil`` / ``unless true`` / ``while false`` blocks
# (Ruby's only falsey constants are ``false`` and ``nil``). No braces, so the
# matching ``end`` is found by INDENTATION anchoring: Ruby's universal
# convention puts the closing ``end`` at the same column as the opening
# keyword. The dead branch ends at an ``else``/``elsif`` (live) or the ``end``
# at that column; if the scan dedents past the opener first (malformed /
# unconventional), we BAIL and report nothing — a false positive here would
# hard-suppress live code, so ambiguity must under-detect.
# ---------------------------------------------------------------------------


_RB_DEAD_IF = re.compile(
    r"^(\s*)(?:if\s+(?:false|nil)|unless\s+true|while\s+false|until\s+true)"
    r"\s*(?:then\b.*)?$")
_RB_BRANCH_AT = re.compile(r"^(\s*)(?:else|elsif)\b")
_RB_END_AT = re.compile(r"^(\s*)end\b")


def _detect_ruby(content: str) -> List[DeadRange]:
    lines = [re.sub(r"#.*$", "", ln) for ln in content.split("\n")]
    ranges: List[DeadRange] = []
    for i, line in enumerate(lines):
        m = _RB_DEAD_IF.match(line)
        if not m:
            continue
        ind = m.group(1)
        for j in range(i + 1, len(lines)):
            lj = lines[j]
            if not lj.strip():
                continue
            cur = lj[:len(lj) - len(lj.lstrip())]
            be = _RB_BRANCH_AT.match(lj)
            en = _RB_END_AT.match(lj)
            if (be and be.group(1) == ind) or (en and en.group(1) == ind):
                # dead branch body is lines i+1..j-1 (0-indexed) →
                # (i+2 .. j) 1-indexed.
                if i + 2 <= j:
                    ranges.append((i + 2, j))
                break
            if len(cur) < len(ind):
                break  # dedented past the opener without a match — bail (sound)
    return ranges


__all__ = ["DeadRange", "detect_dead_scopes"]
