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
only fire on unambiguously-constant guards, plus — for C/C++ — on
file-scope ``static`` functions with no caller in their translation
unit. ``if DEBUG:`` is NOT dead (DEBUG is a runtime name); ``if
False:`` IS. ``#[cfg(test)]`` is NOT dead (it compiles under the test
profile); ``#[cfg(any())]`` IS (an empty ``any()`` is the canonical
always-false cfg). False negatives are cheap (miss a deferral); false
positives are expensive (silence a real finding in live code).

Per-language detection currently handled:

  * Python: ``if <falsey-constant>:`` / ``while <falsey-constant>:``
    — the BODY only (``else`` / ``elif`` branches stay live). Falsey
    constants: ``False``, ``0``, ``0.0``, ``""``, ``None``.
  * JavaScript / TypeScript: ``if (false) {…}`` / ``if (0) {…}`` at
    any brace depth — the guarded block range.
  * C / C++: ``static`` functions whose name occurs exactly once in
    the translation unit (definition only, no callers) — provably
    dead at file scope.
  * Rust: ``if false {…}`` blocks, and ``#[cfg(any())]`` /
    ``#[cfg(all(any()))]`` attributes — the following ``fn`` block.
  * PHP: ``if (false) {…}`` / ``if (0)`` / ``if (null)`` blocks —
    the guarded block range.
  * Ruby: ``if false`` / ``if nil`` / ``unless true`` /
    ``while false`` blocks, matched by indentation-anchored ``end``.

Other languages return ``[]`` (no detector wired) — graceful
degradation; the consumer treats absence as "no dead scope found",
never as "everything is live".
"""

from __future__ import annotations

import ast
import logging
import re
from collections import Counter
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
        if language in ("c", "cpp"):
            return _detect_c(content)
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
    stripped = _js_strip_comments_and_strings(content)
    ranges: List[DeadRange] = []
    for m in _JS_DEAD_IF.finditer(stripped):
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


def _js_strip_comments_and_strings(content: str) -> str:
    """Strip comments AND string literals, preserving newlines so
    line numbers remain valid.  After this, only braces, keywords,
    and whitespace remain — the brace matcher never sees quote chars.
    """
    out = list(_js_strip_comments(content))
    i = 0
    n = len(out)
    while i < n:
        c = out[i]
        if c not in "\"'`":
            i += 1
            continue
        quote = c
        out[i] = " "
        j = i + 1
        while j < n:
            ch = out[j]
            if ch == "\\":
                out[j] = " "
                if j + 1 < n:
                    if out[j + 1] != "\n":
                        out[j + 1] = " "
                    j += 2
                else:
                    j += 1
                continue
            if quote == "`" and ch == "$" and j + 1 < n and out[j + 1] == "{":
                out[j] = " "
                out[j + 1] = " "
                j += 2
                depth = 1
                while j < n and depth > 0:
                    ic = out[j]
                    if ic == "{":
                        depth += 1
                    elif ic == "}":
                        depth -= 1
                        if depth == 0:
                            out[j] = " "
                            j += 1
                            break
                    if ic != "\n":
                        out[j] = " "
                    j += 1
                continue
            if ch == quote:
                out[j] = " "
                j += 1
                break
            if ch != "\n":
                out[j] = " "
            j += 1
        i = j
    return "".join(out)


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
        # A bodyless item (e.g. ``mod dead_mod;``) has no ``{`` before
        # its ``;`` — skip rather than latching onto the next item.
        brace_rel = after.find("{")
        semi_rel = after.find(";")
        if brace_rel == -1:
            continue
        if semi_rel != -1 and semi_rel < brace_rel:
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
# C / C++ — ``static`` functions with zero callers in the translation unit.
#
# A ``static`` function has file scope: it can only be called from
# within its translation unit. If the function name (as a whole-word
# match) appears exactly once in the file after stripping comments and
# string/char literals, the definition is the only occurrence — no
# code in the file calls it, so it is provably dead. The compiler
# would emit ``-Wunused-function`` and optimise it away.
#
# Conservative: names appearing in macros, initialiser designators,
# or sizeof expressions all count as occurrences, so we under-detect
# rather than over-detect. ``__attribute__((constructor))`` /
# ``destructor`` functions are skipped (called by the runtime, not by
# source-level call sites).
# ---------------------------------------------------------------------------


_C_NOT_FUNC_NAMES = frozenset({
    "if", "while", "for", "switch", "sizeof", "typeof", "alignof",
    "return", "goto", "case", "do",
    "void", "int", "char", "short", "long", "float", "double",
    "unsigned", "signed", "bool", "_Bool",
    "const", "volatile", "restrict", "_Atomic",
    "struct", "enum", "union", "typedef",
    "inline", "__inline", "__inline__", "__forceinline",
    "__attribute__", "__extension__", "__typeof__",
})


def _c_strip_comments_and_strings(content: str) -> str:
    """Strip C comments and string/char literals, preserving newlines."""
    out = list(content)
    i = 0
    n = len(out)
    while i < n:
        c = out[i]
        if c == "/" and i + 1 < n:
            if out[i + 1] == "/":
                while i < n and out[i] != "\n":
                    out[i] = " "
                    i += 1
                continue
            if out[i + 1] == "*":
                out[i] = " "
                out[i + 1] = " "
                i += 2
                while i < n:
                    if out[i] == "*" and i + 1 < n and out[i + 1] == "/":
                        out[i] = " "
                        out[i + 1] = " "
                        i += 2
                        break
                    if out[i] != "\n":
                        out[i] = " "
                    i += 1
                continue
        if c in "\"'":
            quote = c
            out[i] = " "
            i += 1
            while i < n:
                if out[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    if out[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if out[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if out[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


# Scan-work budget for _detect_c. A crafted file of thousands of tiny
# ``static`` definitions (or repeated never-closing headers) otherwise
# makes every candidate re-scan toward EOF — O(candidates x file-size),
# hours of CPU on a single 8 MiB input (the builder's per-file cap).
# Legitimate code consumes roughly one file-length of scanning in total
# (each body is walked once), so the factor leaves generous headroom;
# on exhaustion we return the ranges found so far (under-detection is
# the cheap, sound failure mode).
_C_SCAN_BUDGET_FACTOR = 8
# A parameter list longer than this is not a plausible function header —
# same cap idea as the extractor's _MAX_C_LINE quadratic guard.
_C_MAX_PARAM_SCAN = 16 * 1024


def _detect_c(content: str) -> List[DeadRange]:
    stripped = _c_strip_comments_and_strings(content)
    ranges: List[DeadRange] = []
    budget = _C_SCAN_BUDGET_FACTOR * len(stripped)
    # Whole-word occurrence count for every identifier, computed once —
    # a per-candidate re.findall over the full file is the other half of
    # the O(candidates x file-size) blowup. Built lazily: most files have
    # no static-function candidates at all.
    counts: "Counter[str] | None" = None

    for m in re.finditer(r"\bstatic\b", stripped):
        if budget <= 0:
            break
        paren_pos = None
        for j in range(m.end(), min(m.end() + 500, len(stripped))):
            c = stripped[j]
            if c == "(":
                paren_pos = j
                break
            if c in ";{}":
                break
        if paren_pos is None:
            continue

        between = stripped[m.end():paren_pos]
        name_match = re.search(r"\b(\w+)\s*$", between)
        if not name_match:
            continue
        name = name_match.group(1)

        if name in _C_NOT_FUNC_NAMES:
            continue
        if re.search(r"constructor|destructor", between):
            continue

        depth = 1
        j = paren_pos + 1
        param_limit = min(len(stripped), paren_pos + 1 + _C_MAX_PARAM_SCAN)
        while j < param_limit and depth > 0:
            if stripped[j] == "(":
                depth += 1
            elif stripped[j] == ")":
                depth -= 1
            j += 1
        budget -= j - paren_pos
        if depth != 0:
            continue

        brace_pos = None
        for k in range(j, min(j + 200, len(stripped))):
            if stripped[k] == "{":
                brace_pos = k
                break
            if stripped[k] == ";":
                break
        if brace_pos is None:
            continue

        close = _match_brace(stripped, brace_pos)
        # A failed match scanned to EOF; charge the worst case so a file
        # of never-closing bodies cannot force repeated full-file scans.
        budget -= (close if close is not None else len(stripped)) - brace_pos
        if close is None:
            continue

        if re.search(r"\binline\b|__inline\b|__inline__\b|__forceinline\b",
                     between):
            continue

        if counts is None:
            counts = Counter(re.findall(r"\w+", stripped))
        if counts[name] <= 1:
            start_line = stripped.count("\n", 0, m.start()) + 1
            end_line = stripped.count("\n", 0, close) + 1
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
            if c == "'" and i + 1 < n and source[i + 1].isalpha():
                if i + 2 >= n or source[i + 2] != "'":
                    i += 1
                    continue
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
        if c == "/" and i + 1 < n and source[i + 1] == "*":
            i += 2
            bc_depth = 1
            while i < n and bc_depth > 0:
                if source[i] == "/" and i + 1 < n and source[i + 1] == "*":
                    bc_depth += 1
                    i += 2
                elif source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    bc_depth -= 1
                    i += 2
                else:
                    i += 1
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


_PHP_DEAD_IF = re.compile(r"\bif\s*\(\s*(?:false|0|null)\s*\)\s*\{")


def _php_strip_comments_and_strings(content: str) -> str:
    """Strip PHP comments (``/* */``, ``//``, ``#``) AND string literals
    (``'…'`` / ``"…"`` / heredoc / nowdoc) in one pass, preserving
    newlines so line numbers stay valid.

    Single-pass matters twice over: a ``#`` or ``//`` inside a string
    (``"color: #fff"``) must not truncate the line, and an
    ``if (false) {`` inside a string literal must never reach the
    matcher — string content is untrusted target-repo text, and a match
    starting mid-string yields garbage dead ranges that hard-suppress
    real findings in live code (the expensive failure mode, per the
    module header).
    """
    out = list(content)
    i = 0
    n = len(out)
    while i < n:
        c = out[i]
        if c == "/" and i + 1 < n and out[i + 1] == "/":
            while i < n and out[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "#":
            while i < n and out[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and out[i + 1] == "*":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n:
                if out[i] == "*" and i + 1 < n and out[i + 1] == "/":
                    out[i] = " "
                    out[i + 1] = " "
                    i += 2
                    break
                if out[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        if c == "<" and content.startswith("<<<", i):
            j = _php_blank_heredoc(out, content, i)
            if j is not None:
                i = j
            else:
                i += 3
            continue
        if c in "\"'":
            quote = c
            out[i] = " "
            i += 1
            while i < n:
                if out[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    if out[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if out[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if out[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _php_blank_heredoc(
    out: "list[str]", content: str, start: int,
) -> "int | None":
    """Blank a heredoc/nowdoc starting at ``start`` (the ``<<<``).
    Returns the index just past the closing identifier, or ``None``
    when ``<<<`` isn't followed by a valid opener (caller skips it).
    Positions >= ``start`` in ``out`` are still pristine, so
    ``content`` can be used for lookahead. Unterminated heredocs blank
    to EOF — the remainder is string data, not code."""
    n = len(content)
    j = start + 3
    quote = None
    if j < n and content[j] in "\"'":
        quote = content[j]
        j += 1
    ident_start = j
    while j < n and (content[j].isalnum() or content[j] == "_"):
        j += 1
    ident = content[ident_start:j]
    if not ident or ident[0].isdigit():
        return None
    if quote is not None:
        if j >= n or content[j] != quote:
            return None
        j += 1
    eol = content.find("\n", j)
    if eol == -1 or content[j:eol].strip():
        return None
    # Body runs until a line whose first token (PHP 7.3 allows indented
    # closers) is the identifier followed by a non-identifier char.
    k = eol
    end = n
    while k < n:
        line_start = k + 1
        line_end = content.find("\n", line_start)
        if line_end == -1:
            line_end = n
        line = content[line_start:line_end]
        candidate = line.lstrip(" \t")
        if candidate.startswith(ident):
            rest = candidate[len(ident):]
            if not rest or not (rest[0].isalnum() or rest[0] == "_"):
                indent = len(line) - len(candidate)
                end = line_start + indent + len(ident)
                break
        k = line_end
    for p in range(start, end):
        if out[p] != "\n":
            out[p] = " "
    return end


def _detect_php(content: str) -> List[DeadRange]:
    # Strip comments AND string literals in a single pass (the JS
    # detector's two-phase regex approach would let a comment marker
    # inside a string eat the closing quote) so neither a keyword in a
    # comment nor an ``if (false) {`` in a string misleads the matcher.
    stripped = _php_strip_comments_and_strings(content)
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


def _strip_ruby_comment(line: str) -> str:
    """Strip ``#`` comments while respecting string literals."""
    in_str: str | None = None
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and in_str:
            i += 2
            continue
        if in_str:
            if c == in_str:
                in_str = None
        elif c in ('"', "'"):
            in_str = c
        elif c == "#":
            return line[:i]
        i += 1
    return line


def _detect_ruby(content: str) -> List[DeadRange]:
    lines = [_strip_ruby_comment(ln) for ln in content.split("\n")]
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
