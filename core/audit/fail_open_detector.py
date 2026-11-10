"""Detect fail-open-on-unknown bugs via mechanical pattern matching.

Four sub-patterns where ambiguous/unknown/error results silently
become "safe":

1. **optional_not_checked** — function returns ``Optional[T]`` but the
   caller only branches on the non-None values, letting None fall
   through to a default-safe path.  Classic: ``if X is False:`` without
   a corresponding ``if X is None:``.

2. **truncation_not_signaled** — a loop has a cap/limit and breaks
   early, but the function returns no truncation indicator.  The caller
   cannot distinguish "searched everything, found nothing" from "stopped
   searching early."

3. **error_conflated_with_empty** — an ``except`` block returns the
   same literal as a legitimate "no results" return in the same
   function (e.g. ``except Exception: return {}`` alongside a normal
   ``return {}``).

4. **truncation_consumed_unchecked** — consumer-side companion to
   pattern 2: a caller of a truncation-silent function treats the
   possibly-truncated result as authoritative (e.g. branches to a
   "safe"/"clean" outcome on an empty result) with no
   truncation-awareness check anywhere in the caller.

All detection is mechanical: regex/AST-free pattern matching on source
text, optionally enhanced by caller-side call-graph data.

Real bugs this catches:
- Bug 38:  ``codeql_trust.py`` walk-cap fail-open
- Bug 426: ``review.py:136`` — ``is False`` without ``is None``
- Bug 406/407: cache sentinel confusion (None → [])
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from core.source.lines import iter_source_lines, split_lines
from typing import Any

from .run_memo import BoundedMemo
from ._function_preparation import FunctionPreparation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

PATTERN_TYPES = frozenset({
    "optional_not_checked",
    "truncation_not_signaled",
    "truncation_consumed_unchecked",
    "error_conflated_with_empty",
})

_C_EXTS = (
    ".c", ".h", ".cc", ".cpp", ".cxx",
    ".go", ".rs",
    ".java", ".kt", ".kts",
    ".js", ".mjs", ".cjs", ".ts", ".tsx",
    ".cs", ".swift",
)


@dataclass
class FailOpenPattern:
    """A single fail-open-on-unknown finding."""

    file: str
    function: str
    line: int
    pattern_type: str
    description: str
    confidence: str  # "high", "medium", "low"

    def __post_init__(self) -> None:
        if self.pattern_type not in PATTERN_TYPES:
            msg = (
                f"Unknown pattern_type {self.pattern_type!r}; "
                f"expected one of {sorted(PATTERN_TYPES)}"
            )
            raise ValueError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "pattern_type": self.pattern_type,
            "description": self.description,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# ``if X is False:``  (identity check on bool)
_IS_FALSE_RE = re.compile(r"\bif\s+(\w+)\s+is\s+False\b")

# Companion None checks
_IS_NONE_RE = re.compile(r"\bif\s+(\w+)\s+is\s+None\b")
_IS_NOT_NONE_RE = re.compile(r"\bif\s+(\w+)\s+is\s+not\s+None\b")

# Loop-cap break: ``if count >= limit: break`` (Python),
# ``if (count >= limit) break;`` (C/C++/Java/JS),
# ``if len(results) >= limit {`` (Go) variants.
# LHS: simple var, len(var), var.length, var.size(), var.count()
_LHS = r"(?:\w+(?:\(\w+\))?(?:\.(?:length|size|count)(?:\(\))?)?)"
_RHS = r"(?:\w+|\d+)"
# ``\s*\n?\s*`` is one whitespace run (\s already matches the
# newline): the three-piece spelling stacked unbounded spans around
# the redundant \n? — quadratic on an if-line followed by a long
# whitespace run with no break/return. ``\s*`` alone is the same
# language.
_CAP_BREAK_RE = re.compile(
    # Python: if LHS >= RHS: break/return
    rf"\bif\s+{_LHS}\s*(?:>=|>|==)\s*{_RHS}\s*:\s*(?:break|return)\b"
    # C/Java/JS: if (LHS >= RHS) break;/return;
    rf"|\bif\s*\(\s*{_LHS}\s*(?:>=|>|==)\s*{_RHS}\s*\)\s*(?:break|return)\s*;"
    # C/Java/JS: if (LHS >= RHS) { break; } (with braces)
    rf"|\bif\s*\(\s*{_LHS}\s*(?:>=|>|==)\s*{_RHS}\s*\)\s*\{{\s*(?:break|return)\b"
    # Go: if LHS >= RHS { break/return
    rf"|\bif\s+{_LHS}\s*(?:>=|>|==)\s*{_RHS}\s*\{{\s*(?:break|return)\b",
    re.MULTILINE,
)

# Truncation signaling: returning a tuple, a dict with "truncated", or
# logging a truncation warning.
_TRUNCATION_SIGNAL_RE = re.compile(
    r'(?:truncat|capped|incomplete|"truncated"|"partial"'
    # Python: return results, True/False
    r"|return\s+\w+\s*,\s*(?:True|False|truncated|capped)"
    # gated optional paren — the naive \(?\s* pair was quadratic
    r"|return\s+(?:\(\s*)?\w+\s*,\s*(?:True|False)\s*\)?"
    # Go: return results, true/false
    r"|return\s+\w+\s*,\s*(?:true|false)\b"
    # JS: { results, truncated: true }
    r"|truncated\s*:\s*(?:true|false)"
    r"|isTruncated\b|is_truncated\b"
    # Logging across languages (bounded .{0,200} to avoid O(n^2) backtracking)
    r"|warnings?\.warn|(?:log(?:ger)?)\.\w+\(.{0,200}(?:truncat|cap|limit)"
    r"|console\.(?:warn|log)\(.{0,200}(?:truncat|cap|limit)"
    r"|log\.(?:Warn|Info|Printf)\(.{0,200}(?:truncat|cap|limit)"
    r"|fmt\.(?:Printf|Fprintf)\(.{0,200}(?:truncat|cap|limit))",
    re.IGNORECASE,
)

# Except clause header. One branch per header shape: with an
# exception list (``\s+\w[\w.,\s]*`` — the class already admits the
# ``as name`` tail and interior whitespace), a directly-adjoined
# ``as`` clause (``exceptas e:`` — matched by the previous spelling,
# kept for equivalence), or bare (``\s*``). The naive
# ``(?:\s+\w[\w.,\s]*)?\s*(?:as\s+\w+)?\s*:`` chained THREE
# unbounded whitespace-capable spans around optional atoms with the
# same match set: an ``except a``-opening line ending in a long
# whitespace run with no ``:`` made the engine try every split of
# the run between the spans — cubic in the line length.
_EXCEPT_HEADER_RE = re.compile(
    r"^\s*except(?:\s+\w[\w.,\s]*|as\s+\w+\s*|\s*):\s*$"
)

# Any return with a literal value
_RETURN_LITERAL_RE = re.compile(
    r"^\s*return\s+(?P<value>\{[^}]*\}|\[[^\]]*\]|None|True|False|\"\"|''|0)\s*$",
)


def _extract_functions(
    source: str, *, _preparation: FunctionPreparation | None = None,
) -> list:
    """Extract (name, start_line, body) for each top-level/method def."""
    from ._util import extract_functions_from_source
    if _preparation is None:
        return extract_functions_from_source(source)
    return _preparation.get(
        source, extract_functions_from_source, _preparation_consumers_native,
    )


# ---------------------------------------------------------------------------
# Sub-detector: optional_not_checked
# ---------------------------------------------------------------------------

def _detect_optional_not_checked(
    file_path: str,
    source: str,
    *,
    _preparation: FunctionPreparation | None = None,
) -> list[FailOpenPattern]:
    """Find ``if X is False:`` without a corresponding ``is None`` guard."""
    results: list[FailOpenPattern] = []

    for name, start_line, body in _function_rows(source, _preparation):
        is_false_matches = list(_IS_FALSE_RE.finditer(body))
        if not is_false_matches:
            continue

        # Collect all variable names checked with ``is None``
        none_checked_vars = {
            m.group(1) for m in _IS_NONE_RE.finditer(body)
        } | {
            m.group(1) for m in _IS_NOT_NONE_RE.finditer(body)
        }

        native_body = type(body) is str
        match_line = start_line
        line_offset = 0
        for m in is_false_matches:
            var_name = m.group(1)
            if var_name in none_checked_vars:
                continue

            # Check for a broad ``if not var:`` that would catch None too
            broad_check = re.search(
                rf"\bif\s+not\s+{re.escape(var_name)}\b", body
            )
            if broad_check:
                continue

            if native_body:
                offset = m.start()
                match_line += body.count("\n", line_offset, offset)
                line_offset = offset
            else:
                match_line = start_line + body.count("\n", 0, m.start())
            results.append(FailOpenPattern(
                file=file_path,
                function=name,
                line=match_line,
                pattern_type="optional_not_checked",
                description=(
                    f"Variable '{var_name}' checked with "
                    f"'is False' but never with 'is None'; "
                    f"a None value (unknown/error) falls through "
                    f"to the default path"
                ),
                confidence="high",
            ))

    return results


# ---------------------------------------------------------------------------
# Sub-detector: truncation_not_signaled
# ---------------------------------------------------------------------------

# Bounded iteration/window counts on every newline-crossing span.
# The qualifier/type loops and the params class cross newlines BY
# DESIGN (multi-line declarations and parameter lists must keep
# matching), but the unbounded spelling was quadratic two ways: the
# keyword loop and the type loop overlap on every word (keywords ARE
# \w+), so a run of qualifier words with no paren made the engine
# try every split of the run between the loops; and every MULTILINE
# ``^`` restart re-scanned the remaining text through the loops
# (4x per input doubling measured at 14-56KB). Bound trade-off, both
# directions: larger keeps pathological declarations matching but
# raises the per-anchor re-scan ceiling; smaller is faster but a
# real declaration beyond the bound stops matching. 16 words per
# loop / 400-char receiver / 4096-char params sit far above real
# code while capping per-anchor work at a constant.
_C_FUNC_RE = re.compile(
    r"^[ \t]*(?:(?:static|inline|void|int|char|unsigned|const|auto|"
    r"public|private|protected|func|function|export|async|fn|"
    r"override|virtual|abstract|final|synchronized)\s+){0,16}"
    r"(?:\([^)]{0,400}\)\s+)?"     # Go method receiver
    r"(?:\w+[*&]*\s+){0,16}"       # return type(s) with pointer/ref
    r"(\w+)\s*\([^)]{0,4096}\)\s*\{",
    re.MULTILINE,
)


def _extract_c_functions(source: str, file_path: str = "file.c") -> list[tuple[str, int, str]]:
    """C function extraction — tree-sitter with regex fallback."""
    try:
        from .ts_extract import _iter_functions, _parse_file
        parsed = _parse_file(file_path, source)
        if parsed is not None:
            tree, lang, src_bytes = parsed
            funcs: list[tuple[str, int, str]] = []
            for func_node, name, body in _iter_functions(tree, lang, src_bytes, file_path):
                func_text = src_bytes[func_node.start_byte:func_node.end_byte].decode(
                    "utf-8", errors="replace"
                )
                start_line = func_node.start_point[0] + 1
                funcs.append((name, start_line, func_text))
            return funcs
    except ImportError:
        pass

    funcs = []
    native_source = type(source) is str
    start_line = 1
    line_offset = 0
    for m in _C_FUNC_RE.finditer(source):
        name = m.group(1)
        if native_source:
            offset = m.start()
            start_line += source.count("\n", line_offset, offset)
            line_offset = offset
        else:
            start_line = source.count("\n", 0, m.start()) + 1
        brace_start = source.index("{", m.start())
        depth = 1
        i = brace_start + 1
        while i < len(source) and depth > 0:
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
            i += 1
        body = source[m.start():i]
        funcs.append((name, start_line, body))
    return funcs


def _detect_truncation_via_ts(
    file_path: str,
    source: str,
) -> list[FailOpenPattern] | None:
    """Tree-sitter loop-cap detection for non-Python files.

    Returns None if tree-sitter is unavailable (caller falls back to regex).
    """
    try:
        from .ts_extract import extract_function_body, extract_loop_caps
    except ImportError:
        return None

    caps = extract_loop_caps(file_path, source)
    if caps is None:
        return None

    results: list[FailOpenPattern] = []
    for cap in caps:
        func_body = extract_function_body(file_path, source, cap.function)
        if func_body is None:
            continue
        if not func_body:
            continue
        if not re.search(r"^[^\S\n]*return\b", func_body, re.MULTILINE):
            continue
        if _TRUNCATION_SIGNAL_RE.search(func_body):
            continue

        results.append(FailOpenPattern(
            file=file_path,
            function=cap.function,
            line=cap.line,
            pattern_type="truncation_not_signaled",
            description=(
                f"Loop in '{cap.function}' breaks at a cap/limit but "
                f"the function does not signal truncation to the "
                f"caller; 'searched everything' is indistinguishable "
                f"from 'stopped early'"
            ),
            confidence="medium",
        ))

    return results


def _detect_truncation_not_signaled(
    file_path: str,
    source: str,
    *,
    _preparation: FunctionPreparation | None = None,
) -> list[FailOpenPattern]:
    """Find functions with a loop-cap break that don't signal truncation."""
    # Non-Python: try tree-sitter first (better structural detection)
    if not file_path.endswith(".py"):
        ts_results = _detect_truncation_via_ts(file_path, source)
        if ts_results is not None:
            return ts_results

    results: list[FailOpenPattern] = []

    funcs = _function_rows(source, _preparation)
    if not funcs and any(file_path.endswith(ext) for ext in _C_EXTS):
        funcs = _extract_c_functions(source, file_path)

    for name, start_line, body in funcs:
        cap_matches = list(_CAP_BREAK_RE.finditer(body))
        if not cap_matches:
            continue

        # Must have a return statement (to be a function returning results)
        if not re.search(r"^[^\S\n]*return\b", body, re.MULTILINE):
            continue

        # Check whether truncation is signaled anywhere in the body
        if _TRUNCATION_SIGNAL_RE.search(body):
            continue

        # Use the line of the first cap-break as the finding location
        first_cap = cap_matches[0]
        match_line = start_line + body.count("\n", 0, first_cap.start())

        results.append(FailOpenPattern(
            file=file_path,
            function=name,
            line=match_line,
            pattern_type="truncation_not_signaled",
            description=(
                f"Loop in '{name}' breaks at a cap/limit but "
                f"the function does not signal truncation to the "
                f"caller; 'searched everything' is indistinguishable "
                f"from 'stopped early'"
            ),
            confidence="medium",
        ))

    return results


# ---------------------------------------------------------------------------
# Sub-detector: error_conflated_with_empty
# ---------------------------------------------------------------------------

def _normalise_literal(val: str) -> str:
    """Normalise a return-value literal for comparison."""
    v = val.strip()
    # Collapse whitespace inside braces/brackets
    v = re.sub(r"\s+", "", v)
    # Treat '' and "" as equivalent
    if v in ('""', "''"):
        return '""'
    return v


_LITERAL_NORMALIZE_IMPL = _normalise_literal
_LITERAL_RETURN_IMPL = _RETURN_LITERAL_RE
_LITERAL_EXCEPT_IMPL = _EXCEPT_HEADER_RE
_LITERAL_SUB_IMPL = re.sub


def _detect_error_conflated_with_empty(
    file_path: str,
    source: str,
    *,
    _preparation: FunctionPreparation | None = None,
) -> list[FailOpenPattern]:
    """Find except blocks that return the same literal as a success path."""
    results: list[FailOpenPattern] = []

    for name, start_line, body in _function_rows(source, _preparation):
        lines = body.split("\n")  # line-model: callers deliver \n-model text (universal-newline reads / split_lines span joins)

        native_body = type(body) is str
        native_values = (native_body and _normalise_literal is _LITERAL_NORMALIZE_IMPL
                         and _RETURN_LITERAL_RE is _LITERAL_RETURN_IMPL
                         and _EXCEPT_HEADER_RE is _LITERAL_EXCEPT_IMPL
                         and re.sub is _LITERAL_SUB_IMPL)
        # Pass 1: identify which line-indices are inside an except block.
        # An except block starts at an ``except ...:`` header and ends
        # when indentation returns to the same level or lower.
        except_line_indices: set[int] = set()
        i = 0
        while i < len(lines):
            if _EXCEPT_HEADER_RE.match(lines[i]):
                header_indent = len(lines[i]) - len(lines[i].lstrip())
                j = i + 1
                while j < len(lines):
                    stripped = lines[j].lstrip()
                    if stripped and not stripped.startswith("#"):
                        line_indent = len(lines[j]) - len(stripped if native_body else lines[j].lstrip())
                        if line_indent <= header_indent:
                            break
                    except_line_indices.add(j)
                    j += 1
                i = j
            else:
                i += 1

        # Pass 2: collect return literals, split by except vs. non-except.
        except_returns: list[tuple[str, int]] = []  # (normalised_val, line_idx)
        success_returns: dict[str, list[int]] = {}   # adapter path retains original operations
        success_values: set[str] = set()  # only membership is consumed below

        for idx, line in enumerate(lines):
            m = _RETURN_LITERAL_RE.match(line)
            if not m:
                continue
            val = _normalise_literal(m.group("value"))
            if idx in except_line_indices:
                except_returns.append((val, idx))
            elif native_values:
                success_values.add(val)
            else:
                success_returns.setdefault(val, []).append(idx)

        # Pass 3: flag except-returns whose literal also appears on a
        # success path.
        for exc_val, exc_idx in except_returns:
            if exc_val not in (success_values if native_values else success_returns):
                continue

            match_line = start_line + exc_idx

            results.append(FailOpenPattern(
                file=file_path,
                function=name,
                line=match_line,
                pattern_type="error_conflated_with_empty",
                description=(
                    f"Except block in '{name}' returns {exc_val!r} "
                    f"which is the same value as a non-error return; "
                    f"callers cannot distinguish 'fetch failed' from "
                    f"'no results'"
                ),
                confidence="high",
            ))

    return results


# ---------------------------------------------------------------------------
# Sub-detector: truncation_consumed_unchecked (consumer-side)
# ---------------------------------------------------------------------------

# Patterns indicating truncation awareness in a caller
# The len() argument window is bounded: unbounded, source that
# repeats ``len(`` makes every occurrence re-scan the rest of the
# text for the missing ``)`` — quadratic on hostile source. A real
# len() argument sits far inside 400 chars (trade-off: a longer
# argument stops matching, versus an unbounded scan).
_TRUNCATION_AWARE_RE = re.compile(
    r"truncat|\.is_complete|\.is_truncated|total\s*[><=!]+\s*len\("
    r"|len\([^)]{0,400}\)\s*[<>=!]+\s*total"
    r"|partial|incomplete",
    re.IGNORECASE,
)

# Patterns indicating the caller treats an empty result as "safe"
_EMPTY_AS_SAFE_RE = re.compile(
    r"""(?:if\s+not\s+\w+\s*:|"""
    r"""if\s+len\(\w+\)\s*==\s*0\s*:|"""
    r"""if\s+\w+\s*==\s*\[\]\s*:|"""
    r"""if\s+not\s+len\(\w+\)\s*:)""",
)

# Patterns indicating a security decision based on result emptiness
_SAFE_RETURN_AFTER_EMPTY_RE = re.compile(
    r"""(?:return\s+(?:"safe"|"clean"|True|"ok"|"pass"|\[\])|"""
    r"""(?:status|result|verdict)\s*=\s*(?:"safe"|"clean"|"ok"|"pass"))""",
    re.IGNORECASE,
)


def _detect_consumer_fail_open(
    source_text: dict[str, str],
    call_graphs: dict[str, Any],
    truncation_silent: list[FailOpenPattern],
) -> list[FailOpenPattern]:
    """Find callers of truncation-silent functions that treat results as authoritative."""
    results: list[FailOpenPattern] = []

    silent_funcs: set = {fop.function for fop in truncation_silent}
    if not silent_funcs:
        return results

    silent_by_file: dict[str, set] = {}
    for fop in truncation_silent:
        silent_by_file.setdefault(fop.file, set()).add(fop.function)

    for caller_file, cg in call_graphs.items():
        source = source_text.get(caller_file, "")
        if not source:
            continue

        calls = getattr(cg, "calls", None) or (
            cg.get("calls", []) if isinstance(cg, dict) else []
        )
        starts: BoundedMemo[int] | None = (
            BoundedMemo(256)
            if (type(source) is str and len(source) >= 4096
                and (type(calls) is list or type(calls) is tuple) and len(calls) > 1)
            else None
        )
        for call_info in calls:
            caller_name = (
                getattr(call_info, "caller", None)
                or (call_info.get("caller") if isinstance(call_info, dict) else None)
                or ""
            )
            chain = (
                getattr(call_info, "chain", None)
                or (call_info.get("chain") if isinstance(call_info, dict) else None)
                or []
            )
            if not chain:
                continue

            callee_name = chain[-1] if chain else ""
            if callee_name not in silent_funcs:
                continue

            caller_body = _extract_caller_body(source, caller_name, caller_file)
            if not caller_body:
                continue

            if _TRUNCATION_AWARE_RE.search(caller_body):
                continue

            empty_check = _EMPTY_AS_SAFE_RE.search(caller_body)
            safe_return = _SAFE_RETURN_AFTER_EMPTY_RE.search(caller_body)

            if not (empty_check or safe_return):
                continue

            confidence = "high" if caller_file in silent_by_file else "medium"

            line = 0
            if (starts is not None and _function_start_line is _START_LINE_IMPL
                    and split_lines is _START_LINES_IMPL
                    and re.search is _START_SEARCH_IMPL and re.escape is _START_ESCAPE_IMPL
                    and type(caller_name) is str and len(caller_name) <= 512):
                start_line, _ = starts.get_or_compute(
                    caller_name, lambda: _function_start_line(source, caller_name),
                )
            else:
                start_line = _function_start_line(source, caller_name)
            if empty_check:
                line = start_line + caller_body.count("\n", 0, empty_check.start())

            results.append(FailOpenPattern(
                file=caller_file,
                function=caller_name,
                line=line,
                pattern_type="truncation_consumed_unchecked",
                description=(
                    f"'{caller_name}' calls truncation-silent "
                    f"'{callee_name}' and treats the result as "
                    f"authoritative; an attacker can pad input to "
                    f"fill the cap, hiding malicious entries in "
                    f"the uninspected tail"
                ),
                confidence=confidence,
            ))

    return results


def _function_start_line(source: str, func_name: str) -> int:
    """Return the 1-based line number of a function definition in source."""
    lines = (iter_source_lines(source)
             if type(source) is str and split_lines is _START_LINES_IMPL else split_lines(source))
    native_match = (type(source) is str and type(func_name) is str
                    and split_lines is _START_LINES_IMPL and iter_source_lines is _START_ITER_IMPL)
    pattern = None
    for i, line in enumerate(lines, 1):
        if (native_match and re is _START_RE_MODULE
                and re.search is _START_SEARCH_IMPL and re.escape is _START_ESCAPE_IMPL
                and re.compile is _START_COMPILE_IMPL):
            if pattern is None:
                pattern = re.compile(rf"\b{re.escape(func_name)}\s*\(")
            if pattern.search(line):
                return i
        elif re.search(rf"\b{re.escape(func_name)}\s*\(", line):
            return i
    return 1


_START_LINE_IMPL = _function_start_line
_START_LINES_IMPL = split_lines
_START_SEARCH_IMPL = re.search
_START_ESCAPE_IMPL = re.escape
_START_RE_MODULE = re
_START_COMPILE_IMPL = re.compile
_START_ITER_IMPL = iter_source_lines


def _extract_caller_body(
    source: str, func_name: str, file_path: str = "file.py",
) -> str:
    """Extract the body of a named function — tree-sitter with regex fallback."""
    try:
        from .ts_extract import extract_function_body
        body = extract_function_body(file_path, source, func_name)
        if body is not None:
            return body
    except ImportError:
        pass

    return _extract_function_body_regex(source, func_name)


def _extract_function_body_regex(source: str, func_name: str) -> str:
    """Multi-language regex function-body extraction."""
    lines = source.splitlines()
    start = None
    indent = 0
    uses_braces = False

    for i, line in enumerate(lines):
        # Python: def / async def
        fm = re.match(r"(\s*)(?:async\s+)?def\s+(\w+)\s*\(", line)
        if fm and fm.group(2) == func_name:
            start = i
            indent = len(fm.group(1))
            uses_braces = False
            continue

        # C/Go/Java/JS/Rust: function header with opening brace
        fm = re.match(
            r"(\s*)(?:(?:static|inline|void|int|char|unsigned|const|auto|"
            r"func|function|export|async|public|private|protected|fn|"
            r"override|virtual|abstract|final|synchronized)\s+)*"
            r"(?:\([^)]*\)\s+)?"
            r"(?:\w+[*&]*\s+)*"
            r"(\w+)\s*\([^)]*\)\s*(?:[^{]*)\{",
            line,
        )
        if fm and fm.group(2) == func_name:
            start = i
            indent = len(fm.group(1))
            uses_braces = True
            continue

        if start is not None and i > start:
            if uses_braces:
                # Brace-counting: find the closing brace at the same indent
                depth = 0
                for j in range(start, len(lines)):
                    for ch in lines[j]:
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                    if depth <= 0 and j > start:
                        return "\n".join(lines[start:j + 1])
                return "\n".join(lines[start:])
            # Python: indentation-based
            stripped = line.lstrip()
            if stripped and not stripped.startswith("#"):
                line_indent = len(line) - len(stripped)
                if line_indent <= indent:
                    return "\n".join(lines[start:i])

    if start is not None:
        return "\n".join(lines[start:])
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_PREP_TYPE = 0 .__class__.__class__
_PREP_STR = ''.__class__
_PREP_BASE_EXCEPTION = BaseException
_PREP_EXCEPTION = Exception
_PREP_ISINSTANCE = isinstance

def _PREP_LEN(value: Any) -> int:
    return value.__len__()
_PREP_FUNCTION_TYPE = type(_extract_functions)
_PREP_MODULE_TYPE = type(re)
_PREP_PATTERN_TYPE = re.Pattern
_PREP_ZERO_FLAG = re.__dict__.get('_zero_sentinel')
_PREP_ZERO_CLASS = _PREP_TYPE(_PREP_ZERO_FLAG)
_PREP_ZERO_STATE = tuple(_PREP_ZERO_CLASS.__dict__.items())
_PREP_GLOBALS = globals()
_PREP_BUILTINS: dict[str, Any] = _PREP_GLOBALS['_extract_functions'].__builtins__
_PREP_BUILTIN_STATE = tuple(((name, _PREP_GLOBALS.get(name, _PREP_BUILTINS.get(name))) for name in ('type', 'str', 'len', 'list', 'tuple', 'dict', 'set', 'enumerate', 'range', 'any')))
_PREP_FUNCTION_STATE: dict[str, tuple[Any, Any]] = {name: (_PREP_GLOBALS[name], _PREP_GLOBALS[name].__code__) for name in ('_extract_functions', '_normalise_literal', '_detect_optional_not_checked', '_detect_truncation_not_signaled', '_detect_error_conflated_with_empty')}
_PREP_BINDING_STATE = tuple(((name, _PREP_GLOBALS[name]) for name in ('_IS_FALSE_RE', '_IS_NONE_RE', '_IS_NOT_NONE_RE', '_CAP_BREAK_RE', '_TRUNCATION_SIGNAL_RE', '_RETURN_LITERAL_RE', '_EXCEPT_HEADER_RE', '_LITERAL_NORMALIZE_IMPL', '_LITERAL_RETURN_IMPL', '_LITERAL_EXCEPT_IMPL', '_LITERAL_SUB_IMPL', 'PATTERN_TYPES')))
_PREP_CLASS = FailOpenPattern
_PREP_CLASS_STATE = tuple(((name, value, value.__code__ if _PREP_TYPE(value) is _PREP_FUNCTION_TYPE else None) for name, value in FailOpenPattern.__dict__.items()))
_PREP_RE_MODULE = re
_PREP_RE_STATE: tuple[tuple[str, Any, Any], ...] = tuple(((name, re.__dict__[name], re.__dict__[name].__code__) for name in ('search', 'sub', '_compile')))

def _preparation_consumers_native() -> bool:
    for name, (function, code) in _PREP_FUNCTION_STATE.items():
        if function is None:
            return False
        if function.__code__ is not code or _PREP_GLOBALS.get(name) is not function:
            return False
    for name, value in _PREP_BINDING_STATE:
        if _PREP_GLOBALS.get(name) is not value:
            return False
    for name, value in _PREP_BUILTIN_STATE:
        if _PREP_GLOBALS.get(name, _PREP_BUILTINS.get(name)) is not value:
            return False
    if FailOpenPattern is not _PREP_CLASS:
        return False
    attrs = _PREP_CLASS.__dict__
    if _PREP_LEN(attrs) != _PREP_LEN(_PREP_CLASS_STATE):
        return False
    for name, value, code in _PREP_CLASS_STATE:
        if attrs.get(name) is not value:
            return False
        if code is not None and (value is None or value.__code__ is not code):
            return False
    if re is not _PREP_RE_MODULE or _PREP_TYPE(re) is not _PREP_MODULE_TYPE:
        return False
    for name, value, code in _PREP_RE_STATE:
        if value is None:
            return False
        if value.__code__ is not code or re.__dict__.get(name) is not value:
            return False
    if re.__dict__.get('_zero_sentinel') is not _PREP_ZERO_FLAG:
        return False
    zero_attrs = _PREP_ZERO_CLASS.__dict__
    if _PREP_LEN(zero_attrs) != _PREP_LEN(_PREP_ZERO_STATE):
        return False
    for name, value in _PREP_ZERO_STATE:
        if zero_attrs.get(name) is not value:
            return False
    for name, maximum in (('_cache', 512), ('_cache2', 256)):
        cache: Any = re.__dict__.get(name)
        if _PREP_TYPE(cache) is not dict or _PREP_LEN(cache) > maximum:
            return False
        for key, value in cache.items():
            if _PREP_TYPE(key) is not tuple or _PREP_LEN(key) != 3 or (not (key[0] is str or key[0] is bytes)) or (_PREP_TYPE(key[1]) is not key[0]) or (_PREP_TYPE(key[2]) is not int and (_PREP_ZERO_FLAG is None or key[2] is not _PREP_ZERO_FLAG)) or (_PREP_TYPE(value) is not _PREP_PATTERN_TYPE):
                return False
    return True

def _function_rows(source: str, preparation: FunctionPreparation | None) -> list:
    function, code = _PREP_FUNCTION_STATE['_extract_functions']
    if preparation is None or _extract_functions is not function or function.__code__ is not code:
        return _extract_functions(source)
    return _extract_functions(source, _preparation=preparation)

def _call_with_preparation(name: str, current: Any, path: str, source: str, preparation: FunctionPreparation | None) -> list[FailOpenPattern]:
    original, code = _PREP_FUNCTION_STATE[name]
    if preparation is not None and current is original and (current.__code__ is code):
        return current(path, source, _preparation=preparation)
    return current(path, source)


def detect_fail_open_patterns(
    source_text: dict[str, str],
    call_graphs: dict | None = None,
) -> list[FailOpenPattern]:
    """Run all fail-open sub-detectors across a set of source files.

    Parameters
    ----------
    source_text:
        Mapping of ``{file_path: source_code}``.
    call_graphs:
        Optional call-graph data.  When provided, enables consumer-
        side truncation checking: callers of truncation-silent
        functions are checked for authoritative consumption.

    Returns
    -------
    List of :class:`FailOpenPattern` findings, sorted by
    (file, line).
    """
    results: list[FailOpenPattern] = []

    for file_path, source in source_text.items():
        if file_path.endswith(".py"):
            _preparation = None
            if _PREP_TYPE(file_path) is _PREP_STR and _PREP_TYPE(source) is _PREP_STR and (_PREP_LEN(source) >= 4096):
                try:
                    _preparation = FunctionPreparation()
                except _PREP_EXCEPTION:
                    pass
            _preparation_failed = False
            try:
                results.extend(_call_with_preparation('_detect_optional_not_checked', _detect_optional_not_checked, file_path, source, _preparation))
                results.extend(_call_with_preparation('_detect_truncation_not_signaled', _detect_truncation_not_signaled, file_path, source, _preparation))
                results.extend(_call_with_preparation('_detect_error_conflated_with_empty', _detect_error_conflated_with_empty, file_path, source, _preparation))
            except _PREP_BASE_EXCEPTION:
                _preparation_failed = True
                raise
            finally:
                if _preparation is not None:
                    try:
                        _preparation.release()
                    except _PREP_BASE_EXCEPTION as cleanup:
                        if not _preparation_failed and (not _PREP_ISINSTANCE(cleanup, _PREP_EXCEPTION)):
                            raise
        elif any(file_path.endswith(e) for e in _C_EXTS):
            results.extend(_detect_truncation_not_signaled(file_path, source))

    # Consumer-side: check callers of truncation-silent functions
    truncation_silent = [
        r for r in results if r.pattern_type == "truncation_not_signaled"
    ]
    if call_graphs and truncation_silent:
        results.extend(
            _detect_consumer_fail_open(source_text, call_graphs, truncation_silent)
        )

    results.sort(key=lambda p: (p.file, p.line))
    return results
