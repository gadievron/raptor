"""Detect fail-open-on-unknown bugs via mechanical pattern matching.

Three sub-patterns where ambiguous/unknown/error results silently
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
from typing import Any, Dict, List, Optional, Tuple

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
    ".java", ".kt",
    ".js", ".mjs", ".cjs", ".ts", ".tsx",
    ".cs",
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
            raise ValueError(
                f"Unknown pattern_type {self.pattern_type!r}; "
                f"expected one of {sorted(PATTERN_TYPES)}"
            )

    def to_dict(self) -> Dict[str, Any]:
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

# ``if X is False:`` / ``if X is True:``  (identity checks on bool)
_IS_FALSE_RE = re.compile(r"\bif\s+(\w+)\s+is\s+False\b")
_IS_TRUE_RE = re.compile(r"\bif\s+(\w+)\s+is\s+True\b")

# Companion None checks
_IS_NONE_RE = re.compile(r"\bif\s+(\w+)\s+is\s+None\b")
_IS_NOT_NONE_RE = re.compile(r"\bif\s+(\w+)\s+is\s+not\s+None\b")

# Loop-cap break: ``if count >= limit: break`` (Python),
# ``if (count >= limit) break;`` (C/C++/Java/JS),
# ``if len(results) >= limit {`` (Go) variants.
# LHS: simple var, len(var), var.length, var.size(), var.count()
_LHS = r"(?:\w+(?:\(\w+\))?(?:\.(?:length|size|count)(?:\(\))?)?)"
_RHS = r"(?:\w+|\d+)"
_CAP_BREAK_RE = re.compile(
    # Python: if LHS >= RHS: break/return
    rf"\bif\s+{_LHS}\s*(?:>=|>|==)\s*{_RHS}\s*:\s*\n?\s*(?:break|return)\b"
    # C/Java/JS: if (LHS >= RHS) break;/return;
    rf"|\bif\s*\(\s*{_LHS}\s*(?:>=|>|==)\s*{_RHS}\s*\)\s*\n?\s*(?:break|return)\s*;"
    # C/Java/JS: if (LHS >= RHS) { break; } (with braces)
    rf"|\bif\s*\(\s*{_LHS}\s*(?:>=|>|==)\s*{_RHS}\s*\)\s*\{{\s*\n?\s*(?:break|return)\b"
    # Go: if LHS >= RHS { break/return
    rf"|\bif\s+{_LHS}\s*(?:>=|>|==)\s*{_RHS}\s*\{{\s*\n?\s*(?:break|return)\b",
    re.MULTILINE,
)

# Collection returns
_RETURN_COLLECTION_RE = re.compile(
    r"^\s*return\s+\w+\s*$", re.MULTILINE
)

# Truncation signaling: returning a tuple, a dict with "truncated", or
# logging a truncation warning.
_TRUNCATION_SIGNAL_RE = re.compile(
    r'(?:truncat|capped|incomplete|"truncated"|"partial"'
    # Python: return results, True/False
    r"|return\s+\w+\s*,\s*(?:True|False|truncated|capped)"
    r"|return\s+\(?\s*\w+\s*,\s*(?:True|False)\s*\)?"
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

# Except clause header
_EXCEPT_HEADER_RE = re.compile(
    r"^\s*except(?:\s+\w[\w.,\s]*)?\s*(?:as\s+\w+)?\s*:\s*$"
)

# Any return with a literal value
_RETURN_LITERAL_RE = re.compile(
    r"^\s*return\s+(?P<value>\{[^}]*\}|\[[^\]]*\]|None|True|False|\"\"|''|0)\s*$",
)


def _extract_functions(source: str) -> List[Tuple[str, int, str]]:
    """Extract (name, start_line, body) for each top-level/method def."""
    from ._util import extract_functions_from_source
    return extract_functions_from_source(source)


def _line_number_of(source: str, match_start: int) -> int:
    """1-based line number for a character offset."""
    return source[:match_start].count("\n") + 1


# ---------------------------------------------------------------------------
# Sub-detector: optional_not_checked
# ---------------------------------------------------------------------------

def _detect_optional_not_checked(
    file_path: str,
    source: str,
) -> List[FailOpenPattern]:
    """Find ``if X is False:`` without a corresponding ``is None`` guard."""
    results: List[FailOpenPattern] = []

    for name, start_line, body in _extract_functions(source):
        is_false_matches = list(_IS_FALSE_RE.finditer(body))
        if not is_false_matches:
            continue

        # Collect all variable names checked with ``is None``
        none_checked_vars = {
            m.group(1) for m in _IS_NONE_RE.finditer(body)
        } | {
            m.group(1) for m in _IS_NOT_NONE_RE.finditer(body)
        }

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

            match_line = start_line + body[:m.start()].count("\n")
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

_C_FUNC_RE = re.compile(
    r"^[ \t]*(?:(?:static|inline|void|int|char|unsigned|const|auto|"
    r"public|private|protected|func|function|export|async|fn|"
    r"override|virtual|abstract|final|synchronized)\s+)*"
    r"(?:\([^)]*\)\s+)?"      # Go method receiver
    r"(?:\w+[*&]*\s+)*"       # return type(s) with pointer/ref
    r"(\w+)\s*\([^)]*\)\s*\{",
    re.MULTILINE,
)


def _extract_c_functions(source: str, file_path: str = "file.c") -> List[Tuple[str, int, str]]:
    """C function extraction — tree-sitter with regex fallback."""
    try:
        from .ts_extract import _parse_file, _iter_functions
        parsed = _parse_file(file_path, source)
        if parsed is not None:
            tree, lang, src_bytes = parsed
            funcs: List[Tuple[str, int, str]] = []
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
    for m in _C_FUNC_RE.finditer(source):
        name = m.group(1)
        start_line = source[:m.start()].count("\n") + 1
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
) -> Optional[List[FailOpenPattern]]:
    """Tree-sitter loop-cap detection for non-Python files.

    Returns None if tree-sitter is unavailable (caller falls back to regex).
    """
    try:
        from .ts_extract import extract_loop_caps, extract_function_body
    except ImportError:
        return None

    caps = extract_loop_caps(file_path, source)
    if caps is None:
        return None

    results: List[FailOpenPattern] = []
    for cap in caps:
        func_body = extract_function_body(file_path, source, cap.function)
        if func_body is None:
            continue
        if not func_body:
            continue
        if not re.search(r"^\s*return\b", func_body, re.MULTILINE):
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
) -> List[FailOpenPattern]:
    """Find functions with a loop-cap break that don't signal truncation."""
    # Non-Python: try tree-sitter first (better structural detection)
    if not file_path.endswith(".py"):
        ts_results = _detect_truncation_via_ts(file_path, source)
        if ts_results is not None:
            return ts_results

    results: List[FailOpenPattern] = []

    funcs = _extract_functions(source)
    if not funcs and any(file_path.endswith(ext) for ext in _C_EXTS):
        funcs = _extract_c_functions(source, file_path)

    for name, start_line, body in funcs:
        cap_matches = list(_CAP_BREAK_RE.finditer(body))
        if not cap_matches:
            continue

        # Must have a return statement (to be a function returning results)
        if not re.search(r"^\s*return\b", body, re.MULTILINE):
            continue

        # Check whether truncation is signaled anywhere in the body
        if _TRUNCATION_SIGNAL_RE.search(body):
            continue

        # Use the line of the first cap-break as the finding location
        first_cap = cap_matches[0]
        match_line = start_line + body[:first_cap.start()].count("\n")

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


def _detect_error_conflated_with_empty(
    file_path: str,
    source: str,
) -> List[FailOpenPattern]:
    """Find except blocks that return the same literal as a success path."""
    results: List[FailOpenPattern] = []

    for name, start_line, body in _extract_functions(source):
        lines = body.split("\n")

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
                        line_indent = len(lines[j]) - len(lines[j].lstrip())
                        if line_indent <= header_indent:
                            break
                    except_line_indices.add(j)
                    j += 1
                i = j
            else:
                i += 1

        # Pass 2: collect return literals, split by except vs. non-except.
        except_returns: List[Tuple[str, int]] = []  # (normalised_val, line_idx)
        success_returns: Dict[str, List[int]] = {}   # val -> [line_idx, ...]

        for idx, line in enumerate(lines):
            m = _RETURN_LITERAL_RE.match(line)
            if not m:
                continue
            val = _normalise_literal(m.group("value"))
            if idx in except_line_indices:
                except_returns.append((val, idx))
            else:
                success_returns.setdefault(val, []).append(idx)

        # Pass 3: flag except-returns whose literal also appears on a
        # success path.
        for exc_val, exc_idx in except_returns:
            if exc_val not in success_returns:
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
_TRUNCATION_AWARE_RE = re.compile(
    r"truncat|\.is_complete|\.is_truncated|total\s*[><=!]+\s*len\("
    r"|len\([^)]*\)\s*[<>=!]+\s*total"
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
    source_text: Dict[str, str],
    call_graphs: Dict[str, Any],
    truncation_silent: List[FailOpenPattern],
) -> List[FailOpenPattern]:
    """Find callers of truncation-silent functions that treat results as authoritative."""
    results: List[FailOpenPattern] = []

    silent_funcs: set = {fop.function for fop in truncation_silent}
    if not silent_funcs:
        return results

    silent_by_file: Dict[str, set] = {}
    for fop in truncation_silent:
        silent_by_file.setdefault(fop.file, set()).add(fop.function)

    for caller_file, cg in call_graphs.items():
        source = source_text.get(caller_file, "")
        if not source:
            continue

        calls = getattr(cg, "calls", None) or (
            cg.get("calls", []) if isinstance(cg, dict) else []
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
            start_line = _function_start_line(source, caller_name)
            if empty_check:
                line = start_line + caller_body[:empty_check.start()].count("\n")

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
    for i, line in enumerate(source.splitlines(), 1):
        if re.search(rf"\b{re.escape(func_name)}\s*\(", line):
            return i
    return 1


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
            else:
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

def detect_fail_open_patterns(
    source_text: Dict[str, str],
    call_graphs: Optional[dict] = None,
) -> List[FailOpenPattern]:
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
    results: List[FailOpenPattern] = []

    for file_path, source in source_text.items():
        if file_path.endswith(".py"):
            results.extend(_detect_optional_not_checked(file_path, source))
            results.extend(_detect_truncation_not_signaled(file_path, source))
            results.extend(_detect_error_conflated_with_empty(file_path, source))
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
