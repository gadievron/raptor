"""Mechanical verification of LLM-stated preconditions.

When the LLM marks a function as 'finding', it must state preconditions —
assumptions that must hold for the vulnerability to be exploitable.  Each
precondition names a check_type and a location.  This module runs the
check and returns whether the precondition is supported, contradicted,
or inconclusive.

Only CONTRADICTED results demote; inconclusive results are left alone.

Receipt grades: every supported result carries a ``grade``
naming what kind of receipt earned it, because the positive direction
(the suspicious→finding promotion floor) may only anchor on a
tool-grounded receipt:

- ``structural`` — a call-shaped sink match against the sanitized
  source view (comments and string literals blanked): an actual call
  site, not prose.  The only grade the promotion floor accepts as its
  load-bearing anchor.
- ``context_map`` — reachability derived from the context map, whose
  entry points are LLM-authored (/understand output).  Corroborating,
  never the anchor.
- ``lexical`` — raw regex presence of a related pattern.  Weak.
- ``absence`` — a regex found NOTHING and the claim expected absence.
  "No pattern found" is not a positive receipt (the module's own
  absent-verdict doctrine), so absence-supported arms can never anchor
  a promotion.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# Receipt grades for supported results (see module docstring).
GRADE_STRUCTURAL = "structural"
GRADE_CONTEXT_MAP = "context_map"
GRADE_LEXICAL = "lexical"
GRADE_ABSENCE = "absence"


@dataclass
class CheckResult:
    """Result of verifying a single precondition."""

    check_type: str
    assumption: str
    verdict: str  # "supported", "contradicted", "inconclusive"
    evidence: str = ""  # what we found (or didn't)
    grade: str = ""  # receipt grade for supported results


@dataclass
class PreconditionVerdict:
    """Aggregate result of checking all preconditions for a finding."""

    checks: list[CheckResult] = field(default_factory=list)

    @property
    def any_contradicted(self) -> bool:
        return any(c.verdict == "contradicted" for c in self.checks)

    @property
    def contradiction_summary(self) -> str:
        parts = [f"{c.check_type}: {c.evidence}" for c in self.checks if c.verdict == "contradicted"]
        return "; ".join(parts)

    @property
    def all_supported(self) -> bool:
        """True when every check verified in the vulnerability-supporting direction.

        Empty check lists are NOT "all supported" — an absent verdict is
        not a positive one.
        """
        return bool(self.checks) and all(
            c.verdict == "supported" for c in self.checks
        )

    @property
    def supported_types(self) -> frozenset:
        """check_type values whose verdict came back supported."""
        return frozenset(
            c.check_type for c in self.checks if c.verdict == "supported"
        )


def verify_preconditions(
    preconditions: list[dict[str, Any]],
    target_path: Path,
    context_map: dict[str, Any] | None = None,
) -> PreconditionVerdict:
    """Run mechanical checks on LLM-stated preconditions.

    Each precondition dict has: assumption, check_type, location,
    expect_absent, and optionally parameter.
    """
    verdict = PreconditionVerdict()

    for pc in preconditions:
        check_type = pc.get("check_type", "")
        location = pc.get("location", {})
        loc_file = location.get("file", "")
        loc_func = location.get("function", "")
        expect_absent = pc.get("expect_absent", True)
        parameter = pc.get("parameter", "")
        assumption = pc.get("assumption", "")

        if not check_type or not loc_file or not loc_func:
            verdict.checks.append(CheckResult(
                check_type=check_type or "unknown",
                assumption=assumption,
                verdict="inconclusive",
                evidence="missing check_type or location",
            ))
            continue

        source = _read_function_source(target_path, loc_file, loc_func)
        if source is None:
            verdict.checks.append(CheckResult(
                check_type=check_type,
                assumption=assumption,
                verdict="inconclusive",
                evidence=f"could not read {loc_file}:{loc_func}",
            ))
            continue

        if check_type == "caller_null_terminates":
            result = _check_null_termination(
                source, loc_file, loc_func, parameter, expect_absent,
            )
        elif check_type == "caller_bounds_checks":
            result = _check_bounds(
                source, loc_file, loc_func, parameter, expect_absent,
            )
        elif check_type == "caller_sanitizes":
            result = _check_sanitization(
                source, loc_file, loc_func, parameter, expect_absent,
            )
        elif check_type == "attacker_controls_input":
            result = _check_attacker_control(
                source, loc_file, loc_func, parameter,
                expect_absent, context_map,
            )
        elif check_type == "function_reaches_sink":
            result = _check_reaches_sink(
                source, loc_file, loc_func, parameter, expect_absent,
            )
        else:
            result = CheckResult(
                check_type=check_type,
                assumption=assumption,
                verdict="inconclusive",
                evidence=f"unknown check_type: {check_type}",
            )

        result.assumption = assumption
        verdict.checks.append(result)

    return verdict


def _read_function_source(
    target_path: Path, file_path: str, function_name: str,
) -> str | None:
    """Read a function's source from the target directory."""
    full = (target_path / file_path).resolve()
    if not full.is_relative_to(target_path.resolve()):
        return None
    if not full.is_file():
        return None
    try:
        text = full.read_text(errors="replace")
    except OSError:
        return None

    # For C: find function definition by name and extract the body
    # For Python: find def block
    if file_path.endswith((".c", ".h", ".cpp", ".cc")):
        return _extract_c_function(text, function_name)
    if file_path.endswith(".py"):
        return _extract_python_function(text, function_name)
    return text


def _extract_c_function(source: str, name: str) -> str | None:
    """Extract a C function body (heuristic brace-matching)."""
    # Find the function definition: type name(...)  {
    pattern = re.compile(
        rf'\b{re.escape(name)}\s*\([^)]*\)\s*\{{',
        re.MULTILINE,
    )
    m = pattern.search(source)
    if not m:
        return None

    start = m.start()
    depth = 0
    length = len(source)
    i = m.end() - 1
    in_string = False
    string_char = ""
    while i < length:
        ch = source[i]
        if in_string:
            if ch == string_char:
                bs = 0
                while i - 1 - bs >= 0 and source[i - 1 - bs] == "\\":
                    bs += 1
                if bs % 2 == 0:
                    in_string = False
        elif ch in ('"', "'"):
            in_string = True
            string_char = ch
        elif ch == "/" and i + 1 < length:
            nxt = source[i + 1]
            if nxt == "/":
                nl = source.find("\n", i + 2)
                i = nl if nl >= 0 else length
            elif nxt == "*":
                end = source.find("*/", i + 2)
                i = end + 1 if end >= 0 else length
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    return source[start:]


def _extract_python_function(source: str, name: str) -> str | None:
    """Extract a Python function body (indent-based)."""
    pattern = re.compile(rf'^([ \t]*)def\s+{re.escape(name)}\s*\(', re.MULTILINE)
    m = pattern.search(source)
    if not m:
        return None
    indent = len(m.group(1))
    start = m.start()
    lines = source[start:].split('\n')
    result = [lines[0]]
    for line in lines[1:]:
        stripped = line.lstrip()
        if stripped and not line[:1].isspace():
            break
        cur_indent = len(line) - len(stripped) if stripped else indent + 1
        if stripped and cur_indent <= indent:
            break
        result.append(line)
    return '\n'.join(result)


# ── Check implementations ──────────────────────────────────────────

# Explicit terminator stores: buf[len] = '\0'; buf[n] = 0;
_NULL_TERM_STORE_PATTERNS = [
    re.compile(r"\[\s*\w+\s*\]\s*=\s*['\"]?\\0['\"]?\s*;"),
    re.compile(r"\[\s*\w+\s*\]\s*=\s*0\s*;"),
]

# Bare call tokens: too weak to bind to a specific buffer (and
# strncpy does not even guarantee termination).
_NULL_TERM_TOKEN_PATTERNS = [
    re.compile(r"\bstrncpy\b"),
    re.compile(r"\bstrlcpy\b"),
    re.compile(r"\bsnprintf\b"),
    # strdup family (always null-terminated)
    re.compile(r"\bstrdup\b"),
    re.compile(r"\bstrndup\b"),
]

_NULL_TERM_PATTERNS = _NULL_TERM_STORE_PATTERNS + _NULL_TERM_TOKEN_PATTERNS


def _check_null_termination(
    source: str, file: str, func: str,
    parameter: str, expect_absent: bool,
) -> CheckResult:
    """Check if a function null-terminates a buffer.

    For caller_null_terminates, expect_absent=True means the LLM claims
    the caller does NOT null-terminate. Bare call tokens (a strncpy or
    strdup anywhere in the function) are weak evidence — they don't
    prove the specific buffer is terminated — so they cap at
    'inconclusive', matching _check_bounds/_check_sanitization. Only
    an explicit terminator store contradicts: bound to the named
    parameter when one is given, or any store when the claim names no
    buffer to bind.
    """
    found_patterns = []
    strong_patterns = []

    for pat in _NULL_TERM_STORE_PATTERNS:
        if pat.search(source):
            found_patterns.append(pat.pattern[:40])
            if not parameter:
                strong_patterns.append(pat.pattern[:40])

    found_patterns.extend(pat.pattern[:40] for pat in _NULL_TERM_TOKEN_PATTERNS if pat.search(source))

    # Also look for the specific parameter if given
    if parameter:
        param_null = re.compile(
            rf'\b{re.escape(parameter)}\b.*=\s*[\'"]?\\0[\'"]?\s*;'
            rf'|'
            rf'\b{re.escape(parameter)}\s*\[.*\]\s*=\s*[\'"]?\\0[\'"]?\s*;'
            rf'|'
            rf'\b{re.escape(parameter)}\s*\[.*\]\s*=\s*0\s*;',
        )
        if param_null.search(source):
            found_patterns.append(f"explicit \\0 on '{parameter}'")
            strong_patterns.append(f"explicit \\0 on '{parameter}'")

    has_null_term = bool(found_patterns)

    if expect_absent:
        # LLM claims null-termination is ABSENT
        if strong_patterns:
            return CheckResult(
                check_type="caller_null_terminates",
                assumption="",
                verdict="contradicted",
                evidence=(
                    f"{file}:{func} DOES null-terminate: "
                    f"{', '.join(strong_patterns[:3])}"
                ),
            )
        if has_null_term:
            return CheckResult(
                check_type="caller_null_terminates",
                assumption="",
                verdict="inconclusive",
                evidence=(
                    f"{file}:{func} has null-termination-related patterns "
                    f"({', '.join(found_patterns[:3])}) but cannot confirm "
                    "they terminate this specific buffer"
                ),
            )
        return CheckResult(
            check_type="caller_null_terminates",
            assumption="",
            verdict="supported",
            evidence=f"no null-termination found in {file}:{func}",
            grade=GRADE_ABSENCE,
        )
    # LLM claims null-termination IS present
    if has_null_term:
        return CheckResult(
            check_type="caller_null_terminates",
            assumption="",
            verdict="supported",
            evidence=f"null-termination found: {', '.join(found_patterns[:3])}",
            grade=GRADE_LEXICAL,
        )
    return CheckResult(
        check_type="caller_null_terminates",
        assumption="",
        verdict="inconclusive",
        evidence=f"no null-termination pattern found in {file}:{func}",
    )


_BOUNDS_PATTERNS = [
    re.compile(r"\bsizeof\b"),
    re.compile(r"\bstrlen\b"),
    re.compile(r"\bstrnlen\b"),
    re.compile(r"\bMAX_\w+"),
    re.compile(r"\b\w+_MAX\b"),
    re.compile(r"\b\w+_LEN\b"),
    re.compile(r"\b\w+_SIZE\b"),
    re.compile(r"\b\w+_CAP\b"),
    # Comparison operators near length/size variables
    re.compile(r"\b\w*len\w*\s*[<>=!]+"),
    re.compile(r"\b\w*size\w*\s*[<>=!]+"),
    re.compile(r"\b\w*cap\w*\s*[<>=!]+"),
]


def _check_bounds(
    source: str, file: str, func: str,
    _parameter: str, expect_absent: bool,
) -> CheckResult:
    """Check if a function performs bounds checking.

    Regex matching is weak evidence — a sizeof or MAX_ in a function
    doesn't prove it protects the specific argument.  So this never
    returns 'contradicted': under expect_absent, found patterns yield
    'inconclusive' (we decline to affirm on weak evidence) and
    'supported' is returned only when no patterns are found; without
    expect_absent, found patterns yield 'supported' and their absence
    'inconclusive'.
    """
    found = [pat.pattern[:30] for pat in _BOUNDS_PATTERNS if pat.search(source)]

    has_bounds = bool(found)

    if expect_absent:
        if has_bounds:
            return CheckResult(
                check_type="caller_bounds_checks",
                assumption="",
                verdict="inconclusive",
                evidence=(
                    f"{file}:{func} has bounds-related patterns "
                    f"({', '.join(found[:3])}) but cannot confirm "
                    "they protect this specific operation"
                ),
            )
        return CheckResult(
            check_type="caller_bounds_checks",
            assumption="",
            verdict="supported",
            evidence=f"no bounds checking found in {file}:{func}",
            grade=GRADE_ABSENCE,
        )
    if has_bounds:
        return CheckResult(
            check_type="caller_bounds_checks",
            assumption="",
            verdict="supported",
            evidence=f"bounds checking found: {', '.join(found[:3])}",
            grade=GRADE_LEXICAL,
        )
    return CheckResult(
        check_type="caller_bounds_checks",
        assumption="",
        verdict="inconclusive",
        evidence=f"no bounds pattern found in {file}:{func}",
    )


_SANITIZE_PATTERNS = [
    re.compile(r"\bvalidat\w*\b", re.IGNORECASE),
    re.compile(r"\bsanitiz\w*\b", re.IGNORECASE),
    re.compile(r"\bcheck_\w+\b"),
    re.compile(r"\bis_valid\w*\b"),
    re.compile(r"\bescape\w*\b", re.IGNORECASE),
    re.compile(r"\bfilter\w*\b", re.IGNORECASE),
    re.compile(r"\bnormalize\w*\b", re.IGNORECASE),
    # Python-specific
    re.compile(r"\bos\.path\.abspath\b"),
    re.compile(r"\bos\.path\.realpath\b"),
    re.compile(r"\bshlex\.quote\b"),
    re.compile(r"\bhtml\.escape\b"),
    re.compile(r"\bmarkup[Ss]afe\b"),
    # SQL parameterization
    re.compile(r"\bparameteriz\w*\b", re.IGNORECASE),
    re.compile(r"\bprepared?\s+statement\b", re.IGNORECASE),
    re.compile(r"\bplaceholder\b", re.IGNORECASE),
    re.compile(r"%s.*execute\b"),
    re.compile(r"\?\s*,"),
]


def _check_sanitization(
    source: str, file: str, func: str,
    _parameter: str, expect_absent: bool,
) -> CheckResult:
    """Check if a function sanitizes/validates input.

    Regex matching is weak evidence — a validate/normalize call
    doesn't prove it protects the specific vulnerable operation.
    Return 'inconclusive' instead of 'contradicted' for regex hits.
    """
    found = [pat.pattern[:30] for pat in _SANITIZE_PATTERNS if pat.search(source)]

    has_sanitization = bool(found)

    if expect_absent:
        if has_sanitization:
            return CheckResult(
                check_type="caller_sanitizes",
                assumption="",
                verdict="inconclusive",
                evidence=(
                    f"{file}:{func} has sanitization-related patterns "
                    f"({', '.join(found[:3])}) but cannot confirm "
                    "they protect this specific operation"
                ),
            )
        return CheckResult(
            check_type="caller_sanitizes",
            assumption="",
            verdict="supported",
            evidence=f"no sanitization found in {file}:{func}",
            grade=GRADE_ABSENCE,
        )
    if has_sanitization:
        return CheckResult(
            check_type="caller_sanitizes",
            assumption="",
            verdict="supported",
            evidence=f"sanitization found: {', '.join(found[:3])}",
            grade=GRADE_LEXICAL,
        )
    return CheckResult(
        check_type="caller_sanitizes",
        assumption="",
        verdict="inconclusive",
        evidence=f"no sanitization pattern found in {file}:{func}",
    )


def _check_attacker_control(
    _source: str, file: str, func: str,
    _parameter: str, expect_absent: bool,
    context_map: dict[str, Any] | None = None,
) -> CheckResult:
    """Check if a function's input is attacker-controlled.

    Uses the context map's entry_points to determine reachability.
    """
    if context_map is None:
        return CheckResult(
            check_type="attacker_controls_input",
            assumption="",
            verdict="inconclusive",
            evidence="no context map available",
        )

    entry_points = set()
    for ep in context_map.get("entry_points", []):
        if isinstance(ep, str):
            ep_name = ep
            ep_file = ""
        else:
            ep_name = ep.get("name", "")
            ep_file = ep.get("file", "")
        if ep_name:
            entry_points.add(ep_name)
            if ep_file:
                entry_points.add(f"{ep_file}:{ep_name}")

    if not entry_points:
        return CheckResult(
            check_type="attacker_controls_input",
            assumption="",
            verdict="inconclusive",
            evidence="no entry points catalogued — cannot determine reachability",
        )

    is_entry = func in entry_points or f"{file}:{func}" in entry_points

    # Check call edges: is this function called (transitively) from an entry?
    callers_of_func = set()
    for edge in context_map.get("call_edges", []):
        if edge.get("callee") == func:
            callers_of_func.add(edge.get("caller", ""))

    reachable = is_entry or bool(callers_of_func & entry_points)
    if not reachable:
        # Check 2-hop
        for caller in callers_of_func:
            for edge in context_map.get("call_edges", []):
                if (
                    edge.get("callee") == caller
                    and edge.get("caller", "") in entry_points
                ):
                    reachable = True
                    break
            if reachable:
                break

    if expect_absent:
        # LLM claims attacker does NOT control input
        if reachable:
            return CheckResult(
                check_type="attacker_controls_input",
                assumption="",
                verdict="contradicted",
                evidence=f"{func} IS reachable from entry points",
            )
        return CheckResult(
            check_type="attacker_controls_input",
            assumption="",
            verdict="supported",
            evidence=f"{func} is not reachable from entry points",
            grade=GRADE_CONTEXT_MAP,
        )
    # LLM claims attacker DOES control input
    if reachable:
        # The context map's entry points are LLM-authored
        # (/understand output) — corroborating, never a
        # tool-grounded anchor.
        return CheckResult(
            check_type="attacker_controls_input",
            assumption="",
            verdict="supported",
            evidence=f"{func} is reachable from entry points",
            grade=GRADE_CONTEXT_MAP,
        )
    return CheckResult(
        check_type="attacker_controls_input",
        assumption="",
        verdict="contradicted",
        evidence=(
            f"{func} is NOT reachable from entry points"
        ),
    )


# Call-shaped sink patterns: the token must be followed by an opening
# parenthesis, so declarations/prose fragments don't count. Matched
# against the SANITIZED view only (comments and string literals
# blanked) — a comment or format string that merely mentions a sink
# must never earn the receipt — a hostile repo could plant sink
# tokens in comments to satisfy the promotion floor's
# load-bearing check.
_SINK_CALL_PATTERNS = [
    # Memory-unsafe C APIs
    re.compile(r"\bstrcpy\s*\("),
    re.compile(r"\bstrcat\s*\("),
    re.compile(r"\bsprintf\s*\("),
    re.compile(r"\bgets\s*\("),
    re.compile(r"\bmemcpy\s*\("),
    re.compile(r"\bmemmove\s*\("),
    # File/path APIs
    re.compile(r"\bfopen\s*\("),
    re.compile(r"\bopen\s*\("),
    re.compile(r"\bexecv\w*\s*\("),
    re.compile(r"\bsystem\s*\("),
    re.compile(r"\bpopen\s*\("),
    # SQL
    re.compile(r"\bexecute(?:many)?\s*\("),
    re.compile(r"\bsqlite3_exec\s*\("),
    re.compile(r"\bmysql_query\s*\("),
    # Python dangerous APIs
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bsubprocess\.\w+\s*\("),
]


def _check_reaches_sink(
    source: str, file: str, func: str,
    _parameter: str, expect_absent: bool,
) -> CheckResult:
    """Check if a function directly calls a dangerous API (sink).

    Only checks the function's own body for sink CALL SITES — the
    match runs on the sanitized view (comments/strings blanked) and
    requires the call shape (``token(``), so prose mentioning a sink
    never counts in either direction. When the LLM claims a function
    reaches a sink but the function only reaches it through callees,
    return inconclusive — we can't confirm or deny transitive
    reachability with a regex check.
    """
    from .source_view import sanitized_view

    view = sanitized_view(source, file)
    found = [pat.pattern[:30] for pat in _SINK_CALL_PATTERNS if pat.search(view)]

    has_sink = bool(found)

    if expect_absent:
        if has_sink:
            return CheckResult(
                check_type="function_reaches_sink",
                assumption="",
                verdict="inconclusive",
                evidence=(
                    f"{func} DOES reach sinks: {', '.join(found[:3])} "
                    f"(LLM claimed absent, but presence of sinks "
                    f"doesn't disprove the finding)"
                ),
            )
        return CheckResult(
            check_type="function_reaches_sink",
            assumption="",
            verdict="supported",
            evidence=f"no sink calls found in {func}",
            grade=GRADE_ABSENCE,
        )
    if has_sink:
        return CheckResult(
            check_type="function_reaches_sink",
            assumption="",
            verdict="supported",
            evidence=(
                f"sink call sites found (sanitized view): "
                f"{', '.join(found[:3])}"
            ),
            grade=GRADE_STRUCTURAL,
        )
    return CheckResult(
        check_type="function_reaches_sink",
        assumption="",
        verdict="inconclusive",
        evidence=(
            f"{func} does not directly call known sinks "
            "(may reach them through callees)"
        ),
    )
