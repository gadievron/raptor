"""Callee contract precondition injection for audit review.

When a function calls a callee with known preconditions (from FunctionSummary),
inject those preconditions into the review context so the LLM can check
whether the caller ensures them on all code paths (Cap 8 lightweight).

Also provides mechanical best-effort precondition checking via regex
patterns (ContractViolation / enforce_callee_contracts).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

logger = logging.getLogger(__name__)


@dataclass
class ContractContext:
    """A callee's preconditions that the caller must ensure."""

    callee_function: str
    callee_file: str
    preconditions: List[str]
    source: str = "joern_summary"


@dataclass
class ContractViolation:
    """A mechanically detected precondition violation."""

    caller_file: str
    caller_function: str
    callee_function: str
    violated_precondition: str
    evidence: str
    cwe: str = ""
    callee_file: str = ""


def extract_callee_contracts(
    gap: Dict[str, Any],
    summaries: Dict[str, Any],
) -> List[ContractContext]:
    """Extract precondition contracts from callee summaries.

    For each callee in the gap's callee list, look up its FunctionSummary
    and extract preconditions.
    """
    callees = gap.get("callees", [])
    if not callees:
        return []

    contracts: List[ContractContext] = []

    for callee in callees:
        callee_name = callee if isinstance(callee, str) else callee.get("name", "")
        callee_file = "" if isinstance(callee, str) else callee.get("file", "")
        if not callee_name:
            continue

        summary = _lookup_summary(callee_name, callee_file, summaries)
        if summary is None:
            continue

        preconditions = _extract_preconditions(summary)
        if not preconditions:
            continue

        contracts.append(ContractContext(
            callee_function=callee_name,
            callee_file=callee_file,
            preconditions=preconditions,
            source="joern_summary",
        ))

    return contracts


def format_contracts_for_prompt(
    contracts: Sequence[ContractContext],
) -> str:
    """Render callee contracts as prose for LLM context injection.

    Returns empty string if no contracts to render.
    """
    if not contracts:
        return ""

    lines = [
        "### Callee contracts (preconditions to verify)",
        "",
    ]

    for c in contracts:
        precond_str = "; ".join(c.preconditions)
        loc = f" ({c.callee_file})" if c.callee_file else ""
        lines.append(
            f"- `{c.callee_function}()`{loc} requires: {precond_str}"
        )

    lines.extend([
        "",
        "Check: does this function ensure these preconditions on ALL "
        "code paths, including error paths? A missing precondition "
        "check is a potential vulnerability.",
    ])

    return "\n".join(lines)


def format_contract_violations_for_prompt(
    violations: Sequence[ContractViolation],
) -> str:
    """Render mechanically detected contract violations for the LLM.

    These are heuristic findings from ``enforce_callee_contracts`` —
    the caller source showed no guard for a callee precondition.
    Returns empty string if there is nothing to render.
    """
    if not violations:
        return ""

    lines = [
        "### Contract violations (mechanically detected, verify)",
        "",
    ]

    for v in violations:
        cwe = f" [{v.cwe}]" if v.cwe else ""
        lines.append(
            f"- `{v.callee_function}()` precondition "
            f"\"{v.violated_precondition}\" not guarded in "
            f"`{v.caller_function}`{cwe} — {v.evidence}"
        )

    lines.extend([
        "",
        "These guards were not found by regex heuristics; confirm "
        "whether the precondition is enforced another way (wrapper, "
        "type invariant, earlier check) before treating one as a bug.",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Mechanical precondition checking (best-effort, regex-based)
# ---------------------------------------------------------------------------

# Regex patterns for common precondition idioms.  Each entry maps a
# precondition keyword to a (pattern_builder, cwe) pair.  The pattern
# builder takes the parameter name and returns a compiled regex that
# matches a satisfying check in the caller source.

_NULL_CHECK_RE = re.compile(
    r"(?:!=\s*NULL|!=\s*nullptr|!=\s*0\b|!=\s*\(\s*void\s*\*\s*\)\s*0"
    r"|\bif\s*\([^)]*\b{param}\b[^)]*\))",
)

_POSITIVE_CHECK_RE = re.compile(
    r"(?:>\s*0|>=\s*1|>=\s*0)",
)

_SIZE_CHECK_RE = re.compile(
    r"(?:>=\s*\d+|<=\s*\d+|<\s*\d+|>\s*\d+|\bsizeof\b|\blen(?:gth)?\b)",
)

_LOCK_PATTERNS = (
    "pthread_mutex_lock", "mutex_lock", "spin_lock", "lock_acquire",
    "EnterCriticalSection", "lock(", "acquire(",
)


def _has_null_check(param: str, source: str) -> bool:
    """Check if source contains a null check for *param* before use."""
    pattern = re.compile(
        rf"\b{re.escape(param)}\b\s*!=\s*(?:NULL|nullptr|0\b)"
        rf"|\bif\s*\(\s*{re.escape(param)}\s*\)",
    )
    return bool(pattern.search(source))


def _has_positive_check(param: str, source: str) -> bool:
    """Check if source validates *param* is positive."""
    pattern = re.compile(
        rf"\b{re.escape(param)}\b\s*(?:>\s*0|>=\s*1)"
        rf"|0\s*<\s*{re.escape(param)}\b"
        rf"|1\s*<=\s*{re.escape(param)}\b",
    )
    return bool(pattern.search(source))


def _has_size_check(param: str, source: str) -> bool:
    """Check if source validates a buffer size for *param*."""
    pattern = re.compile(
        rf"\b{re.escape(param)}\b\s*(?:>=|<=|<|>)\s*\d+"
        rf"|\bsizeof\s*\(\s*{re.escape(param)}\s*\)"
        rf"|\b(?:len|length|size)\s*\(\s*{re.escape(param)}\s*\)",
    )
    return bool(pattern.search(source))


def _has_lock_before(callee: str, source: str) -> bool:
    """Check if source acquires a lock before calling *callee*."""
    callee_pos = source.find(callee)
    if callee_pos < 0:
        return False
    preamble = source[:callee_pos]
    for lp in _LOCK_PATTERNS:
        idx = preamble.find(lp)
        if idx < 0:
            continue
        if idx > 0 and preamble[idx - 1].isalpha():
            continue
        return True
    return False


def _extract_param_from_precondition(precondition: str) -> str:
    """Pull the parameter name from a precondition string.

    Handles the format produced by ``_extract_preconditions``:
      "parameter `foo` must satisfy: ..."
      "parameter `buf` flows to ..."
    """
    m = re.search(r"parameter\s+`(\w+)`", precondition)
    return m.group(1) if m else ""


def enforce_callee_contracts(
    gap: Dict[str, Any],
    callee_summaries: Dict[str, Any],
    source: str,
) -> List[ContractViolation]:
    """Mechanically check caller source for missing precondition guards.

    For each callee's preconditions, use regex patterns to look for
    null checks, bounds checks, positivity checks, and lock acquisitions
    in the caller *source*.  Returns one ``ContractViolation`` per
    missing guard.

    This is best-effort heuristic checking, not sound static analysis.
    """
    contracts = extract_callee_contracts(gap, callee_summaries)
    if not contracts:
        return []

    caller_file = gap.get("file", "")
    caller_function = gap.get("name", "")
    violations: List[ContractViolation] = []

    for contract in contracts:
        for precondition in contract.preconditions:
            violation = _check_single_precondition(
                precondition,
                contract.callee_function,
                caller_file,
                caller_function,
                source,
                callee_file=contract.callee_file,
            )
            if violation is not None:
                violations.append(violation)

    if violations:
        logger.debug(
            "enforce_callee_contracts: %d violation(s) in %s:%s",
            len(violations), caller_file, caller_function,
        )

    return violations


def _check_single_precondition(
    precondition: str,
    callee_function: str,
    caller_file: str,
    caller_function: str,
    source: str,
    *,
    callee_file: str = "",
) -> "ContractViolation | None":
    """Check one precondition against the caller source.

    Returns a ``ContractViolation`` if the guard is missing, else ``None``.
    """
    p_lower = precondition.lower()
    param = _extract_param_from_precondition(precondition)

    # --- NULL checks ---
    if "null" in p_lower or "!= null" in p_lower or "not null" in p_lower:
        if param and not _has_null_check(param, source):
            return ContractViolation(
                caller_file=caller_file,
                caller_function=caller_function,
                callee_function=callee_function,
                violated_precondition=precondition,
                evidence=f"no null check for `{param}` before call to `{callee_function}()`",
                cwe="CWE-476",
                callee_file=callee_file,
            )

    # --- Positivity / range checks ---
    if "positive" in p_lower or "> 0" in p_lower or ">= 1" in p_lower:
        if param and not _has_positive_check(param, source):
            return ContractViolation(
                caller_file=caller_file,
                caller_function=caller_function,
                callee_function=callee_function,
                violated_precondition=precondition,
                evidence=f"no positivity check for `{param}` before call to `{callee_function}()`",
                cwe="CWE-20",
                callee_file=callee_file,
            )

    # --- Buffer size checks ---
    if any(kw in p_lower for kw in ("size", "byte", "length", "bound", "at least")):
        if param and not _has_size_check(param, source):
            return ContractViolation(
                caller_file=caller_file,
                caller_function=caller_function,
                callee_function=callee_function,
                violated_precondition=precondition,
                evidence=f"no size validation for `{param}` before call to `{callee_function}()`",
                cwe="CWE-120",
                callee_file=callee_file,
            )

    # --- Lock checks ---
    if "lock" in p_lower or "mutex" in p_lower or "hold" in p_lower:
        if not _has_lock_before(callee_function, source):
            return ContractViolation(
                caller_file=caller_file,
                caller_function=caller_function,
                callee_function=callee_function,
                violated_precondition=precondition,
                evidence=f"no lock acquisition before call to `{callee_function}()`",
                cwe="CWE-362",
                callee_file=callee_file,
            )

    return None


def _lookup_summary(
    function_name: str,
    file_path: str,
    summaries: Dict[str, Any],
) -> Any:
    """Look up a FunctionSummary by function name.

    Tries exact key (file:function) first, then function-name-only.
    """
    if file_path:
        key = f"{file_path}:{function_name}"
        if key in summaries:
            return summaries[key]

    for k, v in summaries.items():
        if k.endswith(f":{function_name}"):
            return v

    if function_name in summaries:
        return summaries[function_name]

    return None


def _extract_preconditions(summary: Any) -> List[str]:
    """Extract human-readable precondition strings from a FunctionSummary."""
    preconditions: List[str] = []

    preconds = getattr(summary, "preconditions", [])
    for p in preconds:
        param = getattr(p, "param", "?")
        conditions = getattr(p, "conditions", [])
        if conditions:
            cond_str = ", ".join(str(c)[:80] for c in conditions[:3])
            preconditions.append(
                f"parameter `{param}` must satisfy: {cond_str}"
            )

    taint_rules = getattr(summary, "taint_rules", [])
    for r in taint_rules:
        source = getattr(r, "source_param", "?")
        sink = getattr(r, "sink_call", "?")
        preconditions.append(
            f"parameter `{source}` flows to `{sink}()` — "
            f"caller must validate `{source}` before passing"
        )

    return preconditions
