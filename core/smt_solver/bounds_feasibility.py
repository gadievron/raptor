"""Check whether buffer-overflow bounds conditions are provably infeasible.

Given a function's source text and CWE class, extract bounds conditions
(if/while guards that reference size-related identifiers) and ask Z3
whether those conditions make overflow impossible (UNSAT).

This is the generic checker — callers provide the source text and CWE;
file I/O and checklist lookup remain in the caller.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_OVERFLOW_CWES = frozenset({"120", "121", "122", "787", "190"})

# The source text comes from the scanned target, so the pattern must stay
# linear on adversarial input: the (?!keyword) loop pins the match to the
# first size keyword (no ambiguous [^)]* overlap to backtrack through) and
# every inner quantifier is bounded, so unclosed-paren keyword-repeating
# input cannot trigger super-linear backtracking. Conditions longer than
# the bounds are degenerate and deliberately unmatched.
_SIZE_KEYWORD = r"(?:len|size|length|count|MAX|LIMIT|BUFSIZ|sizeof)"
_BOUNDS_CONDITION_RE = re.compile(
    r"if\s*\("
    r"((?:(?!" + _SIZE_KEYWORD + r")[^)]){0,512}"
    + _SIZE_KEYWORD
    + r"[^)<>=!]{0,256}[<>=!]{1,4}[^)]{0,256})\)",
    re.IGNORECASE,
)


def check_bounds_infeasible(
    source: str,
    cwe: str,
    *,
    timeout_ms: int = 5000,
) -> bool | None:
    """Return True if overflow is provably impossible, False if possible, None if inconclusive.

    Only runs for overflow-related CWEs (120, 121, 122, 787, 190).
    Returns None when Z3 is unavailable, no conditions are found, or the
    solver times out.

    Refuse-to-conjoin: guards are extracted from flat source text and
    carry NO path structure. Guards on mutually exclusive branches
    (``if (len < 16) … else if (len >= 16)`` — the standard C
    size-dispatch idiom — or disjoint early-return guards) are jointly
    UNSAT by construction, so asserting them as one conjunction would
    "prove" overflow impossible in exactly the functions most likely
    to overflow, and the consumer demotes real findings on that forged
    receipt. Without per-path guard sets there is no sound conjunction
    of two DIFFERENT guards, so more than one distinct guard →
    inconclusive (None). A single guard (or the same guard text
    repeated) is a genuine one-guard conjunction and keeps the
    original semantics. Residual limit (documented): even a single
    guard is not bound to the overflow site, so True still means "the
    only size-guard in scope is self-contradictory", not a
    site-anchored proof — the condition_smt fallback in the consumer
    carries the hypothesis-anchored disproof.
    """
    cwe_num = cwe.rsplit("-", 1)[-1] if "-" in cwe else cwe
    if cwe_num not in _OVERFLOW_CWES:
        return None

    try:
        from core.smt_solver.path_feasibility import (
            PathCondition,
            check_path_feasibility,
        )
    except ImportError:
        return None

    conditions = []
    seen: set[str] = set()
    for match in _BOUNDS_CONDITION_RE.finditer(source):
        cond_text = match.group(1).strip()
        if cond_text in seen:
            continue  # identical guard text — idempotent conjunct
        seen.add(cond_text)
        conditions.append(PathCondition(text=cond_text, step_index=0))

    if not conditions:
        return None
    if len(conditions) > 1:
        # Distinct guards without path structure — refuse to conjoin
        # (see docstring). Inconclusive, never "provably impossible".
        return None

    try:
        result = check_path_feasibility(conditions, timeout_ms=timeout_ms)
        if result.feasible is False:
            return True
        return False if result.feasible is True else None
    except Exception:
        logger.debug("SMT bounds check failed", exc_info=True)
        return None
