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
from typing import Optional

logger = logging.getLogger(__name__)

_OVERFLOW_CWES = frozenset({"120", "121", "122", "787", "190"})

_BOUNDS_CONDITION_RE = re.compile(
    r"if\s*\(\s*([^)]*(?:len|size|length|count|MAX|LIMIT|BUFSIZ|sizeof)[^)]*"
    r"(?:[<>=!]+)[^)]*)\)",
    re.IGNORECASE,
)


def check_bounds_infeasible(
    source: str,
    cwe: str,
    *,
    timeout_ms: int = 5000,
) -> Optional[bool]:
    """Return True if overflow is provably impossible, False if possible, None if inconclusive.

    Only runs for overflow-related CWEs (120, 121, 122, 787, 190).
    Returns None when Z3 is unavailable, no conditions are found, or the
    solver times out.
    """
    if not any(c in cwe for c in _OVERFLOW_CWES):
        return None

    try:
        from core.smt_solver.path_feasibility import (
            PathCondition,
            check_path_feasibility,
        )
    except ImportError:
        return None

    conditions = []
    for match in _BOUNDS_CONDITION_RE.finditer(source):
        cond_text = match.group(1).strip()
        conditions.append(PathCondition(text=cond_text, step_index=0))

    if not conditions:
        return None

    try:
        result = check_path_feasibility(conditions, timeout_ms=timeout_ms)
        if result.feasible is False:
            return True
        return False if result.feasible is True else None
    except Exception:
        logger.debug("SMT bounds check failed", exc_info=True)
        return None
