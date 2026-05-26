"""Typosquat candidate detector.

For each direct dep, computes Damerau-Levenshtein distance against the
bundled per-ecosystem popular-names list. A name within distance 1 or
2 of a popular package is flagged as a candidate; an *exact* match is
trusted (the dep IS the popular package).

Limits & honesty:

- The bundled list ships ~80–100 names per ecosystem — far short of
  the 5k target the design doc anticipates. False negatives are
  inevitable for less-trafficked names. Add to ``data/popular/<eco>.json``
  to extend coverage; the file is JSON for that reason.
- We use a string-only check; ``lodash`` vs ``lodaash`` flags, but
  ``lodash`` (correct) vs ``loadsh`` (transposed) needs the Damerau
  variant — included.
- Scope-name typosquats are normalised: ``@types/node`` is compared
  against the popular list both as itself and as ``types/node`` (some
  attackers omit the ``@``). The package name kept on the finding is
  the original.
"""

from __future__ import annotations

import json as _json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..models import Confidence, Dependency

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "popular"

# Distances above this are not interesting; below it we always flag
# (with severity scaled by distance).
_MAX_DISTANCE = 2

# Per-ecosystem popular-name caches. Loaded lazily and re-used.
_POPULAR_BY_ECO: Dict[str, List[str]] = {}
# Per-ecosystem ``{length: [name, ...]}`` index. The Damerau-
# Levenshtein cap ``_MAX_DISTANCE`` already implies
# ``|len(query) - len(pop)| ≤ _MAX_DISTANCE``; pre-bucketing by
# length lets ``_check_one`` walk only the candidate names whose
# lengths are within ±_MAX_DISTANCE of the query — typically 5-15
# names instead of the full ~100. Pre-fix, the inner loop ran the
# full popular list per dep × 1300+ deps = 134k Damerau-Levenshtein
# calls per scan. The dropped calls would have all returned ``cutoff``
# from the first ``abs(la-lb) >= cutoff`` early-out anyway, so the
# bucket index is purely a faster way to enforce a check the inner
# function was already doing — output is byte-identical.
_POPULAR_BY_LEN: Dict[str, Dict[int, List[str]]] = {}
# Set view of the popular list for the O(1) "is it popular" test
# in ``_check_one`` (was a list ``in`` linear scan pre-fix).
_POPULAR_SET: Dict[str, set] = {}


@dataclass(frozen=True)
class TyposquatFinding:
    dependency: Dependency
    nearest_popular: str
    distance: int
    severity: str
    confidence: Confidence


def scan_deps(deps: Iterable[Dependency]) -> List[TyposquatFinding]:
    """Run the candidate check on every direct dep."""
    out: List[TyposquatFinding] = []
    for d in deps:
        if not d.direct:
            continue
        finding = _check_one(d)
        if finding is not None:
            out.append(finding)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _check_one(dep: Dependency) -> Optional[TyposquatFinding]:
    popular = _load_popular(dep.ecosystem)
    if not popular:
        return None

    name_norm = dep.name.lower()
    # Full name is in the popular list → it IS the popular package.
    # Set lookup is O(1) — was a linear scan via ``in popular``
    # against the underlying list before the index landed.
    if name_norm in _popular_set(dep.ecosystem):
        return None

    candidates = [name_norm]
    if name_norm.startswith("@") and "/" in name_norm:
        candidates.append(name_norm.split("/", 1)[1])

    by_len = _popular_by_len(dep.ecosystem)
    best: Optional[Tuple[int, str]] = None
    for cand in candidates:
        # Walk only the length buckets that COULD contain a match.
        # Damerau-Levenshtein with cutoff ``_MAX_DISTANCE`` requires
        # ``|len(cand) - len(pop)| ≤ _MAX_DISTANCE``; the inner
        # function's early-out enforces this anyway, so dropped
        # candidates would all have returned ``cutoff`` and been
        # skipped. Walking the buckets directly avoids the function-
        # call overhead for those certain-fails.
        cand_len = len(cand)
        lo, hi = cand_len - _MAX_DISTANCE, cand_len + _MAX_DISTANCE
        for length in range(lo, hi + 1):
            shortlist = by_len.get(length)
            if not shortlist:
                continue
            for pop in shortlist:
                if cand == pop:
                    # Bare-form exact match inside a non-popular scope.
                    # ``@evil/lodash`` shape — scoped-namespace squat
                    # rather than a typo.
                    if best is None or 0 < best[0]:
                        best = (0, pop)
                    continue
                d = _damerau_levenshtein(cand, pop, _MAX_DISTANCE + 1)
                if d > _MAX_DISTANCE:
                    continue
                if best is None or d < best[0]:
                    best = (d, pop)

    if best is None:
        return None

    distance, nearest = best
    if distance == 0:
        severity = "high"
        confidence_reason = (
            f"bare form matches popular '{nearest}'; "
            "scoped-name namespace squat shape"
        )
        confidence_level = "high"
    elif distance == 1:
        severity = "high"
        confidence_reason = (
            f"distance-1 from popular '{nearest}'; "
            "may be a legitimate package or a typosquat"
        )
        confidence_level = "medium"
    else:
        severity = "medium"
        confidence_reason = (
            f"distance-{distance} from popular '{nearest}'; "
            "may be a legitimate package or a typosquat"
        )
        confidence_level = "low"

    return TyposquatFinding(
        dependency=dep,
        nearest_popular=nearest,
        distance=distance,
        severity=severity,
        confidence=Confidence(confidence_level, reason=confidence_reason),
    )


def _load_popular(ecosystem: str) -> List[str]:
    if ecosystem in _POPULAR_BY_ECO:
        return _POPULAR_BY_ECO[ecosystem]
    path = _DATA_DIR / f"{ecosystem}.json"
    if not path.exists():
        _POPULAR_BY_ECO[ecosystem] = []
        return []
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError) as e:
        logger.warning("sca.supply_chain.typosquat: failed to load %s: %s",
                       path, e)
        _POPULAR_BY_ECO[ecosystem] = []
        return []
    if not isinstance(data, list):
        _POPULAR_BY_ECO[ecosystem] = []
        return []
    cleaned = [n.lower() for n in data if isinstance(n, str)]
    _POPULAR_BY_ECO[ecosystem] = cleaned
    return cleaned


def _popular_set(ecosystem: str) -> set:
    """Return the popular list as a set for O(1) ``in`` checks."""
    cached = _POPULAR_SET.get(ecosystem)
    if cached is not None:
        return cached
    popular = _load_popular(ecosystem)
    s = set(popular)
    _POPULAR_SET[ecosystem] = s
    return s


def _popular_by_len(ecosystem: str) -> Dict[int, List[str]]:
    """Return the popular list indexed by name length.

    Walking only the buckets at lengths within ``_MAX_DISTANCE`` of
    the query length cuts the inner ``_damerau_levenshtein`` calls
    by ~5-10× on a typical ~100-name popular list (lengths span
    4-15 chars; ±2 buckets give ~5 length values vs the whole
    list).
    """
    cached = _POPULAR_BY_LEN.get(ecosystem)
    if cached is not None:
        return cached
    by_len: Dict[int, List[str]] = {}
    for name in _load_popular(ecosystem):
        by_len.setdefault(len(name), []).append(name)
    _POPULAR_BY_LEN[ecosystem] = by_len
    return by_len


def _damerau_levenshtein(a: str, b: str, cutoff: int) -> int:
    """Optimal-string-alignment distance with early-exit ``cutoff``.

    Returns ``cutoff`` (the cap) when the true distance exceeds it.
    Standard implementation: row-by-row DP with a single character of
    look-back to handle adjacent transpositions.
    """
    la, lb = len(a), len(b)
    if abs(la - lb) >= cutoff:
        return cutoff
    if la == 0:
        return min(lb, cutoff)
    if lb == 0:
        return min(la, cutoff)

    # Base row d[0][j] = j (cost of inserting j chars of b into empty a).
    # The pre-fix code zero-initialised ``prev`` and then rotated it at the
    # START of each iteration, which discarded the base row entirely — at
    # i=1, ``prev`` was [0,0,…,0] instead of [0,1,2,…,lb]. The DP then
    # propagated a 0 to ``cur[j]`` for any j where ``a[0] == b[j-1]``,
    # making ``DL("a", "cma") = 0`` instead of 2 (similarly ``DL("a", "ba")``,
    # ``DL("a", "aa")``). Fix: initialise ``prev`` correctly and rotate at
    # the END of each iteration so the first body sees the right base row.
    prev_prev = [0] * (lb + 1)         # unused at i=1; placeholder
    prev = list(range(lb + 1))         # d[0]
    cur = [0] * (lb + 1)               # d[1] scratch
    for i in range(1, la + 1):
        cur[0] = i
        row_min = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(
                prev[j] + 1,           # deletion
                cur[j - 1] + 1,        # insertion
                prev[j - 1] + cost,    # substitution
            )
            if (i > 1 and j > 1
                    and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                cur[j] = min(cur[j], prev_prev[j - 2] + 1)
            if cur[j] < row_min:
                row_min = cur[j]
        if row_min >= cutoff:
            return cutoff
        # Rotate AFTER computing this row: the just-filled ``cur`` is
        # next iteration's ``prev``; ``prev`` becomes ``prev_prev``.
        cur, prev, prev_prev = [0] * (lb + 1), cur, prev
    # After the final rotation the last filled row is in ``prev``.
    return min(prev[lb], cutoff)


__all__ = ["TyposquatFinding", "scan_deps"]
