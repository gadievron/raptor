"""Shared Damerau-Levenshtein (optimal string alignment) distance.

Both name-typosquat (``typosquat``) and domain-typosquat
(``typosquat_domain``) need the same distance metric; one
implementation here keeps the two from drifting apart (the module
previously carried two independent copies, only one of which had the
base-row initialisation fix documented below).

Convention: ``damerau_levenshtein(a, b, cutoff)`` CLAMPS at
``cutoff`` — it returns the exact distance when that distance is
``< cutoff`` and ``cutoff`` itself otherwise. Callers that need the
historical "``cap + 1`` on overflow, exact up to and including
``cap``" convention call with ``cutoff = cap + 1``; the clamp then
returns exact values for distances ``<= cap`` and ``cap + 1``
beyond, which is that convention precisely.
"""

from __future__ import annotations


def damerau_levenshtein(a: str, b: str, cutoff: int) -> int:
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


__all__ = ["damerau_levenshtein"]
