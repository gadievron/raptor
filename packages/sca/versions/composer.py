"""Composer (PHP / Packagist) version comparator.

Composer's grammar is largely SemVer 2.0 with a few extras:
  - Branch versions (``dev-master``, ``dev-some-branch``) — these are
    incomparable in any meaningful order; we treat all ``dev-*``
    versions as a single "dev" bucket that sorts AFTER any released
    version of the same base (Composer's documented preference for
    "latest-tag-or-dev" workflows).
  - Optional leading ``v`` (``v1.2.3``).
  - 4-part versions (``1.2.3.4``) — Composer accepts them.
  - Stability suffixes: ``-stable`` > ``-rc`` > ``-beta`` > ``-alpha``
    > ``-dev``. We rank them numerically.

Reference: https://getcomposer.org/doc/articles/versions.md
"""

from __future__ import annotations

import re
from typing import List, Tuple


_STABILITY_RANK = {
    "dev": 0,
    "alpha": 1, "a": 1,
    "beta": 2, "b": 2,
    "rc": 3, "pre": 3,
    "stable": 4, "release": 4, "": 4,
}


def compare(a: str, b: str) -> int:
    da = _is_dev(a)
    db = _is_dev(b)
    if da and db:
        # Both dev-*: lex-sort the branch names. Not a great answer but
        # ranges over dev versions are vanishingly rare.
        return (a > b) - (a < b)
    if da:
        return 1
    if db:
        return -1

    nums_a, stab_a, stab_idx_a = _split(a)
    nums_b, stab_b, stab_idx_b = _split(b)
    max_len = max(len(nums_a), len(nums_b))
    while len(nums_a) < max_len:
        nums_a.append(0)
    while len(nums_b) < max_len:
        nums_b.append(0)
    for x, y in zip(nums_a, nums_b):
        if x != y:
            return -1 if x < y else 1
    if stab_a != stab_b:
        return -1 if stab_a < stab_b else 1
    if stab_idx_a != stab_idx_b:
        return -1 if stab_idx_a < stab_idx_b else 1
    return 0


def _is_dev(v: str) -> bool:
    return v.strip().lower().startswith("dev-")


_STAB_RE = re.compile(
    r"^(?P<base>v?\d[\d.]*)(?:[-.]?(?P<stab>"
    r"alpha|beta|rc|pre|stable|release|dev|a|b)(?P<idx>\d*))?",
    re.IGNORECASE,
)


def _split(version: str) -> Tuple[List[int], int, int]:
    """Return (numeric segments, stability rank, stability index)."""
    s = version.strip()
    m = _STAB_RE.match(s)
    if not m:
        return [0], _STABILITY_RANK["stable"], 0
    base = m.group("base").lstrip("v")
    nums: List[int] = []
    for piece in base.split("."):
        try:
            nums.append(int(piece))
        except ValueError:
            nums.append(0)
    stab_word = (m.group("stab") or "").lower()
    rank = _STABILITY_RANK.get(stab_word, _STABILITY_RANK["stable"])
    idx_raw = m.group("idx") or "0"
    try:
        idx = int(idx_raw)
    except ValueError:
        idx = 0
    return nums, rank, idx


__all__ = ["compare"]
