"""NuGet version comparator.

NuGet versions are SemVer 2.0 with a few quirks:
  - 4-part versions (``1.2.3.4``) — legacy AssemblyVersion shape — are
    accepted; SemVer 2 is 3 parts max but NuGet allows 4.
  - Pre-release tags (``-alpha``, ``-rc1``) sort *before* their release.
  - Build metadata (``+commit-sha``) is ignored for ordering.
  - Leading ``v`` is tolerated.

Reference: https://learn.microsoft.com/en-us/nuget/concepts/package-versioning
"""

from __future__ import annotations

from typing import List, Tuple


def compare(a: str, b: str) -> int:
    pa, qa = _split(a)
    pb, qb = _split(b)
    # Compare base-version segments numerically.
    max_len = max(len(pa), len(pb))
    while len(pa) < max_len:
        pa.append(0)
    while len(pb) < max_len:
        pb.append(0)
    for x, y in zip(pa, pb):
        if x != y:
            return -1 if x < y else 1
    # Pre-release: empty wins over non-empty (release > pre-release).
    if not qa and not qb:
        return 0
    if not qa:
        return 1
    if not qb:
        return -1
    return _cmp_prerelease(qa, qb)


def _split(version: str) -> Tuple[List[int], List[str]]:
    """Split a version into ``(numeric_segments, prerelease_segments)``.

    Strips leading ``v`` and any ``+build`` metadata.
    """
    s = version.strip().lstrip("v")
    s = s.split("+", 1)[0]                  # drop build metadata
    if "-" in s:
        base, pre = s.split("-", 1)
    else:
        base, pre = s, ""
    nums: List[int] = []
    for piece in base.split("."):
        try:
            nums.append(int(piece))
        except ValueError:
            # Non-numeric segment in the base — treat as 0 with a
            # tail-string penalty.
            nums.append(0)
    pre_segs = [p.lower() for p in pre.split(".")] if pre else []
    return nums, pre_segs


def _cmp_prerelease(a: List[str], b: List[str]) -> int:
    """SemVer pre-release comparison: per-segment, numeric < non-numeric;
    longer wins on tie."""
    for sa, sb in zip(a, b):
        a_is_num = sa.isdigit()
        b_is_num = sb.isdigit()
        if a_is_num and b_is_num:
            ia, ib = int(sa), int(sb)
            if ia != ib:
                return -1 if ia < ib else 1
        elif a_is_num != b_is_num:
            return -1 if a_is_num else 1
        else:
            if sa != sb:
                return -1 if sa < sb else 1
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return 0


__all__ = ["compare"]
