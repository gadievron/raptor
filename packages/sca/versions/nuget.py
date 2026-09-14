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

import re

_NUGET_CHARSET_RE = re.compile(r"[0-9A-Za-z.+-]+")


def compare(a: str, b: str) -> int:
    pa, qa = _split(a)
    pb, qb = _split(b)
    # Compare base-version segments numerically.
    max_len = max(len(pa), len(pb))
    while len(pa) < max_len:
        pa.append(0)
    while len(pb) < max_len:
        pb.append(0)
    for x, y in zip(pa, pb, strict=True):
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


def _split(version: str) -> tuple[list[int], list[str]]:
    """Split a version into ``(numeric_segments, prerelease_segments)``.

    Strips leading ``v`` and any ``+build`` metadata.
    """
    s = version.strip().lstrip("vV")
    # NuGet's whole version charset (SemVer 2 + legacy 4-part): digits,
    # ASCII letters, ``.``, ``-``, ``+``. Enforced over the FULL string
    # — checking only the leading segment let digit-led garbage
    # (``9.9.9 || curl …``, ``9.9.9;curl``) through to the lenient
    # tail-penalty ordering, where it never raised and therefore
    # probed "parseable" at the findings layer, winning advisory
    # combines over real fix versions.
    if not s or not _NUGET_CHARSET_RE.fullmatch(s):
        msg = f"not a NuGet version: {version!r} (illegal characters)"
        raise ValueError(msg)
    s = s.split("+", 1)[0]                  # drop build metadata
    if "-" in s:
        base, pre = s.split("-", 1)
    else:
        base, pre = s, ""
    # NuGet versions always lead with a numeric segment (SemVer 2 /
    # legacy AssemblyVersion both require it). Raising here — instead
    # of best-effort ordering arbitrary strings — keeps the findings
    # layer's parse probe meaningful: a git SHA or crafted garbage
    # ``fixed`` entry must not probe "parseable" and steer the
    # advisory combine / fix planner at a non-version. Later
    # non-numeric segments keep the lenient 0-with-tail-penalty
    # handling (seen in odd registry entries).
    first = base.split(".", 1)[0]
    if not (first.isascii() and first.isdigit()):
        msg = f"not a NuGet version: {version!r} (no leading numeric segment)"
        raise ValueError(msg)
    nums: list[int] = []
    for piece in base.split("."):
        try:
            nums.append(int(piece))
        except ValueError:
            # Non-numeric segment in the base — treat as 0 with a
            # tail-string penalty.
            nums.append(0)
            if not pre:
                pre = piece.lower()
    pre_segs = [p.lower() for p in pre.split(".")] if pre else []
    return nums, pre_segs


def _cmp_prerelease(a: list[str], b: list[str]) -> int:
    """SemVer pre-release comparison: per-segment, numeric < non-numeric;
    longer wins on tie."""
    for sa, sb in zip(a, b, strict=False):
        a_is_num = sa.isdigit()
        b_is_num = sb.isdigit()
        if a_is_num and b_is_num:
            ia, ib = int(sa), int(sb)
            if ia != ib:
                return -1 if ia < ib else 1
        elif a_is_num != b_is_num:
            return -1 if a_is_num else 1
        elif sa != sb:
            return -1 if sa < sb else 1
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return 0


__all__ = ["compare"]
