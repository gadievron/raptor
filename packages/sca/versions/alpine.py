"""Alpine (apk) version comparator.

Implements apk-tools version ordering for the shapes that appear in
real Alpine package versions and OSV ``Alpine`` advisories:

    version   = digits ("." digits)* [letter] ("_" suffix [digits])* ["-r" digits]
    suffix    = alpha | beta | pre | rc          (pre-release, sorts BEFORE bare)
              | cvs | svn | git | hg | p         (post-release, sorts AFTER bare)

Ordering, per apk-tools' ``version.c``:

  1. Numeric components compare numerically, pairwise; when a common
     prefix is equal, the version with additional numeric components
     is newer (``1.2 < 1.2.0 < 1.2.1``).
  2. A single trailing letter sorts after the bare version
     (``1.2 < 1.2a < 1.2b``).
  3. ``_alpha``/``_beta``/``_pre``/``_rc`` sort before the unsuffixed
     version (in that order); ``_cvs``/``_svn``/``_git``/``_hg``/``_p``
     sort after it (in that order). A trailing number on the suffix
     breaks ties (``_rc1 < _rc2``).
  4. ``-rN`` pkgrel compares numerically last (absent = 0).

Anything outside this grammar raises ``ValueError`` (the versions
dispatcher normalises to ``VersionError``), so unmatchable shapes are
skipped by range-matching callers rather than guessed at.
"""

from __future__ import annotations

import re

# Pre-release suffixes get negative weights (sort before the bare
# version), post-release suffixes positive (sort after). Bare = 0.
_SUFFIX_WEIGHT = {
    "alpha": -4, "beta": -3, "pre": -2, "rc": -1,
    "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

# Digit-run cap: real Alpine components never exceed a handful of
# digits; bounding keeps ``int()`` off hostile-length runs.
_VERSION_RE = re.compile(
    r"""
    ^
    (?P<nums>\d{1,32}(?:\.\d{1,32})*)
    (?P<letter>[a-z])?
    (?P<suffixes>(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d{0,32})*)
    (?:-r(?P<pkgrel>\d{1,32}))?
    $
    """,
    re.VERBOSE,
)

_SUFFIX_RE = re.compile(r"_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d{0,32})")


def _parse(
    version: str,
) -> tuple[list[int], str, list[tuple[int, int]], int]:
    """Parse into ``(numeric_parts, letter, suffixes, pkgrel)``.

    ``suffixes`` is a list of ``(weight, number)`` pairs in declaration
    order. Raises ``ValueError`` for anything outside the apk grammar.
    """
    m = _VERSION_RE.match(version.strip())
    if not m:
        msg = f"not an Alpine (apk) version: {version!r}"
        raise ValueError(msg)
    nums = [int(p) for p in m.group("nums").split(".")]
    letter = m.group("letter") or ""
    suffixes = [
        (_SUFFIX_WEIGHT[name], int(num) if num else 0)
        for name, num in _SUFFIX_RE.findall(m.group("suffixes"))
    ]
    pkgrel = int(m.group("pkgrel")) if m.group("pkgrel") else 0
    return nums, letter, suffixes, pkgrel


def _cmp(a: int | str, b: int | str) -> int:
    if a == b:
        return 0
    return -1 if a < b else 1  # type: ignore[operator]


def compare(a: str, b: str) -> int:
    """Return -1, 0, or 1 for ``a < b``, ``a == b``, ``a > b`` per apk."""
    if a == b:
        return 0
    na, la, sa, ra = _parse(a)
    nb, lb, sb, rb = _parse(b)
    # 1. Numeric components, pairwise; extra components = newer.
    for xa, xb in zip(na, nb, strict=False):
        if xa != xb:
            return _cmp(xa, xb)
    if len(na) != len(nb):
        return _cmp(len(na), len(nb))
    # 2. Trailing letter: absent < 'a' < 'b' < ...
    if la != lb:
        return _cmp(la, lb)
    # 3. Suffix chain: compare pairwise on (weight, number). A missing
    #    suffix compares as the bare version (weight 0), so
    #    ``1.0_rc1 < 1.0 < 1.0_p1``.
    for (wa, qa), (wb, qb) in zip(sa, sb, strict=False):
        if wa != wb:
            return _cmp(wa, wb)
        if qa != qb:
            return _cmp(qa, qb)
    if len(sa) != len(sb):
        longer_w = (sa if len(sa) > len(sb) else sb)[
            min(len(sa), len(sb))][0]
        outcome = 1 if longer_w > 0 else -1
        return outcome if len(sa) > len(sb) else -outcome
    # 4. pkgrel.
    return _cmp(ra, rb)


__all__ = ["compare"]
