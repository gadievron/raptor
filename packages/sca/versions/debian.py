"""Debian (dpkg) version comparator.

Implements ``dpkg --compare-versions`` semantics (Debian Policy §5.6.12).
A version is ``[epoch:]upstream_version[-debian_revision]``:

  - ``epoch``: optional non-negative integer, default 0; compared first,
    numerically. A higher epoch always wins regardless of the rest.
  - ``upstream_version`` and ``debian_revision``: each compared with
    dpkg's ``verrevcmp`` — walk the string in alternating non-digit and
    digit runs. Digit runs compare numerically (leading zeros ignored,
    the longer run wins). Non-digit runs compare character by character
    with a modified order: ``~`` sorts *before* everything including
    end-of-string (so ``1.0~rc1`` < ``1.0``), letters sort before other
    punctuation, and otherwise by code point.

Used for OSV/SCA ordering of Debian/apt packages and by harden's
per-ecosystem version selection (``versions.compare("Debian", ...)``).
"""

from __future__ import annotations

from typing import Tuple


def _split(version: str) -> Tuple[int, str, str]:
    """Split into ``(epoch, upstream_version, debian_revision)``.

    Epoch is everything before the first ``:`` (must be numeric); the
    debian revision is everything after the *last* ``-``. Absent epoch
    defaults to 0; absent revision to ``""`` (which compares equal to
    ``"0"`` per dpkg).
    """
    v = version.strip()
    epoch = 0
    if ":" in v:
        head, _, rest = v.partition(":")
        if not head.isdigit():
            raise ValueError(f"invalid Debian epoch in {version!r}")
        epoch = int(head)
        v = rest
    if "-" in v:
        upstream, _, revision = v.rpartition("-")
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def _order(c: str) -> int:
    """Character ordering for dpkg's non-digit comparison.

    ``~`` is below everything (incl. end-of-string, which maps to 0);
    letters keep their code point; other punctuation sorts *after* all
    letters; digits are handled by the numeric path (return 0 here).
    """
    if c == "" or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """dpkg ``verrevcmp`` on a single component (upstream or revision)."""
    ia, ib = 0, 0
    la, lb = len(a), len(b)
    while ia < la or ib < lb:
        # Non-digit run: advance both in lockstep until either hits a digit.
        while (ia < la and not a[ia].isdigit()) or (ib < lb and not b[ib].isdigit()):
            oa = _order(a[ia] if ia < la else "")
            ob = _order(b[ib] if ib < lb else "")
            if oa != ob:
                return -1 if oa < ob else 1
            ia += 1
            ib += 1
        # Strip leading zeros, then compare the digit runs.
        while ia < la and a[ia] == "0":
            ia += 1
        while ib < lb and b[ib] == "0":
            ib += 1
        first_diff = 0
        while ia < la and a[ia].isdigit() and ib < lb and b[ib].isdigit():
            if first_diff == 0:
                first_diff = ord(a[ia]) - ord(b[ib])
            ia += 1
            ib += 1
        if ia < la and a[ia].isdigit():     # a's number has more digits
            return 1
        if ib < lb and b[ib].isdigit():
            return -1
        if first_diff != 0:
            return -1 if first_diff < 0 else 1
    return 0


def compare(a: str, b: str) -> int:
    """Return -1, 0, or 1 for ``a < b``, ``a == b``, ``a > b`` per dpkg.

    Raises ``ValueError`` when an epoch is present but non-numeric (the
    versions dispatcher normalises that to ``VersionError``).
    """
    if a == b:
        return 0
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _verrevcmp(ua, ub)
    if c != 0:
        return c
    return _verrevcmp(ra, rb)


__all__ = ["compare"]
