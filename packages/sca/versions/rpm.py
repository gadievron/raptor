"""RPM (Red Hat) version comparator.

Implements ``rpmvercmp`` ordering over ``[epoch:]version[-release]``
strings as used by Red Hat / Fedora packages and OSV ``Red Hat``
advisories:

  - ``epoch``: optional non-negative integer, default 0; compared
    first, numerically — a higher epoch always wins.
  - ``version`` and ``release`` each go through ``rpmvercmp``: walk
    the string in alternating digit and alpha segments (any other
    character is a separator). Digit segments compare numerically
    (leading zeros stripped, longer run wins); alpha segments compare
    lexically; a digit segment beats an alpha segment at the same
    position.
  - ``~`` sorts before everything, including end-of-string
    (``1.0~rc1 < 1.0``); ``^`` sorts after end-of-string but before
    any other continuation (``1.0 < 1.0^git1 < 1.0.1``).

Digit segments are compared as strings (leading-zero strip + length +
lexicographic), so arbitrarily long hostile digit runs cost O(n) and
never hit ``int()`` conversion limits.
"""

from __future__ import annotations


def _split_evr(evr: str) -> tuple[int, str, str]:
    """Split ``[epoch:]version[-release]``; raises ``ValueError`` on a
    non-numeric epoch or an empty version."""
    v = evr.strip()
    epoch = 0
    if ":" in v:
        head, _, rest = v.partition(":")
        if not (head.isascii() and head.isdigit()) or len(head) > 32:
            msg = f"invalid RPM epoch in {evr!r}"
            raise ValueError(msg)
        epoch = int(head)
        v = rest
    # RPM forbids ``-`` inside the version proper; the first ``-``
    # separates version from release.
    version, _, release = v.partition("-")
    if not version:
        msg = f"empty RPM version in {evr!r}"
        raise ValueError(msg)
    return epoch, version, release


def _is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def _is_alpha(c: str) -> bool:
    return "a" <= c <= "z" or "A" <= c <= "Z"


def _rpmvercmp(a: str, b: str) -> int:  # noqa: PLR0911, PLR0912
    ia, ib = 0, 0
    la, lb = len(a), len(b)
    while ia < la or ib < lb:
        # Skip separators (anything that is not alnum / '~' / '^').
        while ia < la and not (_is_digit(a[ia]) or _is_alpha(a[ia])
                               or a[ia] in "~^"):
            ia += 1
        while ib < lb and not (_is_digit(b[ib]) or _is_alpha(b[ib])
                               or b[ib] in "~^"):
            ib += 1
        a_tilde = ia < la and a[ia] == "~"
        b_tilde = ib < lb and b[ib] == "~"
        if a_tilde or b_tilde:
            if a_tilde and b_tilde:
                ia += 1
                ib += 1
                continue
            return -1 if a_tilde else 1
        a_caret = ia < la and a[ia] == "^"
        b_caret = ib < lb and b[ib] == "^"
        if a_caret or b_caret:
            if a_caret and b_caret:
                ia += 1
                ib += 1
                continue
            # ``^`` beats end-of-string but loses to any other
            # continuation ("1.0 < 1.0^git1 < 1.0.1").
            if a_caret:
                return 1 if ib >= lb else -1
            return -1 if ia >= la else 1
        if ia >= la or ib >= lb:
            break
        # Grab the next segment from each side.
        if _is_digit(a[ia]):
            if not _is_digit(b[ib]):
                return 1                    # numeric beats alpha
            ja, jb = ia, ib
            while ja < la and _is_digit(a[ja]):
                ja += 1
            while jb < lb and _is_digit(b[jb]):
                jb += 1
            sa = a[ia:ja].lstrip("0")
            sb = b[ib:jb].lstrip("0")
            if len(sa) != len(sb):
                return -1 if len(sa) < len(sb) else 1
            if sa != sb:
                return -1 if sa < sb else 1
            ia, ib = ja, jb
        else:
            if _is_digit(b[ib]):
                return -1                   # alpha loses to numeric
            ja, jb = ia, ib
            while ja < la and _is_alpha(a[ja]):
                ja += 1
            while jb < lb and _is_alpha(b[jb]):
                jb += 1
            sa, sb = a[ia:ja], b[ib:jb]
            if sa != sb:
                return -1 if sa < sb else 1
            ia, ib = ja, jb
    # One side exhausted (separators already skipped): the side with
    # remaining content is newer.
    a_left = ia < la
    b_left = ib < lb
    if a_left == b_left:
        return 0
    return 1 if a_left else -1


def compare(a: str, b: str) -> int:
    """Return -1, 0, or 1 for ``a < b``, ``a == b``, ``a > b`` per RPM
    ``epoch:version-release`` ordering."""
    if a == b:
        return 0
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _rpmvercmp(va, vb)
    if c != 0:
        return c
    # Missing release compares as older than any explicit release
    # ("1.0" < "1.0-1"), matching rpmvercmp over the raw strings.
    return _rpmvercmp(ra, rb)


__all__ = ["compare"]
