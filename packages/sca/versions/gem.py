"""RubyGems version comparator.

RubyGems versions follow a custom grammar — basically dot-separated
segments where each segment is either an integer or a pre-release
string. Pre-releases sort *before* their release counterparts:

  ``1.0.0.pre1 < 1.0.0.pre2 < 1.0.0``

Reference: https://docs.ruby-lang.org/en/3.0/Gem/Version.html

Numeric segments compare numerically; string segments compare
lexicographically; a string segment is "less than" a numeric segment
at the same position (this is what makes pre-releases sort earlier).

We aim for compatibility with the official Gem::Version#<=> behaviour
on the cases that matter for OSV range matching. Edge cases involving
trailing zeros (``1.0.0`` == ``1.0`` per RubyGems) are handled.
"""

from __future__ import annotations

import re
from typing import Union


_Segment = Union[int, str]

# Gem::Version's ANCHORED_VERSION_PATTERN: an optional version whose
# FIRST segment is purely numeric, followed by dot-separated
# alphanumeric segments and an optional dash-led platform/pre tail.
# Rejecting everything else matches the real ecosystem (RubyGems
# itself refuses these strings), and it is what makes the findings
# layer's parse probe meaningful here: a comparator that best-effort
# orders ANY string reports git SHAs / crafted garbage "parseable",
# letting them outrank real fix versions in advisory combines.
# The optional version body carries its trailing whitespace INSIDE
# the optional group: the naive ``\s*(V)?\s*\Z`` puts two unbounded
# whitespace spans around the optional body, and an advisory-derived
# string that is one long whitespace run makes the engine try every
# split of the run between them — superlinear in the string length.
# Match set and the capture groups are unchanged (body absent: the
# two spans collapse to one).
_ANCHORED_VERSION_RE = re.compile(
    r"\s*(?:(\d+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?)"
    r"\s*)?\Z"
)


def compare(a: str, b: str) -> int:
    """Return -1 / 0 / 1 per the standard comparator convention.

    Raises ``ValueError`` (normalised to ``VersionError`` by the
    dispatcher) when either input does not match RubyGems' own
    version grammar.
    """
    sa = _segments(a)
    sb = _segments(b)
    # Pad with 0s so equal-numeric tails compare equal (``1.0.0`` == ``1.0``).
    max_len = max(len(sa), len(sb))
    while len(sa) < max_len:
        sa.append(0)
    while len(sb) < max_len:
        sb.append(0)
    for x, y in zip(sa, sb, strict=True):
        c = _cmp_segment(x, y)
        if c != 0:
            return c
    return 0


def _segments(version: str) -> list[_Segment]:
    """Split a Gem version into its numeric/string segments.

    Splits on ``.`` and on transitions between digits and letters
    (``1.0.0pre1`` → ``[1, 0, 0, "pre", 1]``).
    """
    if _ANCHORED_VERSION_RE.fullmatch(version) is None:
        msg = f"not a RubyGems version: {version!r}"
        raise ValueError(msg)
    out: list[_Segment] = []
    for part in version.strip().split("."):
        for sub in re.findall(r"\d+|[A-Za-z]+", part):
            if sub.isdigit():
                out.append(int(sub))
            else:
                out.append(sub.lower())
    return out


def _cmp_segment(x: _Segment, y: _Segment) -> int:
    if isinstance(x, int) and isinstance(y, int):
        return (x > y) - (x < y)
    if isinstance(x, str) and isinstance(y, str):
        return (x > y) - (x < y)
    # Mixed: string < int (pre-release sorts before release).
    if isinstance(x, str):
        return -1
    return 1


__all__ = ["compare"]
