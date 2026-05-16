"""Shared stable-semver filter for upstream-latest lookups.

Both ``github_releases`` and ``oci_tags`` (and future modules
like ``helm_index``) need the same logic: given a list of tag /
version strings, pick the highest one that's stable-semver-
shaped, rejecting pre-releases / dev shapes / non-version refs.

Centralising means one source of truth for what counts as
"stable" — adding a shape (e.g. NuGet 5-part) lands once and
every registry kind benefits."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

# Stable-semver shapes we accept:
#   * ``1``, ``1.2``, ``1.2.3``, ``1.2.3.4`` (1-4 part numeric)
#   * Optional leading ``v`` (Go-style / GitHub tag convention)
# Rejected:
#   * Pre-release suffixes (``-rc.1``, ``-beta``, ``-alpha``)
#   * PEP440 dev / pre shapes (``.dev0``, ``b1``, ``rc1`` inline)
#   * Date-shaped tags (``2024-01-15``)
#   * Branch / commit refs (``main``, ``deadbeef``)
#   * Container variant suffixes (``3.12-bookworm``, ``3.12-slim``)
_STABLE_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$"
)


def parse_stable(tag: str) -> Optional[Tuple[int, ...]]:
    """Return the numeric tuple if ``tag`` is stable-semver, else None.

    Tuple ordering matches lexical comparison: ``(1, 17, 21) >
    (1, 17, 4)`` naturally gives the right answer across 1-4 part
    versions because Python tuple comparison is element-wise.
    """
    match = _STABLE_RE.match(tag)
    if match is None:
        return None
    return tuple(int(g) for g in match.groups() if g is not None)


def highest_stable(tags: List[str]) -> Optional[str]:
    """Return the highest stable-semver tag from ``tags``, or None
    if no tag matches the stable shape.

    Callers raise their own ``NoStableVersionsFound`` (or similar)
    on None — keeps this function pure / testable without
    exception coupling.
    """
    stable: List[Tuple[Tuple[int, ...], str]] = []
    for tag in tags:
        parts = parse_stable(tag)
        if parts is None:
            continue
        stable.append((parts, tag))
    if not stable:
        return None
    return max(stable)[1]
