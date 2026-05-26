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

# Container variant shape:
#   * ``<semver>-<variant>`` where ``<variant>`` is one or more
#     lowercase-word-or-dash segments (slim / alpine / bookworm /
#     jdk / jre / slim-bookworm / jdk-alpine / ...).
# We deliberately allow dashes IN the variant so compound shapes
# (``slim-bookworm``, ``jre-alpine``) are captured as one variant
# string, not split into ``slim`` + ``bookworm``. The bumper then
# filters the registry tag list to tags carrying THE SAME variant
# string so ``python:3.9-slim-bookworm`` only ever proposes
# ``python:<latest>-slim-bookworm`` — never accidentally
# ``python:<latest>-slim`` (Debian-default but might not exist).
_VARIANT_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?"
    r"-([a-z][a-z0-9-]*)$"
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


def parse_stable_with_variant(
    tag: str,
) -> Optional[Tuple[Tuple[int, ...], str]]:
    """Return ``(version_tuple, variant_suffix)`` for either:

      * bare stable semver — ``"3.12"`` → ``((3, 12), "")``
      * variant-suffixed semver — ``"3.12-slim-bookworm"`` →
        ``((3, 12), "slim-bookworm")``

    Returns ``None`` when the tag matches neither shape (date
    tag, branch ref, pre-release, etc.).

    The empty-string variant for bare semver lets callers branch
    on "is this variant-tagged?" without needing a sentinel.
    """
    bare = parse_stable(tag)
    if bare is not None:
        return bare, ""
    match = _VARIANT_RE.match(tag)
    if match is None:
        return None
    nums = tuple(int(g) for g in match.groups()[:4] if g is not None)
    variant = match.group(5)
    return nums, variant


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


def highest_stable_with_variant(
    tags: List[str], variant: str,
) -> Optional[str]:
    """Return the highest tag matching ``<stable-semver>-<variant>``
    in ``tags``, or None if no tag with that variant suffix exists.

    Pass ``variant=""`` to get the same result as :func:`highest_stable`
    (bare semver only). Otherwise the variant string must match
    exactly — ``"slim-bookworm"`` won't match ``"slim"`` tags and
    vice-versa.

    This is the load-bearing piece of the bumper's variant-aware
    Dockerfile FROM handling: ``python:3.9-slim`` looks up tags
    filtered to ``<x>-slim`` shape, finds ``python:3.12-slim``, and
    proposes that.
    """
    stable: List[Tuple[Tuple[int, ...], str]] = []
    for tag in tags:
        parsed = parse_stable_with_variant(tag)
        if parsed is None:
            continue
        nums, v = parsed
        if v != variant:
            continue
        stable.append((nums, tag))
    if not stable:
        return None
    return max(stable)[1]
