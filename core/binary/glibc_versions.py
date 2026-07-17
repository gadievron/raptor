"""Shared glibc-version parsing + comparison helpers.

Callers compare glibc versions across the loose real-world formats
operators see (``"2.35"``, ``"2.43.1"``, ``"2.35-0ubuntu3.4"``,
whitespace tolerated). ``search_major_minor`` additionally accepts
strings wrapped in ldd/apt output (``"ldd (Ubuntu GLIBC 2.38-0ubuntu3)
2.38"``).

The parser refuses to raise: malformed input returns ``None`` (or a
zero tuple) so a garbled version silently doesn't match any record.
Non-numeric components collapse to 0. Distro suffixes are stripped
per-component (real-world ``"2.35-0ubuntu3.4"`` → ``(2, 35, 4)``)
so a ``>=2.32`` predicate matches a distro-suffixed 2.35 — without
this, hardening-branch selectors misclassify safe-linking targets.
"""

from __future__ import annotations

import re
from typing import Optional


_VERSION_RE = re.compile(r"^\s*(\d+)(?:\.(\d+))?(?:\.\d+)?\s*$")


def parse_major_minor(raw: Optional[str]) -> Optional[tuple[int, int]]:
    """Parse a glibc version string into ``(major, minor)``.

    Returns ``None`` for empty / malformed input. Patch-level components
    are dropped — glibc technique-differentiation lives at the minor
    boundary (2.32 introduced safe-linking; 2.35 removed __free_hook),
    not at patch releases.
    """
    if not raw:
        return None
    m = _VERSION_RE.match(str(raw))
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) is not None else 0
    return (major, minor)


_SEARCH_RE = re.compile(r"(\d+)\.(\d+)", re.ASCII)


def search_major_minor(text: Optional[str]) -> Optional[tuple[int, int]]:
    """Extract ``(major, minor)`` from the first ``\\d+\\.\\d+``
    occurrence in ``text``.

    Companion to :func:`parse_major_minor` for callers that receive
    the version wrapped in a larger string — ``ldd --version`` prints
    ``"ldd (Ubuntu GLIBC 2.38-0ubuntu3) 2.38"`` and the anchored
    parser rejects the whole thing. This helper scans for the version
    token instead.

    Prefers substring semantics because the real-world producers
    (``ldd``, ``apt list``, ``/lib/*/libc.so.6`` symlink target)
    surround the version with distribution boilerplate. Returns
    ``None`` on empty input or no digit-dot-digit occurrence.
    """
    if not text:
        return None
    m = _SEARCH_RE.search(str(text))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))


_LEADING_DIGITS_RE = re.compile(r"^\s*(\d+)")


def parse_version(raw: str) -> tuple[int, ...]:
    """Parse a version string of arbitrary depth into a tuple.

    Kept for hardening.py's predicate evaluator which compares
    variable-depth versions. Distro / vendor suffixes on any component
    (``"2.35-0ubuntu3.4"`` → ``(2, 35, 4)``, ``"2.32-9.fc35"`` →
    ``(2, 32, 9)``) are stripped by keeping the leading digit run of
    each dotted component. A component with no leading digits collapses
    to ``0``. Empty input returns ``()``.

    Suffix-stripping matters at the hardening-branch boundary: without
    it, a real-world glibc-2.35 target reports as ``(2, 0, 4)`` and
    fails a ``glibc>=2.32`` predicate, silently feeding pre-safe-linking
    tcache advice on a safe-linking target — exactly the misdirection
    hardening branches exist to prevent.
    """
    if not raw:
        return ()
    parts: list[int] = []
    for p in raw.split("."):
        m = _LEADING_DIGITS_RE.match(p)
        parts.append(int(m.group(1)) if m else 0)
    return tuple(parts)


def compare_versions(
    a: tuple[int, ...], b: tuple[int, ...],
) -> int:
    """Return -1 / 0 / +1 for a<b / a==b / a>b.

    Shorter tuples pad with 0 so ``(2, 35) == (2, 35, 0)``.
    """
    n = max(len(a), len(b))
    pa = a + (0,) * (n - len(a))
    pb = b + (0,) * (n - len(b))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def resolve_greatest_leq(
    target: Optional[tuple[int, int]],
    candidates: list[tuple[int, int]],
) -> Optional[tuple[int, int]]:
    """Pick the greatest candidate ``≤ target``.

    Returns ``None`` when ``target`` is None (no filter) or no candidate
    is ``≤ target`` (target predates every authored entry).

    Callers pass ``candidates`` as the list of versions they have
    content for; this helper picks the operator-authored entry that
    covers the target's mitigation posture.
    """
    if target is None or not candidates:
        return None
    best: Optional[tuple[int, int]] = None
    for c in candidates:
        if c > target:
            continue
        if best is None or c > best:
            best = c
    return best


__all__ = [
    "parse_major_minor",
    "parse_version",
    "compare_versions",
    "resolve_greatest_leq",
]
