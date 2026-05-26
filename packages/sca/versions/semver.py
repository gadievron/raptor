"""Semver comparator.

Used by npm, Cargo, Go (with leading 'v' tolerated). Implements the
ordering rules from https://semver.org/ — three-component MAJOR.MINOR.PATCH
plus optional pre-release and build-metadata suffixes. Build metadata is
ignored for ordering (per spec). Pre-release order is dot-separated
identifier comparison (numeric < non-numeric).

For Go pseudo-versions (e.g., v0.0.0-20210320205559-abc123), we compare
on the full string after stripping the leading 'v'; the timestamp segment
is lexicographically ordered by spec.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple


# v-prefixed (Go), or plain semver, with optional pre-release and build.
# Accepts short forms (1, 1.2, 1.2.3); missing components default to 0.
# Strict semver requires three components but real-world advisory data
# (and Go pseudo-versions) often ships shorter forms.
_SEMVER_RE = re.compile(
    r"""
    ^
    v?                                # tolerate leading v (Go)
    (?P<major>\d+)
    (?:\.(?P<minor>\d+))?
    (?:\.(?P<patch>\d+))?
    (?:-(?P<pre>[0-9A-Za-z.-]+))?     # pre-release
    (?:\+(?P<build>[0-9A-Za-z.-]+))?  # build metadata (ignored for ordering)
    $
    """,
    re.VERBOSE,
)


def parse(version: str) -> Tuple[int, int, int, Optional[List[str]]]:
    """Parse version into (major, minor, patch, pre).

    Missing minor / patch default to 0. pre is a list of dot-separated
    identifiers, or None when absent. Build metadata is dropped (per
    semver spec, ignored for ordering).
    """
    m = _SEMVER_RE.match(version.strip())
    if not m:
        raise ValueError(f"not a semver version: {version!r}")
    pre = m.group("pre")
    return (
        int(m.group("major")),
        int(m.group("minor") or "0"),
        int(m.group("patch") or "0"),
        pre.split(".") if pre else None,
    )


def compare(a: str, b: str) -> int:
    """Return -1, 0, 1 per semver ordering."""
    if a == b:
        return 0
    pa = parse(a)
    pb = parse(b)
    # Compare major.minor.patch numerically.
    for x, y in zip(pa[:3], pb[:3]):
        if x != y:
            return -1 if x < y else 1
    # Pre-release: a version with pre is < the same version without.
    a_pre, b_pre = pa[3], pb[3]
    if a_pre is None and b_pre is None:
        return 0
    if a_pre is None:
        return 1
    if b_pre is None:
        return -1
    # Both pre — compare identifier by identifier.
    for ai, bi in zip(a_pre, b_pre):
        c = _compare_identifier(ai, bi)
        if c != 0:
            return c
    # All compared equal so far — shorter wins per spec.
    if len(a_pre) != len(b_pre):
        return -1 if len(a_pre) < len(b_pre) else 1
    return 0


def _compare_identifier(a: str, b: str) -> int:
    """Compare two pre-release identifiers per semver spec.

    Numeric identifiers always have lower precedence than alphanumeric ones.
    Numeric identifiers are compared numerically; alphanumeric ones lexically.
    """
    a_num = a.isdigit()
    b_num = b.isdigit()
    if a_num and b_num:
        ai, bi = int(a), int(b)
        if ai == bi:
            return 0
        return -1 if ai < bi else 1
    if a_num and not b_num:
        return -1
    if b_num and not a_num:
        return 1
    if a == b:
        return 0
    return -1 if a < b else 1


# ---------------------------------------------------------------------------
# Range bounds extraction (SCA bounded-pinning: corridor floor/ceiling)
# ---------------------------------------------------------------------------

def _loose_components(operand: str) -> Optional[Tuple[int, int, int, int]]:
    """Parse a possibly-partial version into ``(major, minor, patch,
    ncomp)`` where ``ncomp`` is the count of leading concrete numeric
    components. ``x`` / ``X`` / ``*`` and missing trailing components are
    treated as absent (default 0). Returns None for a bare wildcard or
    anything non-numeric (caller treats as 'no bound')."""
    core = re.split(r"[-+]", operand.strip().lstrip("v"), maxsplit=1)[0]
    nums: List[int] = []
    for part in core.split("."):
        if part in ("x", "X", "*", ""):
            break
        if not part.isdigit():
            return None
        nums.append(int(part))
    if not nums:
        return None
    return (nums[0],
            nums[1] if len(nums) > 1 else 0,
            nums[2] if len(nums) > 2 else 0,
            len(nums))


def _join(c: Tuple[int, int, int, int]) -> str:
    return f"{c[0]}.{c[1]}.{c[2]}"


def _caret_ceiling(c: Tuple[int, int, int, int]) -> str:
    """Exclusive upper bound for ``^`` per node-semver (allow changes that
    don't modify the left-most non-zero element)."""
    major, minor, patch, ncomp = c
    if major > 0 or ncomp == 1:        # ^1.2.3 / ^1 / ^1.2 -> <(major+1).0.0
        return f"{major + 1}.0.0"
    if minor > 0 or ncomp == 2:        # ^0.2.3 / ^0.2 / ^0.0 -> <0.(minor+1).0
        return f"0.{minor + 1}.0"
    return f"0.0.{patch + 1}"          # ^0.0.3 -> <0.0.4


def _tilde_ceiling(c: Tuple[int, int, int, int]) -> str:
    """Exclusive upper bound for ``~``."""
    major, minor, _patch, ncomp = c
    if ncomp >= 2:                     # ~1.2.3 / ~1.2 -> <1.(minor+1).0
        return f"{major}.{minor + 1}.0"
    return f"{major + 1}.0.0"          # ~1 -> <2.0.0


def _tightest(versions: List[str], want_max: bool) -> str:
    best = versions[0]
    for v in versions[1:]:
        c = compare(v, best)
        if (want_max and c > 0) or (not want_max and c < 0):
            best = v
    return best


def bounds(spec: str) -> Tuple[Optional[str], Optional[str]]:
    """Best-effort ``(floor, ceiling)`` for an npm/Cargo semver range.

    ``floor`` = tightest inclusive lower bound; ``ceiling`` = tightest
    exclusive upper bound (the version the range stops *before*). Used by
    SCA bounded-pinning to give harden a comparable baseline for a ranged
    dep (the floor) and to keep a bump inside the declared corridor (the
    ceiling).

    Handles caret ``^``, tilde ``~``, comparators ``>=`` ``>`` ``<=``
    ``<``, x-ranges (``2.x`` / ``2`` / ``2.*``), and simple hyphen ranges.
    A fully-specified exact version (``2.7.0`` / ``=2.7.0``) contributes
    NO bound — it's a pin, not a corridor. Returns ``(None, None)`` for OR
    ranges (``||``), bare wildcards, or anything unparseable — callers
    treat that as 'no corridor recorded'.
    """
    spec = spec.strip()
    if not spec or "||" in spec:
        return None, None
    if " - " in spec:                  # hyphen range: capture floor, skip ceiling
        c = _loose_components(spec.split(" - ", 1)[0])
        return (_join(c) if c else None), None

    lowers: List[str] = []
    uppers: List[str] = []
    for tok in spec.split():
        m = re.match(r"^(>=|<=|>|<|=|\^|~)?\s*(.*)$", tok)
        if m is None:
            continue
        op, operand = (m.group(1) or ""), m.group(2).strip()
        if not operand or operand in ("*", "x", "X"):
            continue
        if op == "^":
            c = _loose_components(operand)
            if c:
                lowers.append(_join(c))
                uppers.append(_caret_ceiling(c))
        elif op == "~":
            c = _loose_components(operand)
            if c:
                lowers.append(_join(c))
                uppers.append(_tilde_ceiling(c))
        elif op in (">=", ">"):
            c = _loose_components(operand)
            if c:
                lowers.append(_join(c))
        elif op in ("<", "<="):
            c = _loose_components(operand)
            if c:
                uppers.append(_join(c))
        else:                          # ``=`` or bare: exact OR x-range
            c = _loose_components(operand)
            if c is None:
                continue
            if c[3] >= 3 and not any(ch in operand for ch in "xX*"):
                continue               # fully-specified exact: no bound
            lowers.append(_join(c))
            uppers.append(f"{c[0] + 1}.0.0" if c[3] == 1
                          else f"{c[0]}.{c[1] + 1}.0")

    floor = _tightest(lowers, want_max=True) if lowers else None
    ceiling = _tightest(uppers, want_max=False) if uppers else None
    return floor, ceiling
