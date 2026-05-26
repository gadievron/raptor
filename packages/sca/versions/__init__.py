"""Per-ecosystem version comparators.

Used to match installed versions against OSV affected.ranges.events.
Each ecosystem has its own ordering rules; getting any of these subtly
wrong means missing CVEs or false-flagging clean versions.

Public API:
    compare(ecosystem, a, b) -> int
        Returns -1 if a < b, 0 if a == b, 1 if a > b.
        Raises VersionError if either is unparseable for the ecosystem.

    in_range(ecosystem, version, range_spec) -> bool
        True if version satisfies an OSV-style range spec
        (a list of {introduced, fixed, last_affected, limit} events).
"""

from __future__ import annotations

from typing import Any, Dict, List


class VersionError(ValueError):
    """Raised when a version string can't be parsed for the given ecosystem."""


def compare(ecosystem: str, a: str, b: str) -> int:
    """Return -1, 0, or 1 for a < b, a == b, a > b within the ecosystem's
    version semantics.

    Raises :class:`VersionError` when either ``a`` or ``b`` is
    unparseable for the ecosystem. The per-ecosystem comparators
    historically raised plain ``ValueError`` for unparseable input
    — the dispatcher normalises so callers' ``except VersionError``
    blocks fire (an ``except VersionError`` handler does NOT catch
    its parent ``ValueError``, so the un-normalised path leaked
    failures past intended handlers).

    The bug-class this catches: real-world OSV data sometimes
    carries cross-ecosystem ``fixed_versions`` (e.g. an npm
    advisory with a Ruby-shaped ``'7.0.8.3'`` fix entry). Without
    the normalisation, a single unparseable fix-version aborts
    the whole scan via ``findings._smallest_applicable_fix``;
    with it, the unparseable entry is skipped and the scan
    continues with the parseable ones.
    """
    cmp = _comparators.get(_canonical_ecosystem(ecosystem))
    if cmp is None:
        raise VersionError(f"no version comparator for ecosystem: {ecosystem}")
    try:
        return cmp(a, b)
    except VersionError:
        raise
    except ValueError as exc:
        raise VersionError(str(exc)) from exc


def in_range(ecosystem: str, version: str, events: List[Dict[str, str]]) -> bool:
    """Match an installed version against an OSV affected.ranges.events list.

    OSV semantics:
        - {introduced: X} starts a vulnerable interval at X (inclusive).
        - {fixed: X} ends a vulnerable interval before X (exclusive).
        - {last_affected: X} ends a vulnerable interval at X (inclusive).
        - {limit: X} bounds the range at X (rare; treated as upper exclusive).

    Events come paired (introduced + fixed/last_affected). The version is
    "in range" if it falls within ANY interval.

    Args:
        ecosystem: OSV ecosystem identifier.
        version: installed version string.
        events: OSV-style events array.

    Returns:
        True if version is in at least one vulnerable interval.
    """
    if not events:
        return False

    # Walk events, building intervals. Each "introduced" opens an interval;
    # the next "fixed"/"last_affected"/"limit" closes it. A dangling
    # "introduced" at end-of-list becomes an open-ended interval.
    intervals: List[tuple] = []  # (lower, lower_inclusive, upper, upper_inclusive)
    current_lower: str = "0"     # default: from the start
    current_lower_inclusive = True
    has_open_lower = False       # True iff an introduced has been seen
                                 # without a corresponding closer yet
    for ev in events:
        if "introduced" in ev:
            current_lower = ev["introduced"]
            current_lower_inclusive = True
            has_open_lower = True
        elif "fixed" in ev:
            intervals.append((current_lower, current_lower_inclusive,
                              ev["fixed"], False))
            current_lower = "0"
            has_open_lower = False
        elif "last_affected" in ev:
            intervals.append((current_lower, current_lower_inclusive,
                              ev["last_affected"], True))
            current_lower = "0"
            has_open_lower = False
        elif "limit" in ev:
            intervals.append((current_lower, current_lower_inclusive,
                              ev["limit"], False))
            current_lower = "0"
            has_open_lower = False

    # Dangling introduced (no closer): open-ended upper bound.
    if has_open_lower:
        intervals.append((current_lower, current_lower_inclusive, None, False))

    for lo, lo_incl, hi, hi_incl in intervals:
        if _within(ecosystem, version, lo, lo_incl, hi, hi_incl):
            return True
    return False


def _within(
    ecosystem: str,
    version: str,
    lo: str,
    lo_incl: bool,
    hi,           # str or None for open upper bound
    hi_incl: bool,
) -> bool:
    """Test version is in [lo, hi] / [lo, hi) / (lo, hi] / (lo, hi)."""
    # OSV uses "0" to mean "since the beginning"; some advisories ship a
    # literal "0" as the lower bound. compare() treats "0" as the lowest
    # value per ecosystem.
    if lo == "0":
        # Always ≥ 0 by convention; lower-bound check satisfied.
        pass
    else:
        c_lo = compare(ecosystem, version, lo)
        if lo_incl:
            if c_lo < 0:
                return False
        else:
            if c_lo <= 0:
                return False
    if hi is None:
        return True
    c_hi = compare(ecosystem, version, hi)
    if hi_incl:
        return c_hi <= 0
    return c_hi < 0


def _canonical_ecosystem(eco: str) -> str:
    """Normalise ecosystem strings — OSV uses 'PyPI', 'npm', 'Maven', 'Go',
    'crates.io' / 'Cargo', 'RubyGems', 'NuGet', 'Packagist'.
    """
    return _ECOSYSTEM_ALIASES.get(eco.lower(), eco)


_ECOSYSTEM_ALIASES = {
    "pypi": "PyPI",
    "python": "PyPI",
    "npm": "npm",
    "javascript": "npm",
    "node": "npm",
    "maven": "Maven",
    "java": "Maven",
    "gradle": "Maven",
    "go": "Go",
    "golang": "Go",
    "cargo": "Cargo",
    "crates.io": "Cargo",
    "rust": "Cargo",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "csharp": "NuGet",
    "dotnet": "NuGet",
    "packagist": "Packagist",
    "composer": "Packagist",
    "php": "Packagist",
}


# Comparators registered below by importing each per-ecosystem module.
_comparators: Dict[str, Any] = {}


def _register(ecosystem: str, fn) -> None:
    _comparators[ecosystem] = fn


# Wire concrete comparators (avoids circular imports).
from .semver import compare as _semver_compare        # noqa: E402
from .pep440 import compare as _pep440_compare        # noqa: E402
from .maven import compare as _maven_compare          # noqa: E402
from .gem import compare as _gem_compare              # noqa: E402
from .nuget import compare as _nuget_compare          # noqa: E402
from .composer import compare as _composer_compare    # noqa: E402

_register("npm", _semver_compare)
_register("Cargo", _semver_compare)        # mostly semver
_register("Go", _semver_compare)           # Go uses semver-like, with v-prefix
_register("PyPI", _pep440_compare)
_register("Maven", _maven_compare)
_register("RubyGems", _gem_compare)
_register("NuGet", _nuget_compare)
_register("Packagist", _composer_compare)

__all__ = ["compare", "in_range", "VersionError"]
