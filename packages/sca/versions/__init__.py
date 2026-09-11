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

from typing import Any


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
        msg = f"no version comparator for ecosystem: {ecosystem}"
        raise VersionError(msg)
    try:
        return cmp(a, b)
    except VersionError:
        raise
    except ValueError as exc:
        raise VersionError(str(exc)) from exc


def in_range(ecosystem: str, version: str, events: list[dict[str, str]]) -> bool:
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

    for lo, lo_incl, hi, hi_incl in _intervals(events):
        if _within(ecosystem, version, lo, lo_incl, hi, hi_incl):
            return True
    return False


def affects_admissible_max(
    ecosystem: str,
    events: list[dict[str, str]],
    floor: str | None,
    ceiling: str | None,
) -> bool:
    """Match a version *corridor* (range-pinned dep, no concrete
    installed version) against an OSV affected.ranges.events list.

    Models the version a maximising resolver would install for the
    corridor: the greatest admissible version. For ``pkg<2.0`` that is
    the greatest release below 2.0; for a floor-only corridor like
    ``pkg>1.0`` it is the latest release. The advisory matches when
    its vulnerable interval contains that resolver-max version:

    * With a ceiling ``C``: an interval ``[lo, hi)`` matches when
      ``lo <= C`` and ``hi >= C`` (or ``hi`` is open). Bound-operator
      inclusivity is not recorded on the corridor, so both comparisons
      are inclusive — the over-approximation keeps an advisory whose
      interval only touches ``C`` exactly, never drops one that covers
      versions below it. Note this intentionally KEEPS an advisory
      fixed exactly at ``C``: for an exclusive ``<C`` corridor every
      admissible version predates the fix.
    * Without a ceiling: the resolver-max is the latest release, so
      only open-ended (unfixed) intervals match.

    An empty corridor (``floor > ceiling``) matches nothing.

    Raises :class:`VersionError` when a bound comparison hits an
    unparseable version — callers skip that range, mirroring
    ``in_range`` error handling.
    """
    if not events:
        return False
    if (
        floor is not None and ceiling is not None
        and compare(ecosystem, floor, ceiling) > 0
    ):
        return False
    for lo, _lo_incl, hi, _hi_incl in _intervals(events):
        if ceiling is None:
            if hi is None:
                return True
            continue
        if lo != "0" and compare(ecosystem, lo, ceiling) > 0:
            continue
        if hi is None or compare(ecosystem, hi, ceiling) >= 0:
            return True
    return False


def _intervals(
    events: list[dict[str, str]],
) -> list[tuple[str, bool, str | None, bool]]:
    """Build vulnerable intervals from an OSV events list.

    Walk events, building intervals. Each "introduced" opens an interval;
    the next "fixed"/"last_affected"/"limit" closes it. A dangling
    "introduced" at end-of-list becomes an open-ended interval.
    """
    intervals: list[tuple] = []  # (lower, lower_inclusive, upper, upper_inclusive)
    current_lower: str = "0"     # default: from the start
    current_lower_inclusive = True
    has_open_lower = False       # True iff an introduced has been seen
                                 # without a corresponding closer yet
    for ev in events:
        if "introduced" in ev:
            if has_open_lower:
                # A second ``introduced`` while one interval is still
                # open (multi-introduced range object, or events the
                # producer didn't sort). Overwriting the open lower
                # bound silently DROPPED the first vulnerable interval;
                # close it as open-ended instead — conservative
                # over-approximation, same treatment as a dangling
                # ``introduced`` at end-of-list — then open the next.
                intervals.append((current_lower, current_lower_inclusive,
                                  None, False))
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

    return intervals


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
        elif c_lo <= 0:
            return False
    if hi is None:
        return True
    c_hi = compare(ecosystem, version, hi)
    if hi_incl:
        return c_hi <= 0
    if c_hi < 0 and _is_fork_tagged_at_fix(ecosystem, version, hi):
        return False
    return c_hi < 0


def _is_fork_tagged_at_fix(ecosystem: str, version: str, fixed: str) -> bool:
    """True when *version* is ``X.Y.Z-forktag`` and *fixed* is ``X.Y.Z``
    — the fork-tag prerelease pattern that causes semver false positives
    in OSV range checks.

    Semver says ``0.4.3-succinct < 0.4.3``, so a range ``[introduced,
    0.4.3)`` matches.  But ``-succinct`` is an org/fork tag, not a
    genuine prerelease — the fork was almost certainly published from
    the same ``0.4.3`` codebase that contains the fix.

    Only applies to ecosystems that use semver (Cargo, npm).  Go is
    excluded because Go pseudo-versions legitimately use prereleases
    for timestamp-hash identifiers.
    """
    eco = _canonical_ecosystem(ecosystem)
    if eco not in ("npm", "Cargo"):
        return False
    from .semver import is_fork_tag, parse as _parse_semver
    try:
        v = _parse_semver(version)
        f = _parse_semver(fixed)
    except ValueError:
        return False
    if v[:3] != f[:3]:
        return False
    if v[3] is None or f[3] is not None:
        return False
    return is_fork_tag(v[3])


def _canonical_ecosystem(eco: str) -> str:
    """Normalise ecosystem strings — OSV uses 'PyPI', 'npm', 'Maven', 'Go',
    'crates.io' / 'Cargo', 'RubyGems', 'NuGet', 'Packagist'.

    Distro ecosystems carry release suffixes ('Debian:11',
    'Alpine:v3.18', 'Ubuntu:22.04') — the release stream never changes
    the version *semantics*, so the suffix is dropped for comparator
    lookup when the full string has no alias of its own.
    """
    low = eco.lower()
    hit = _ECOSYSTEM_ALIASES.get(low)
    if hit is not None:
        return hit
    base = low.split(":", 1)[0]
    if base != low:
        hit = _ECOSYSTEM_ALIASES.get(base)
        if hit is not None:
            return hit
    return eco


_ECOSYSTEM_ALIASES = {
    # Ubuntu packages use dpkg version semantics — same comparator
    # as Debian.
    "ubuntu": "Debian",
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
    "debian": "Debian",
    "apt": "Debian",
    "deb": "Debian",
    "alpine": "Alpine",
    "apk": "Alpine",
    "red hat": "Red Hat",
    "redhat": "Red Hat",
    "rpm": "Red Hat",
    "github actions": "GitHub Actions",
    "conancenter": "ConanCenter",
    "conan": "ConanCenter",
    "vcpkg": "vcpkg",
}


# Comparators registered below by importing each per-ecosystem module.
_comparators: dict[str, Any] = {}


def _register(ecosystem: str, fn) -> None:
    _comparators[ecosystem] = fn


# Wire concrete comparators (avoids circular imports).
from .alpine import compare as _alpine_compare
from .composer import compare as _composer_compare
from .conan import compare as _conan_compare
from .debian import compare as _debian_compare
from .gem import compare as _gem_compare
from .maven import compare as _maven_compare
from .nuget import compare as _nuget_compare
from .pep440 import compare as _pep440_compare
from .rpm import compare as _rpm_compare
from .semver import compare as _semver_compare
from .vcpkg import compare as _vcpkg_compare

_register("npm", _semver_compare)
_register("Cargo", _semver_compare)        # mostly semver
_register("Go", _semver_compare)           # Go uses semver-like, with v-prefix
_register("PyPI", _pep440_compare)
_register("Maven", _maven_compare)
_register("RubyGems", _gem_compare)
_register("NuGet", _nuget_compare)
_register("Packagist", _composer_compare)
_register("Debian", _debian_compare)
_register("Alpine", _alpine_compare)
_register("Red Hat", _rpm_compare)
# GitHub Actions tags ("v1", "v1.2.3") follow semver with a leading
# "v" — exactly what the semver comparator already tolerates.
_register("GitHub Actions", _semver_compare)
_register("ConanCenter", _conan_compare)
_register("vcpkg", _vcpkg_compare)

__all__ = [
    "VersionError", "affects_admissible_max", "compare", "in_range",
]
