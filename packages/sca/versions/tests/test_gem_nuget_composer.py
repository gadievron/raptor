"""Tests for the gem / nuget / composer version comparators.

Each comparator's behaviour is what matters for OSV range matching:
ordering between releases, pre-releases sorting before their release,
and end-to-end ``in_range`` smoke."""

from __future__ import annotations

import pytest

from packages.sca.versions import compare, in_range
from packages.sca.versions.composer import compare as composer_cmp
from packages.sca.versions.gem import compare as gem_cmp
from packages.sca.versions.nuget import compare as nuget_cmp


# ---------------------------------------------------------------------------
# Gem
# ---------------------------------------------------------------------------

def test_gem_basic_ordering() -> None:
    assert gem_cmp("1.0.0", "1.0.1") == -1
    assert gem_cmp("1.0.1", "1.0.0") == 1
    assert gem_cmp("1.0.0", "1.0.0") == 0


def test_gem_trailing_zero_equality() -> None:
    """``1.0`` == ``1.0.0`` per RubyGems."""
    assert gem_cmp("1.0", "1.0.0") == 0


def test_gem_prerelease_sorts_before_release() -> None:
    assert gem_cmp("1.0.0.pre1", "1.0.0") == -1
    assert gem_cmp("1.0.0.pre1", "1.0.0.pre2") == -1
    assert gem_cmp("1.0.0.alpha", "1.0.0.beta") == -1


def test_gem_in_range_via_dispatcher() -> None:
    """``versions.in_range`` should dispatch to the gem comparator."""
    events = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
    assert in_range("RubyGems", "1.5.0", events) is True
    assert in_range("RubyGems", "2.0.0", events) is False


# ---------------------------------------------------------------------------
# NuGet
# ---------------------------------------------------------------------------

def test_nuget_basic_ordering() -> None:
    assert nuget_cmp("1.0.0", "1.0.1") == -1
    assert nuget_cmp("13.0.1", "13.0.3") == -1


def test_nuget_four_part_version() -> None:
    """NuGet accepts 4-part legacy AssemblyVersion shape."""
    assert nuget_cmp("1.2.3.4", "1.2.3.5") == -1
    assert nuget_cmp("1.2.3.4", "1.2.3.4") == 0


def test_nuget_v_prefix_tolerated() -> None:
    assert nuget_cmp("v1.0.0", "1.0.0") == 0


def test_nuget_prerelease_sorts_before_release() -> None:
    assert nuget_cmp("1.0.0-rc1", "1.0.0") == -1
    assert nuget_cmp("1.0.0-alpha", "1.0.0-beta") == -1


def test_nuget_build_metadata_ignored() -> None:
    assert nuget_cmp("1.0.0+abc", "1.0.0+def") == 0


def test_nuget_in_range_via_dispatcher() -> None:
    events = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
    assert in_range("NuGet", "1.5.0", events) is True
    assert in_range("NuGet", "2.0.0", events) is False


# ---------------------------------------------------------------------------
# Composer
# ---------------------------------------------------------------------------

def test_composer_basic_ordering() -> None:
    assert composer_cmp("1.0.0", "1.0.1") == -1
    assert composer_cmp("v6.4.0", "v6.4.1") == -1


def test_composer_v_prefix_equivalent() -> None:
    assert composer_cmp("v1.0.0", "1.0.0") == 0


def test_composer_stability_ordering() -> None:
    """``alpha < beta < rc < release``."""
    assert composer_cmp("1.0.0-alpha", "1.0.0-beta") == -1
    assert composer_cmp("1.0.0-beta", "1.0.0-rc") == -1
    assert composer_cmp("1.0.0-rc", "1.0.0") == -1


def test_composer_dev_branch_after_release() -> None:
    """``dev-master`` sorts AFTER any released version (Composer's
    "latest-tag-or-dev" preference)."""
    assert composer_cmp("dev-master", "1.0.0") == 1
    assert composer_cmp("1.0.0", "dev-master") == -1


def test_composer_in_range_via_dispatcher() -> None:
    events = [{"introduced": "6.0.0"}, {"fixed": "6.4.0"}]
    assert in_range("Packagist", "6.3.0", events) is True
    assert in_range("Packagist", "6.4.0", events) is False


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

def test_compare_dispatcher_picks_right_comparator() -> None:
    """``compare(eco, a, b)`` should route to the per-ecosystem fn."""
    assert compare("RubyGems", "1.0.0.pre1", "1.0.0") == -1
    assert compare("NuGet", "1.0.0-rc1", "1.0.0") == -1
    assert compare("Packagist", "1.0.0-alpha", "1.0.0") == -1


def test_compare_dispatcher_normalises_value_error_to_version_error():
    """Per-ecosystem comparators historically raise plain
    ``ValueError`` for unparseable versions. The dispatcher must
    normalise to ``VersionError`` so callers'
    ``except VersionError`` blocks fire — ``except VersionError``
    does NOT catch its parent ``ValueError``.

    Regression: stress sweep on rails @ v7.1.2 hit an OSV
    advisory with cross-ecosystem ``fixed_versions``: an
    npm-tagged dep had a Ruby-shaped ``'7.0.8.3'`` fix entry.
    Pre-fix the plain ``ValueError`` from
    ``semver.parse('7.0.8.3')`` leaked past
    ``findings._smallest_applicable_fix``'s
    ``except VersionError`` handler, aborting the whole scan.
    """
    from packages.sca.versions import VersionError
    # ``'7.0.8.3'`` against ``npm`` — semver can't parse it, must
    # surface as VersionError (not plain ValueError).
    with pytest.raises(VersionError) as exc_info:
        compare("npm", "7.0.8.3", "2.0.5")
    # And the underlying ValueError chained for diagnostics.
    assert exc_info.value.__cause__ is not None
    assert isinstance(exc_info.value.__cause__, ValueError)


def test_compare_dispatcher_passes_through_version_error_unchanged():
    """When the dispatcher itself raises VersionError (e.g.
    unknown ecosystem), pass it through without adapter-wrapping
    so the cause-chain stays clean."""
    from packages.sca.versions import VersionError
    with pytest.raises(VersionError) as exc_info:
        compare("not-an-ecosystem", "1.0.0", "2.0.0")
    # No cause — this VersionError was raised directly.
    assert exc_info.value.__cause__ is None
