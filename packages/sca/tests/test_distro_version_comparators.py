"""Version comparators for Alpine / Red Hat / GitHub Actions /
ConanCenter / vcpkg.

These ecosystems used to have no registered comparator, so every
``compare()`` raised ``VersionError`` — and range-matching callers
treat ``VersionError`` as "skip this range", i.e. every advisory in
these ecosystems silently read as NOT VULNERABLE. Each block below
checks both directions: a vulnerable version matches its advisory
range, and the fixed version does not.
"""

from __future__ import annotations

import pytest

from packages.sca.versions import VersionError, compare, in_range


def _range(introduced: str, fixed: str) -> list[dict[str, str]]:
    return [{"introduced": introduced}, {"fixed": fixed}]


# ---------------------------------------------------------------------------
# Alpine (apk)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("a", "b"), [
    ("1.2.3", "1.2.4"),
    ("1.2", "1.2.0"),              # extra numeric component is newer
    ("1.2.3", "1.2.3a"),           # trailing letter sorts after bare
    ("1.2.3a", "1.2.3b"),
    ("1.2.3_alpha", "1.2.3_beta"),
    ("1.2.3_rc1", "1.2.3_rc2"),
    ("1.2.3_rc1", "1.2.3"),        # pre-release sorts before release
    ("1.2.3", "1.2.3_p1"),         # post-release sorts after release
    ("1.2.3-r1", "1.2.3-r2"),      # pkgrel
    ("3.1.4-r0", "3.1.4-r1"),
])
def test_alpine_ordering(a: str, b: str) -> None:
    assert compare("Alpine", a, b) == -1
    assert compare("Alpine", b, a) == 1
    assert compare("Alpine", a, a) == 0


def test_alpine_range_both_directions() -> None:
    events = _range("0", "1.36.1-r1")
    assert in_range("Alpine", "1.36.0-r5", events)
    assert not in_range("Alpine", "1.36.1-r1", events)


def test_alpine_release_suffixed_ecosystem_string() -> None:
    """Image-derived rows carry 'Alpine:v3.18' — the release suffix
    must route to the same apk comparator."""
    assert compare("Alpine:v3.18", "1.2.3-r0", "1.2.3-r1") == -1
    assert in_range("Alpine:v3.18", "1.2.2-r0", _range("0", "1.2.3-r0"))


def test_alpine_unparseable_raises() -> None:
    with pytest.raises(VersionError):
        compare("Alpine", "not an apk version!", "1.0")


# ---------------------------------------------------------------------------
# Red Hat (rpm)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("a", "b"), [
    ("1.0.2k-8.el7", "1.0.2k-16.el7"),   # release compares numerically
    ("1.0.2j-1.el7", "1.0.2k-1.el7"),    # letter suffix in version
    ("0:2.0-1", "1:1.0-1"),              # epoch beats everything
    ("1.0~rc1", "1.0"),                  # tilde sorts before release
    ("1.0", "1.0^git1"),                 # caret sorts after release
    ("1.0^git1", "1.0.1"),               # ...but before the next patch
    ("2.6", "2.50"),                     # numeric, not lexical
    ("1.0", "1.0-1"),                    # explicit release is newer
])
def test_rpm_ordering(a: str, b: str) -> None:
    assert compare("Red Hat", a, b) == -1
    assert compare("Red Hat", b, a) == 1
    assert compare("Red Hat", a, a) == 0


def test_rpm_range_both_directions() -> None:
    events = _range("0", "1:1.0.2k-16.el7")
    assert in_range("Red Hat", "1:1.0.2k-8.el7", events)
    assert not in_range("Red Hat", "1:1.0.2k-16.el7", events)


def test_rpm_invalid_epoch_raises() -> None:
    with pytest.raises(VersionError):
        compare("Red Hat", "abc:1.0", "1.0")


# ---------------------------------------------------------------------------
# GitHub Actions (v-prefixed semver-ish tags)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("a", "b"), [
    ("v1", "v1.2.3"),
    ("v3.6.0", "v4.0.0"),
    ("v4.1.0", "4.1.7"),      # mixed v-prefix and bare
])
def test_github_actions_ordering(a: str, b: str) -> None:
    assert compare("GitHub Actions", a, b) == -1
    assert compare("GitHub Actions", b, a) == 1


def test_github_actions_range_both_directions() -> None:
    events = _range("0", "4.4.1")
    assert in_range("GitHub Actions", "v4.4.0", events)
    assert not in_range("GitHub Actions", "v4.4.1", events)


# ---------------------------------------------------------------------------
# ConanCenter
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("a", "b"), [
    ("1.1.1k", "1.1.1t"),      # openssl-style letter tails
    ("1.2.11", "1.2.13"),
    ("1.2.3", "1.2.3.1"),      # four-component versions
    ("2.0.0-rc1", "2.0.0"),    # pre-release sorts before release
])
def test_conan_ordering(a: str, b: str) -> None:
    assert compare("ConanCenter", a, b) == -1
    assert compare("ConanCenter", b, a) == 1


def test_conan_range_both_directions() -> None:
    events = _range("0", "1.1.1t")
    assert in_range("ConanCenter", "1.1.1k", events)
    assert not in_range("ConanCenter", "1.1.1t", events)


def test_conan_unorderable_shape_raises() -> None:
    # cci.<date> snapshot names carry no comparable ordering vs
    # release versions — refusing beats guessing.
    with pytest.raises(VersionError):
        compare("ConanCenter", "cci.20210220", "1.0")


# ---------------------------------------------------------------------------
# vcpkg
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("a", "b"), [
    ("1.2.3", "1.2.4"),
    ("1.2.3", "1.2.3#1"),          # port-version bump is newer
    ("1.2.3#2", "1.2.3#10"),       # port-version is numeric
    ("2021-06-01", "2021-07-01"),  # version-date scheme
])
def test_vcpkg_ordering(a: str, b: str) -> None:
    assert compare("vcpkg", a, b) == -1
    assert compare("vcpkg", b, a) == 1


def test_vcpkg_range_both_directions() -> None:
    events = _range("0", "1.2.13")
    assert in_range("vcpkg", "1.2.12#3", events)
    assert not in_range("vcpkg", "1.2.13", events)


def test_vcpkg_version_string_scheme_raises() -> None:
    # vcpkg's ``version-string`` scheme is explicitly unordered.
    with pytest.raises(VersionError):
        compare("vcpkg", "vista", "1.0")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
