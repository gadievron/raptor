"""Tests for the shared stable-semver filter.

Centralised here so a change to the regex / tuple-comparison
logic gets one test surface that covers every upstream-latest
caller (github_releases, oci_tags, future helm_index, etc.)
without duplicating shape tests in each module."""

from __future__ import annotations

import pytest

from core.upstream_latest._version_filter import (
    highest_stable,
    highest_stable_with_variant,
    parse_stable,
    parse_stable_with_variant,
)


# ---------------------------------------------------------------------------
# parse_stable: shape recognition
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tag", [
    "1.2.3",
    "v1.2.3",
    "0.0.1",
    "1.0",
    "1",
    "1.2.3.4",        # 4-part NuGet assembly version
    "v0.0.0",
])
def test_parse_stable_accepts_stable_shapes(tag: str) -> None:
    """Stable shapes (1-4 part numeric, optional v-prefix) parse."""
    assert parse_stable(tag) is not None


@pytest.mark.parametrize("tag", [
    "1.2.3-rc.1",     # semver pre-release
    "v1.2.3-beta.2",   # semver pre-release
    "1.2.3.dev0",      # PEP440 dev
    "20.8b1",          # PEP440 beta inline
    "20.8rc1",         # PEP440 rc inline
    "1.2.3-alpha",     # generic pre-release
    "1.2.3+build.5",   # semver build metadata
    "main",            # branch ref
    "latest",          # alias
    "stable",          # alias
    "2024-01-15",      # date tag
    "3.12-bookworm",   # OCI variant
    "3.12-slim",       # OCI variant
    "release-2026-01", # named release ref
    "deadbeef",        # commit hash
    "",                # empty
])
def test_parse_stable_rejects_non_stable_shapes(tag: str) -> None:
    """Pre-release / variant / branch / non-version shapes
    must NOT parse — an auto-bumper landing any of these in a
    pin would be a regression."""
    assert parse_stable(tag) is None


def test_parse_stable_returns_tuple() -> None:
    """The tuple is used for max(); element-wise comparison gives
    the right ordering across part-count differences."""
    assert parse_stable("1.2.3") == (1, 2, 3)
    assert parse_stable("v0.0.1") == (0, 0, 1)
    assert parse_stable("1.2.3.4") == (1, 2, 3, 4)
    assert parse_stable("1") == (1,)


# ---------------------------------------------------------------------------
# highest_stable: comparison + selection
# ---------------------------------------------------------------------------

def test_highest_stable_picks_largest() -> None:
    """Numeric ordering — (2, 0, 0) > (1, 5, 0) > (1, 0, 0)."""
    assert highest_stable(["v1.0.0", "v2.0.0", "v1.5.0"]) == "v2.0.0"


def test_highest_stable_strips_non_stable_before_comparing() -> None:
    """A pre-release with a HIGHER numeric prefix is still
    rejected; the highest STABLE wins."""
    tags = ["v1.0.0", "v3.0.0-rc.1", "v2.0.0"]
    # v3.0.0-rc.1 is pre-release; v2.0.0 wins among stables.
    assert highest_stable(tags) == "v2.0.0"


def test_highest_stable_handles_mixed_part_counts() -> None:
    """A 4-part version vs 3-part version — element-wise tuple
    compare gives (1, 0, 0, 1) > (1, 0, 0) naturally."""
    tags = ["1.0.0", "1.0.0.1"]
    assert highest_stable(tags) == "1.0.0.1"


def test_highest_stable_none_when_nothing_stable() -> None:
    """No stable shapes → None (callers raise their own error)."""
    assert highest_stable(["main", "latest", "v1.0-rc"]) is None


def test_highest_stable_empty_list() -> None:
    assert highest_stable([]) is None


# ---------------------------------------------------------------------------
# parse_stable_with_variant: bare-semver + variant-suffixed shapes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "tag,expected",
    [
        ("3.12", ((3, 12), "")),
        ("v1.2.3", ((1, 2, 3), "")),
        ("3.12-slim", ((3, 12), "slim")),
        ("3.12-bookworm", ((3, 12), "bookworm")),
        ("18-alpine", ((18,), "alpine")),
        ("11-jdk", ((11,), "jdk")),
        # Compound variants — captured as one variant string,
        # not split. Caller filters on exact-match so
        # ``slim-bookworm`` never accidentally widens to ``slim``.
        ("3.12-slim-bookworm", ((3, 12), "slim-bookworm")),
        ("17-jre-alpine", ((17,), "jre-alpine")),
    ],
)
def test_parse_stable_with_variant_accepts(tag, expected) -> None:
    assert parse_stable_with_variant(tag) == expected


@pytest.mark.parametrize(
    "tag",
    [
        "latest", "main", "deadbeef",
        "2024-01-15",            # date tag
        "3.12-rc.1",             # pre-release suffix
        "3.12.dev0",             # PEP440 dev
        "3.12-",                 # dangling dash
        "-slim",                 # variant without semver
        "3.12--slim",            # double dash — variant regex
                                 # rejects empty leading segment
    ],
)
def test_parse_stable_with_variant_rejects(tag) -> None:
    assert parse_stable_with_variant(tag) is None


# ---------------------------------------------------------------------------
# highest_stable_with_variant: pick highest <semver>-<variant>
# ---------------------------------------------------------------------------

def test_highest_stable_with_variant_filters_to_matching_variant() -> None:
    """Mixed-shape registry tags — only the variant-matching
    ones contribute, the highest of those wins."""
    tags = [
        "3.9", "3.10", "3.11", "3.12",          # bare semver
        "3.9-slim", "3.10-slim", "3.12-slim",    # slim
        "3.10-bookworm", "3.12-bookworm",        # bookworm
        "latest",
    ]
    assert highest_stable_with_variant(tags, "slim") == "3.12-slim"
    assert highest_stable_with_variant(tags, "bookworm") == "3.12-bookworm"
    assert highest_stable_with_variant(tags, "") == "3.12"


def test_highest_stable_with_variant_none_when_variant_absent() -> None:
    """Asking for a variant not present in the tag list → None,
    even if other variants ARE present. Caller surfaces this as
    NoStableVersionsFound."""
    tags = ["3.9", "3.10", "3.12-slim", "3.12-bookworm"]
    assert highest_stable_with_variant(tags, "alpine") is None


def test_highest_stable_with_variant_does_not_match_bare_for_nonempty() -> None:
    """``highest_stable_with_variant(tags, "slim")`` must not
    return a bare ``3.12`` tag — bare-semver tags have variant=""
    and ``"" != "slim"``."""
    tags = ["3.9", "3.12"]
    assert highest_stable_with_variant(tags, "slim") is None


def test_highest_stable_with_variant_compound_variant_isolated() -> None:
    """``slim-bookworm`` variant must not match ``slim`` tags."""
    tags = [
        "3.10-slim", "3.11-slim", "3.12-slim",
        "3.10-slim-bookworm", "3.11-slim-bookworm",
    ]
    assert (
        highest_stable_with_variant(tags, "slim-bookworm")
        == "3.11-slim-bookworm"
    )
    assert (
        highest_stable_with_variant(tags, "slim")
        == "3.12-slim"
    )
