"""Tests for the shared stable-semver filter.

Centralised here so a change to the regex / tuple-comparison
logic gets one test surface that covers every upstream-latest
caller (github_releases, oci_tags, future helm_index, etc.)
without duplicating shape tests in each module."""

from __future__ import annotations

import pytest

from core.upstream_latest._version_filter import (
    highest_stable,
    parse_stable,
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
