"""Tests for the semver version comparator.

Semver (https://semver.org/) is used by npm, Cargo, and Go (with
leading ``v`` tolerated for Go's convention). The spec is cleaner
than PEP 440 / Maven but has two real gotchas:

  * Numeric pre-release identifiers compare NUMERICALLY (so
    ``1.0.0-2 < 1.0.0-10``), while alphanumeric ones compare
    lexically. The split is per-identifier, not per-pre-release.
  * Numeric identifiers always sort BELOW alphanumeric ones at
    the same position — ``1.0.0-1 < 1.0.0-alpha`` rather than
    the other way around. Counter-intuitive but spec-mandated.
  * Build metadata (``+...``) is IGNORED for ordering per spec.
    Three otherwise-identical versions with different build
    metadata sort as equal.

Tests in this file pin those gotchas + the everyday cases.

The semver comparator also tolerates Go's ``v``-prefixed format
and the pseudo-version form ``v0.0.0-<timestamp>-<short_sha>``,
which Go's module system uses for unreleased commits. Those are
covered explicitly.
"""

from __future__ import annotations

import pytest

from packages.sca.versions import compare as dispatch_compare
from packages.sca.versions import in_range
from packages.sca.versions.semver import compare as cmp
from packages.sca.versions.semver import parse


# ---------------------------------------------------------------------------
# Basic ordering.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a, b, expected", [
    ("1.0.0", "1.0.1", -1),
    ("1.0.1", "1.0.0", 1),
    ("1.0.0", "1.0.0", 0),
    ("1.0.0", "1.1.0", -1),
    ("1.0.0", "2.0.0", -1),
    ("0.9.9", "1.0.0", -1),
    ("10.0.0", "9.0.0", 1),     # numeric, not lex
    ("1.10.0", "1.9.0", 1),     # same: numeric compare on minor
])
def test_basic_ordering(a, b, expected) -> None:
    assert cmp(a, b) == expected


def test_identical_short_circuit() -> None:
    """Identical strings short-circuit to 0 without parsing."""
    assert cmp("1.0.0", "1.0.0") == 0
    assert cmp("1.0.0-alpha", "1.0.0-alpha") == 0


# ---------------------------------------------------------------------------
# Pre-release ordering — the spec's core complexity.
# ---------------------------------------------------------------------------

def test_pre_release_below_release() -> None:
    """Pre-releases sort BELOW the bare release per spec §11."""
    assert cmp("1.0.0-alpha", "1.0.0") == -1
    assert cmp("1.0.0-rc.1", "1.0.0") == -1
    assert cmp("1.0.0", "1.0.0-alpha") == 1


def test_pre_release_label_order() -> None:
    """Common pre-release label progression (lex-sorted since
    none are pure numeric)."""
    assert cmp("1.0.0-alpha", "1.0.0-beta") == -1
    assert cmp("1.0.0-beta", "1.0.0-rc.1") == -1


def test_numeric_pre_compares_as_int_not_lex() -> None:
    """The headline gotcha: numeric pre-release identifiers
    compare NUMERICALLY, not lexically. ``1.0.0-2`` < ``1.0.0-10``
    because both pre-release segments are pure numeric — int
    compare wins over lex compare here."""
    assert cmp("1.0.0-2", "1.0.0-10") == -1
    assert cmp("1.0.0-10", "1.0.0-2") == 1


def test_alphanumeric_pre_compares_as_string() -> None:
    """The COUNTERPART gotcha: alphanumeric pre-release
    identifiers compare LEXICALLY, NOT numerically. So
    ``1.0.0-rc11 < 1.0.0-rc2`` because "rc11" < "rc2" in
    string comparison. This is genuinely counter-intuitive
    but spec-mandated — operators who want numeric ordering
    on rcN must separate the rc from the number with a dot
    (``1.0.0-rc.11`` > ``1.0.0-rc.2``)."""
    assert cmp("1.0.0-rc11", "1.0.0-rc2") == -1
    # The fix: separate with a dot so they become two identifiers.
    assert cmp("1.0.0-rc.2", "1.0.0-rc.11") == -1


def test_numeric_below_alphanumeric_in_pre() -> None:
    """Per spec §11.4.3: numeric identifiers always sort BELOW
    alphanumeric ones at the same position. ``1.0.0-1`` <
    ``1.0.0-alpha`` because the first identifier of the LHS is
    numeric (1) and of the RHS is alphanumeric (alpha)."""
    assert cmp("1.0.0-1", "1.0.0-alpha") == -1
    assert cmp("1.0.0-alpha", "1.0.0-1") == 1


def test_pre_chain_length_tiebreak() -> None:
    """Per spec §11.4.4: when shared prefix matches, longer pre-
    release chain wins. ``1.0.0-alpha < 1.0.0-alpha.1`` because
    the extra ``.1`` identifier extends the chain."""
    assert cmp("1.0.0-alpha", "1.0.0-alpha.1") == -1
    assert cmp("1.0.0-alpha.1", "1.0.0-alpha") == 1
    assert cmp("1.0.0-alpha.1", "1.0.0-alpha.beta") == -1


# ---------------------------------------------------------------------------
# Build metadata — explicitly ignored.
# ---------------------------------------------------------------------------

def test_build_metadata_ignored_for_ordering() -> None:
    """Per spec §10: build metadata MUST be ignored when
    determining version precedence. Three versions identical
    except for build metadata sort as equal."""
    assert cmp("1.0.0+a", "1.0.0+b") == 0
    assert cmp("1.0.0+build.1", "1.0.0+build.2") == 0
    assert cmp("1.0.0", "1.0.0+a") == 0


def test_build_metadata_with_pre_release() -> None:
    """Build metadata can co-exist with pre-release. The
    pre-release segment still orders normally; only the build
    metadata is ignored."""
    assert cmp("1.0.0-alpha+build1", "1.0.0-beta+build1") == -1
    assert cmp("1.0.0-alpha+build1", "1.0.0-alpha+build2") == 0


# ---------------------------------------------------------------------------
# Short forms + v-prefix tolerance (Go).
# ---------------------------------------------------------------------------

def test_short_forms_default_to_zero() -> None:
    """Missing minor / patch components default to 0 in this
    comparator. Real-world advisory data + Go pseudo-versions
    use short forms; rejecting them would miss findings."""
    assert parse("1") == (1, 0, 0, None)
    assert parse("1.2") == (1, 2, 0, None)
    assert parse("1.2.3") == (1, 2, 3, None)
    # Comparison is equal across these:
    assert cmp("1", "1.0") == 0
    assert cmp("1.0", "1.0.0") == 0


def test_leading_v_tolerated() -> None:
    """Go's convention is ``v1.2.3``; npm accepts plain ``1.2.3``.
    The comparator tolerates either form, so Go advisory data
    against an npm-style installed version still matches."""
    assert cmp("v1.0.0", "1.0.0") == 0
    assert cmp("v1.0.0", "v1.0.1") == -1
    assert cmp("v2.0.0", "1.0.0") == 1


def test_go_pseudo_version_parses() -> None:
    """Go's pseudo-version form
    ``v0.0.0-<timestamp>-<short_sha>`` is used for unreleased
    commits. The comparator parses it (treating the
    timestamp-sha as a pre-release identifier) so range
    matching against go.mod versions works."""
    major, minor, patch, pre = parse("v0.0.0-20210320205559-abc123")
    assert (major, minor, patch) == (0, 0, 0)
    assert pre is not None
    assert pre[0] == "20210320205559-abc123"


def test_go_pseudo_version_order() -> None:
    """Two pseudo-versions sort by their timestamp segment
    (lexicographic since the format puts the largest unit
    first)."""
    older = "v0.0.0-20200101000000-aaaaaa"
    newer = "v0.0.0-20210320205559-bbbbbb"
    assert cmp(older, newer) == -1


# ---------------------------------------------------------------------------
# Edge cases — malformed / boundary inputs.
# ---------------------------------------------------------------------------

def test_invalid_raises_value_error() -> None:
    """Bad inputs raise ``ValueError`` — not a silent default."""
    with pytest.raises(ValueError):
        parse("not-a-version")
    with pytest.raises(ValueError):
        parse("@@@@")


def test_empty_pre_after_dash_does_not_match() -> None:
    """``1.0.0-`` (dash with nothing after) is malformed.
    Don't silently succeed."""
    with pytest.raises(ValueError):
        parse("1.0.0-")


def test_multiple_dashes_in_pre() -> None:
    """Only the FIRST ``-`` is the pre-release delimiter — the
    rest are part of the pre-release identifier. Common in
    Go pseudo-versions."""
    _, _, _, pre = parse("1.0.0-alpha-1.snapshot")
    assert pre == ["alpha-1", "snapshot"]


# ---------------------------------------------------------------------------
# Dispatcher integration.
# ---------------------------------------------------------------------------

def test_dispatch_routes_npm_to_semver() -> None:
    """``versions.compare("npm", ...)`` routes to the semver
    comparator."""
    assert dispatch_compare("npm", "1.0.0", "1.0.1") == -1
    assert dispatch_compare("npm", "1.0.0-alpha", "1.0.0") == -1


def test_dispatch_routes_cargo_to_semver() -> None:
    """``versions.compare("Cargo", ...)`` also routes here."""
    assert dispatch_compare("Cargo", "1.0.0", "1.0.1") == -1


def test_dispatch_routes_go_to_semver() -> None:
    """Go modules use semver too (with ``v`` prefix tolerated)."""
    assert dispatch_compare("Go", "v1.0.0", "v1.0.1") == -1


def test_in_range_semver_smoke() -> None:
    """End-to-end OSV range matching."""
    events = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
    assert in_range("npm", "1.5.0", events) is True
    assert in_range("npm", "2.0.0", events) is False
    # Pre-release of 2.0 still < 2.0 per spec, so still in range.
    assert in_range("npm", "2.0.0-rc.1", events) is True
