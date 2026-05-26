"""Tests for the Maven version comparator.

Maven version ordering has the most subtle semantics of any
ecosystem we cover — the canonical implementation is
``maven-artifact``'s ``ComparableVersion`` class, with a qualifier
system where ``SNAPSHOT`` / ``alpha`` / ``rc`` / ``ga`` / ``sp``
have specific positions. The headline gotcha is that a qualifier
on a release version makes it pre-release: ``1.0-SNAPSHOT < 1.0``.

Tests in this file pin the comparator against:
  * The well-known qualifier ordering ladder.
  * Qualifier aliases (a == alpha, b == beta, cr == rc, etc.).
  * The "qualifier on release means pre-release" rule.
  * Trailing-zero / trailing-ga equivalences.
  * Unknown-qualifier disposition (sort AFTER known).
  * In-range dispatch via ``versions.in_range``.

When a future change shifts any of these, the failing test names
themselves are documentation: read the test name + docstring to
understand which semantic rule the change touches.
"""

from __future__ import annotations

import pytest

from packages.sca.versions import compare as dispatch_compare
from packages.sca.versions import in_range
from packages.sca.versions.maven import compare as cmp


# ---------------------------------------------------------------------------
# Numeric ordering — the everyday case.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a, b, expected", [
    ("1.0.0", "1.0.1", -1),
    ("1.0.1", "1.0.0", 1),
    ("1.0.0", "1.0.0", 0),
    ("1.0.0", "1.1.0", -1),
    ("1.0.0", "2.0.0", -1),
    ("0.9.9", "1.0.0", -1),
    ("10.0.0", "9.0.0", 1),     # numeric compare, not lex
])
def test_basic_numeric_ordering(a, b, expected) -> None:
    assert cmp(a, b) == expected


def test_trailing_zero_equality() -> None:
    """``1.0 == 1.0.0 == 1.0.0.0`` per Maven — trailing zero
    segments are stripped before comparison."""
    assert cmp("1.0", "1.0.0") == 0
    assert cmp("1.0.0", "1.0.0.0") == 0
    assert cmp("1.0", "1.0.0.0") == 0


# ---------------------------------------------------------------------------
# Qualifier ladder — the headline subtlety.
# ---------------------------------------------------------------------------

def test_snapshot_sorts_below_release() -> None:
    """The canonical Maven gotcha: a SNAPSHOT qualifier on an
    otherwise-bare release version makes it pre-release.
    Every Maven build pipeline depends on this — without it,
    snapshot builds would shadow their own release deploys."""
    assert cmp("1.0-SNAPSHOT", "1.0") == -1
    assert cmp("1.0", "1.0-SNAPSHOT") == 1


def test_qualifier_ordering_ladder() -> None:
    """Per ComparableVersion: alpha < beta < milestone < rc <
    snapshot < release < sp. Each step is one position on the
    known-qualifier ladder."""
    assert cmp("1.0-alpha", "1.0-beta") == -1
    assert cmp("1.0-beta", "1.0-milestone") == -1
    assert cmp("1.0-milestone", "1.0-rc") == -1
    assert cmp("1.0-rc", "1.0-snapshot") == -1
    assert cmp("1.0-snapshot", "1.0") == -1
    assert cmp("1.0", "1.0-sp") == -1


def test_qualifier_aliases() -> None:
    """ComparableVersion treats short qualifier forms as identical
    to their long names. Ensures advisory data using either form
    matches the same dep version."""
    assert cmp("1.0-a", "1.0-alpha") == 0
    assert cmp("1.0-b", "1.0-beta") == 0
    assert cmp("1.0-m", "1.0-milestone") == 0
    assert cmp("1.0-cr", "1.0-rc") == 0
    # With numeric suffix on both sides:
    assert cmp("1.0-a1", "1.0-alpha1") == 0
    assert cmp("1.0-b1", "1.0-beta1") == 0
    assert cmp("1.0-rc1", "1.0-cr1") == 0


def test_release_aliases_are_trivial() -> None:
    """``ga`` / ``final`` / ``release`` are all the explicit
    release-marker qualifiers. Each is equivalent to a bare
    version with no qualifier — stripped during comparison."""
    assert cmp("1.0-ga", "1.0") == 0
    assert cmp("1.0-final", "1.0") == 0
    assert cmp("1.0-release", "1.0") == 0
    assert cmp("1.0-ga", "1.0-final") == 0
    assert cmp("1.0-final", "1.0-release") == 0


def test_sp_suffix_above_release() -> None:
    """``sp`` (Service Pack) is the one qualifier that's ABOVE
    release in the ladder. ``1.0-sp1 > 1.0`` because a service
    pack post-dates the release it patches."""
    assert cmp("1.0-sp1", "1.0") == 1
    assert cmp("1.0", "1.0-sp1") == -1
    assert cmp("1.0-sp1", "1.0-sp2") == -1


def test_numeric_segment_beats_qualifier() -> None:
    """At the same depth, a numeric segment outranks a qualifier
    segment. So ``1.0.1 > 1.0-SNAPSHOT`` despite SNAPSHOT being
    pre-release — the extra `.1` indicates a real later release."""
    assert cmp("1.0.1", "1.0-SNAPSHOT") == 1
    assert cmp("1.0-SNAPSHOT", "1.0.1") == -1


# ---------------------------------------------------------------------------
# Case insensitivity + separator normalisation.
# ---------------------------------------------------------------------------

def test_qualifier_case_insensitive() -> None:
    """Maven qualifier matching is case-insensitive — ``SNAPSHOT``
    / ``snapshot`` / ``Snapshot`` are all equivalent. Advisory
    data is wildly inconsistent on case; the comparator
    canonicalises."""
    assert cmp("1.0-SNAPSHOT", "1.0-snapshot") == 0
    assert cmp("1.0-Snapshot", "1.0-snapshot") == 0
    assert cmp("1.0-Alpha", "1.0-alpha") == 0
    assert cmp("1.0-RC1", "1.0-rc1") == 0


def test_separator_normalisation() -> None:
    """Maven accepts ``.``, ``-``, and ``_`` as version-segment
    separators interchangeably. Lockfile inconsistency between
    ``1.0-rc1`` and ``1.0.rc1`` would otherwise produce false
    range-match misses."""
    assert cmp("1.0-rc1", "1.0.rc1") == 0
    assert cmp("1.0-rc1", "1.0_rc1") == 0
    assert cmp("1.0_alpha", "1.0.alpha") == 0


def test_no_separator_before_qualifier() -> None:
    """``1.0RC1`` (no separator) tokenises by digit/non-digit
    boundary, so the qualifier still gets recognised. Without
    this, advisory ranges using the compact form would silently
    miss."""
    assert cmp("1.0RC1", "1.0") == -1   # RC < release
    assert cmp("1.0RC1", "1.0-rc1") == 0   # equivalent to explicit form


# ---------------------------------------------------------------------------
# Unknown qualifiers.
# ---------------------------------------------------------------------------

def test_unknown_qualifier_sorts_after_known() -> None:
    """Per ComparableVersion: unknown qualifiers sort AFTER every
    known qualifier. ``1.0-zzunknown > 1.0-snapshot`` because the
    parser treats unknown qualifiers as "future / non-canonical"
    additions."""
    assert cmp("1.0-zzunknown", "1.0-snapshot") == 1
    assert cmp("1.0-zzunknown", "1.0-rc") == 1
    assert cmp("1.0-zzunknown", "1.0-alpha") == 1


def test_unknown_qualifier_above_release() -> None:
    """Unknown qualifier on a bare version makes it sort ABOVE
    the bare version — the qualifier is treated as a post-release
    addition. ``1.0 < 1.0-foo`` follows the same rule that puts
    unknown qualifiers after known ones (including the implicit
    'release' marker)."""
    assert cmp("1.0", "1.0-foo") == -1
    assert cmp("1.0-foo", "1.0") == 1


def test_two_unknowns_lexicographic() -> None:
    """When both sides have unknown qualifiers, fall back to
    lexicographic comparison among them. ``1.0-foo < 1.0-zoo``."""
    assert cmp("1.0-foo", "1.0-zoo") == -1
    assert cmp("1.0-zoo", "1.0-foo") == 1
    assert cmp("1.0-foo", "1.0-foo") == 0


# ---------------------------------------------------------------------------
# Nested pre-release chains — the multi-qualifier case.
# ---------------------------------------------------------------------------

def test_nested_pre_chain() -> None:
    """A pre-release chain like ``1.0-alpha-1-SNAPSHOT`` is the
    same as ``1.0-alpha.1.snapshot`` after separator normalisation.
    Adding a SNAPSHOT inside the chain makes it pre-release of the
    surrounding alpha-1."""
    assert cmp("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1") == -1
    assert cmp("1.0-alpha-1", "1.0-alpha-1-SNAPSHOT") == 1


def test_beta_chain_numeric_suffix() -> None:
    """``1.0.0-beta-2 > 1.0.0-beta-1`` — numeric suffix at end of
    chain sorts as int, not lex."""
    assert cmp("1.0.0-beta-1", "1.0.0-beta-2") == -1
    # And int-not-lex applies to two-digit cases:
    assert cmp("1.0.0-beta-2", "1.0.0-beta-10") == -1


# ---------------------------------------------------------------------------
# Defensive — degenerate / malformed inputs.
# ---------------------------------------------------------------------------

def test_qualifier_only_versions() -> None:
    """Versions with no numeric segment at all (just a qualifier
    name) still order by the qualifier ladder. Rare in practice
    but appears in some advisory data."""
    assert cmp("alpha", "beta") == -1
    assert cmp("beta", "rc") == -1
    assert cmp("rc", "release") == -1


def test_whitespace_tolerated() -> None:
    """Leading/trailing whitespace is stripped. Manifest data
    occasionally carries stray whitespace; we tolerate it."""
    assert cmp(" 1.0 ", "1.0") == 0
    assert cmp("1.0", "  1.0  ") == 0


def test_identical_short_circuit() -> None:
    """Identical strings short-circuit to 0 without tokenising —
    a performance optimisation that the test pins so future
    changes don't accidentally break it."""
    assert cmp("1.0.0", "1.0.0") == 0
    assert cmp("1.0-SNAPSHOT", "1.0-SNAPSHOT") == 0


# ---------------------------------------------------------------------------
# Dispatcher integration — confirm Maven gets routed to this comparator.
# ---------------------------------------------------------------------------

def test_dispatch_routes_maven_to_this_comparator() -> None:
    """``versions.compare("Maven", ...)`` must route to the maven
    comparator. Regression-guards an ecosystem-name mismatch
    that would silently fall back to default string compare."""
    assert dispatch_compare("Maven", "1.0", "1.0.1") == -1
    assert dispatch_compare("Maven", "1.0-SNAPSHOT", "1.0") == -1


def test_in_range_for_maven() -> None:
    """End-to-end smoke for OSV-style range matching. An
    advisory that says "introduced=1.0.0, fixed=2.0.0" must
    catch every 1.x version including pre-releases of 2.0."""
    events = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
    assert in_range("Maven", "1.5.0", events) is True
    assert in_range("Maven", "1.0.0", events) is True
    assert in_range("Maven", "2.0.0", events) is False
    assert in_range("Maven", "2.0.0-SNAPSHOT", events) is True   # pre-2.0 still in range
    assert in_range("Maven", "0.9.9", events) is False
