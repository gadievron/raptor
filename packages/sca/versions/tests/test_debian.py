"""Tests for the Debian (dpkg) version comparator.

Cases mirror ``dpkg --compare-versions`` behaviour (Debian Policy
§5.6.12) and the canonical dpkg test suite: epoch dominance, the ``~``
ordering quirk, numeric vs lexical runs, leading-zero equality, and
revision handling. Comparator is also exercised through the
``versions.compare("Debian", ...)`` dispatcher and ``in_range``.
"""

from __future__ import annotations

import pytest

from packages.sca.versions import VersionError, compare, in_range
from packages.sca.versions.debian import compare as deb_cmp


# (a, b, expected sign) — and every pair is also checked for antisymmetry.
_CASES = [
    # Plain ordering.
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("2.0", "1.0", 1),
    ("1.0.0", "1.0", 1),          # extra component sorts higher (non-empty > end)
    # Numeric runs compare numerically, not lexically.
    ("1.10", "1.9", 1),
    ("1.2", "1.10", -1),
    ("0.99", "1.0", -1),
    # Leading zeros are ignored within a digit run.
    ("1.007", "1.7", 0),
    ("1.0", "1.00", 0),
    # Epoch dominates everything.
    ("1:0.1", "2.0", 1),
    ("2.0", "1:0.1", -1),
    ("1:1.0", "2:0.1", -1),
    ("0:1.0", "1.0", 0),          # explicit epoch 0 == no epoch
    # Debian revision.
    ("1.0-1", "1.0-2", -1),
    ("1.0-10", "1.0-9", 1),       # revision compared numerically too
    ("1.0", "1.0-1", -1),         # no revision (== "0") < revision 1
    ("1.0-0", "1.0", 0),          # revision "0" == no revision
    # The ~ quirk: sorts before everything, including end-of-string.
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~~", "1.0~~a", -1),
    ("1.0~~a", "1.0~", -1),
    ("1.0~", "1.0", -1),
    # Trailing letters sort after end-of-string (letter order > 0).
    ("1.0a", "1.0", 1),
    ("1.0a", "1.0b", -1),
    # Letters sort before non-letter punctuation in a non-digit run.
    ("1.0a", "1.0+", -1),
    # Real-world gcc-defaults shape that motivated this (epoch 4, modern
    # upstream) must outrank the ancient woody source package.
    ("2.95.2-20", "4:14.2.0-1", -1),
]


@pytest.mark.parametrize("a,b,expected", _CASES)
def test_compare_cases(a: str, b: str, expected: int) -> None:
    assert deb_cmp(a, b) == expected
    # Antisymmetry: reversing the operands negates the sign.
    assert deb_cmp(b, a) == -expected


def test_reflexive_for_distinct_shapes() -> None:
    for v in ("1.0", "1:2.3-4", "1.0~rc1", "2.95.2-20", "4:14.2.0-1"):
        assert deb_cmp(v, v) == 0


def test_dispatcher_routes_to_debian() -> None:
    """``versions.compare`` with any Debian alias hits this comparator."""
    assert compare("Debian", "1.0~rc1", "1.0") == -1
    assert compare("apt", "1:0.1", "2.0") == 1
    assert compare("deb", "1.007", "1.7") == 0


def test_in_range_via_dispatcher() -> None:
    """OSV-style range matching dispatches to the Debian comparator."""
    events = [{"introduced": "1.0"}, {"fixed": "1.0-3"}]
    assert in_range("Debian", "1.0-1", events) is True
    assert in_range("Debian", "1.0-3", events) is False     # fixed is exclusive
    assert in_range("Debian", "1.0~rc1", events) is False   # below introduced


def test_invalid_epoch_raises_version_error() -> None:
    """A non-numeric epoch surfaces as VersionError through the dispatcher."""
    with pytest.raises(VersionError):
        compare("Debian", "x:1.0", "1.0")


def test_epoch_with_colon_in_upstream() -> None:
    """Only the first ``:`` is the epoch separator; later colons are upstream."""
    # epoch 1, upstream "1.2:3" both sides -> equal.
    assert deb_cmp("1:1.2:3", "1:1.2:3") == 0
    # Higher epoch still wins regardless of a colon further in.
    assert deb_cmp("2:0.1:0", "1:9.9:9") == 1
