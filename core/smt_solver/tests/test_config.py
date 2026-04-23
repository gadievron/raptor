"""Tests for core.smt_solver.config — BVProfile and pre-made profiles."""

import sys
from pathlib import Path

import pytest
from dataclasses import FrozenInstanceError

# core/smt_solver/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.smt_solver import (
    BVProfile,
    BV_X86_64,
    BV_AARCH64,
    BV_I386,
    BV_ARM32,
    BV_C_UINT64,
    BV_C_INT64,
    BV_C_UINT32,
    BV_C_INT32,
    BV_C_UINT16,
    BV_C_INT16,
    BV_C_UINT8,
    BV_C_INT8,
)


class TestBVProfileConstruction:
    def test_defaults_are_64_bit_unsigned(self):
        p = BVProfile()
        assert p.width == 64
        assert p.signed is False

    def test_custom_width_and_signed(self):
        p = BVProfile(width=32, signed=True)
        assert p.width == 32
        assert p.signed is True

    def test_non_standard_width_is_accepted(self):
        """Width isn't constrained to {8, 16, 32, 64} — csem supports
        arbitrary positive widths (e.g. 24-bit types in embedded code)."""
        p = BVProfile(width=24, signed=False)
        assert p.width == 24

    def test_zero_width_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            BVProfile(width=0)

    def test_negative_width_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            BVProfile(width=-1)


class TestBVProfileFrozen:
    """Profiles are immutable — attempted mutation must raise, not silently
    corrupt shared instances.  The pre-made constants (BV_X86_64, etc.) are
    shared across encoders; a stray ``BV_X86_64.width = 32`` would poison
    every subsequent call."""

    def test_cannot_mutate_width(self):
        p = BVProfile()
        with pytest.raises(FrozenInstanceError):
            p.width = 32  # type: ignore[misc]

    def test_cannot_mutate_signed(self):
        p = BVProfile()
        with pytest.raises(FrozenInstanceError):
            p.signed = True  # type: ignore[misc]

    def test_pre_made_profile_frozen(self):
        with pytest.raises(FrozenInstanceError):
            BV_X86_64.width = 32  # type: ignore[misc]


class TestBVProfileFormatting:
    def test_mode_tag_short_form(self):
        assert BVProfile(width=64, signed=False).mode_tag() == "bv64u"
        assert BVProfile(width=64, signed=True).mode_tag() == "bv64s"
        assert BVProfile(width=32, signed=False).mode_tag() == "bv32u"
        assert BVProfile(width=32, signed=True).mode_tag() == "bv32s"
        assert BVProfile(width=8, signed=True).mode_tag() == "bv8s"

    def test_describe_human_readable(self):
        assert BVProfile(width=64, signed=False).describe() == "64-bit unsigned"
        assert BVProfile(width=64, signed=True).describe() == "64-bit signed"
        assert BVProfile(width=32, signed=False).describe() == "32-bit unsigned"
        assert BVProfile(width=8, signed=True).describe() == "8-bit signed"


class TestEquality:
    def test_profiles_with_same_values_are_equal(self):
        assert BVProfile(width=32, signed=True) == BVProfile(width=32, signed=True)

    def test_pre_made_profiles_reuse_matching_shape(self):
        """BV_X86_64 and BV_AARCH64 both model 64-bit unsigned registers —
        they compare equal.  That's expected: the names express intent at
        the call site but the underlying profile is the same."""
        assert BV_X86_64 == BV_AARCH64
        assert BV_X86_64 == BVProfile(width=64, signed=False)


class TestPreMadeProfiles:
    """Pin the width/signed shape of every named constant so a rename or
    rebind gets caught by tests."""

    def test_architecture_profiles(self):
        assert (BV_X86_64.width, BV_X86_64.signed) == (64, False)
        assert (BV_AARCH64.width, BV_AARCH64.signed) == (64, False)
        assert (BV_I386.width, BV_I386.signed) == (32, False)
        assert (BV_ARM32.width, BV_ARM32.signed) == (32, False)

    def test_c_unsigned_int_profiles(self):
        assert (BV_C_UINT64.width, BV_C_UINT64.signed) == (64, False)
        assert (BV_C_UINT32.width, BV_C_UINT32.signed) == (32, False)
        assert (BV_C_UINT16.width, BV_C_UINT16.signed) == (16, False)
        assert (BV_C_UINT8.width, BV_C_UINT8.signed) == (8, False)

    def test_c_signed_int_profiles(self):
        assert (BV_C_INT64.width, BV_C_INT64.signed) == (64, True)
        assert (BV_C_INT32.width, BV_C_INT32.signed) == (32, True)
        assert (BV_C_INT16.width, BV_C_INT16.signed) == (16, True)
        assert (BV_C_INT8.width, BV_C_INT8.signed) == (8, True)
