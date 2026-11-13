"""Hexadecimal type metadata does not construct profile-sized thresholds."""

import pytest

from core.smt_solver import path_feasibility as paths
from core.smt_solver.config import BVProfile
from core.smt_solver.rejection import Rejection, RejectionKind, parse_literal_value


@pytest.fixture(autouse=True)
def no_native_work(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("literal type metadata entered native construction")
    monkeypatch.setattr(paths, "z3", None)
    for name in ("_mk_val", "_mk_var", "_new_solver", "_new_optimizer"):
        monkeypatch.setattr(paths, name, forbidden)


@pytest.mark.parametrize("width", [1, 2, 7, 8, 16, 32, 64, 257, 4096])
@pytest.mark.parametrize("signed", [False, True])
def test_unsigned_choice_matches_existing_threshold_convention(width, signed):
    half, upper = 1 << (width - 1), 1 << width
    values = {0, 1, half - 1, half, half + 1, upper - 1, upper, upper + 1}
    for value in values:
        assert paths._hex_literal_forces_unsigned(hex(value), BVProfile(width, signed)) is (
            signed and value >= half
        )


@pytest.mark.parametrize("token", ["0x0", "0x1", "0XFF", "0x80000000"])
@pytest.mark.parametrize("signed", [False, True])
def test_native_maximum_profile_width_tiny_metadata_needs_no_sort(token, signed):
    assert paths._hex_literal_forces_unsigned(token, BVProfile((1 << 32) - 1, signed)) is False


@pytest.mark.parametrize("token", ["0x", "-0x1", "123", "0x1 trailing", " 0x1", "0xg"])
def test_non_hex_shapes_keep_existing_false_result(token):
    assert paths._hex_literal_forces_unsigned(token, BVProfile(8, True)) is False


def test_type_choice_does_not_admit_an_out_of_range_literal():
    profile = BVProfile(8, True)
    assert paths._hex_literal_forces_unsigned("0x100", profile) is True
    result = parse_literal_value("0x100", profile)
    assert isinstance(result, Rejection)
    assert result.kind == RejectionKind.LITERAL_OUT_OF_RANGE
