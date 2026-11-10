"""Runtime decimal conversion limits must remain structured parser refusals."""

import sys

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8, BVProfile, parse_literal_value
from core.smt_solver.rejection import Rejection, RejectionKind


@pytest.fixture
def decimal_conversion_limit():
    previous = sys.get_int_max_str_digits()
    limit = sys.int_info.str_digits_check_threshold
    try:
        sys.set_int_max_str_digits(limit)
        yield limit
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.parametrize("negative", [False, True], ids=["positive", "negative"])
def test_conversion_limit_returns_an_anchored_rejection(decimal_conversion_limit, negative):
    token = ("-" if negative else "") + "9" * (decimal_conversion_limit + 1)
    text = "Count == " + token
    result = parse_literal_value(token, BV_C_INT8, outer_text=text)
    assert isinstance(result, Rejection)
    assert result.kind == RejectionKind.INPUT_TOO_LONG
    assert result.text == text
    assert "conversion limit" in result.detail
    assert sys.get_int_max_str_digits() == decimal_conversion_limit


@pytest.mark.parametrize("shape", ["relational", "arithmetic", "negative"])
def test_guard_below_character_cap_discloses_conversion_refusal(decimal_conversion_limit, shape):
    pytest.importorskip("z3")
    from core.smt_solver import path_feasibility as paths

    token = "9" * (decimal_conversion_limit + 1)
    text = {"relational": f"Value == {token}", "arithmetic": f"Value + {token} == 0",
            "negative": f"Value == -{token}"}[shape]
    assert len(text) < paths._MAX_CONDITION_CHARS
    result = paths.check_path_feasibility(
        [paths.PathCondition(text, 0)], profile=BV_C_INT8, reduce_constraints=False,
    )
    assert result.feasible is None and result.model == {} and result.wp_complete is False
    assert result.unknown == [text]
    assert result.unknown_reasons[0].kind == RejectionKind.INPUT_TOO_LONG
    assert result.unknown_reasons[0].text == text


def test_conversion_limit_preserves_existing_literal_domains(decimal_conversion_limit):
    assert parse_literal_value("255", BV_C_UINT8) == 255
    assert parse_literal_value("-128", BV_C_INT8) == -128
    assert parse_literal_value("0xff", BV_C_INT8) == 255
    ambiguous = parse_literal_value("0" + "9" * (decimal_conversion_limit + 1), BV_C_UINT8)
    assert isinstance(ambiguous, Rejection) and ambiguous.kind == RejectionKind.LITERAL_AMBIGUOUS
    wide_hex = parse_literal_value("0x" + "f" * (decimal_conversion_limit + 1), BV_C_UINT8)
    assert isinstance(wide_hex, Rejection) and wide_hex.kind == RejectionKind.LITERAL_OUT_OF_RANGE


def test_conversion_budget_is_distinct_from_the_profile_range(decimal_conversion_limit):
    profile = BVProfile(decimal_conversion_limit * 4, False)
    value = 10 ** decimal_conversion_limit + 1
    token = "1" + "0" * (decimal_conversion_limit - 1) + "1"
    result = parse_literal_value(token, profile)
    assert isinstance(result, Rejection) and result.kind == RejectionKind.INPUT_TOO_LONG
    assert result.text == token
    assert parse_literal_value(hex(value), profile) == value
    assert sys.get_int_max_str_digits() == decimal_conversion_limit
