"""Shared C-family decimal literals use ASCII source spellings."""

import pytest

from core.smt_solver.config import BVProfile
from core.smt_solver.rejection import Rejection, RejectionKind, parse_literal_value


def test_unicode_zero_cannot_bypass_ascii_octal_ambiguity_admission():
    result = parse_literal_value('\u066012', BVProfile(8, True))
    assert isinstance(result, Rejection)
    assert result.kind == RejectionKind.UNRECOGNIZED_OPERAND


@pytest.mark.parametrize('token', ['\u0661', '-\u0661', '1\u0662', '\u06f0\u06f1', '\u0967', '\uff11', '0\u0661'])
def test_unicode_and_mixed_decimal_spellings_decline_with_original_anchor(token):
    text = 'Value == '+token
    result = parse_literal_value(token, BVProfile(8, True), outer_text=text)
    assert isinstance(result, Rejection)
    assert result.kind == RejectionKind.UNRECOGNIZED_OPERAND
    assert result.text == text


@pytest.mark.parametrize('token', ['\u0661', '-\u0661', '\u066012'])
def test_expression_frame_declines_before_native_literal_allocation(monkeypatch, token):
    from core.smt_solver import path_feasibility as paths

    def forbidden(*args, **kwargs):
        raise AssertionError('unsupported decimal reached native allocation')

    variables = {}
    with monkeypatch.context() as scope:
        scope.setattr(paths, '_mk_val', forbidden)
        scope.setattr(paths, '_mk_var', forbidden)
        result = paths._parse_typed_expr_in_frame(token, variables, profile=BVProfile(8, True))
    assert isinstance(result, Rejection)
    assert result.kind == RejectionKind.UNRECOGNIZED_OPERAND
    assert result.text == token
    assert variables == {}


@pytest.mark.parametrize('token,signed,expected', [('0', False, 0), ('255', False, 255), ('-128', True, -128), ('127', True, 127), ('0xff', True, 255)])
def test_ascii_decimal_and_hex_domains_remain_supported(token, signed, expected):
    assert parse_literal_value(token, BVProfile(8, signed)) == expected


def test_ascii_leading_zero_keeps_specific_ambiguity_refusal():
    result = parse_literal_value('01', BVProfile(8, False))
    assert isinstance(result, Rejection)
    assert result.kind == RejectionKind.LITERAL_AMBIGUOUS


@pytest.mark.parametrize("token,expected", [("7", 7), ("0xff", 255), ("999", RejectionKind.LITERAL_OUT_OF_RANGE),
                                            ("012", RejectionKind.LITERAL_AMBIGUOUS)])
def test_literal_subclasses_cannot_replace_stored_source_characters(token, expected):
    events = []

    class Literal(str):
        def __int__(self):
            events.append("integer")
            return 0

        def lstrip(self, *args):
            events.append("strip")
            return "1"

        def __str__(self):
            events.append("string")
            return "0"

    result = parse_literal_value(Literal(token), BVProfile(8, False))
    if isinstance(expected, RejectionKind):
        assert isinstance(result, Rejection)
        assert result.kind is expected
        assert type(result.text) is str and result.text == token
    else:
        assert type(result) is int and result == expected
    assert events == []


def test_make_val_preserves_literal_digits_at_native_factory(monkeypatch):
    from core.smt_solver import path_feasibility as paths

    class Literal(str):
        def __int__(self):
            return 0

    seen, result = [], object()
    def construct(value, width):
        seen.append((value, width))
        return result

    monkeypatch.setattr(paths, "_mk_val", construct)
    assert paths.make_val(Literal("7"), profile=BVProfile(8, False)) is result
    assert seen == [(7, 8)]


def test_protocol_literal_range_refusal_retains_outer_source_anchor(monkeypatch):
    from core.smt_solver import path_feasibility as paths

    class Literal(str):
        def __int__(self):
            return 0

    result = parse_literal_value(Literal("999"), BVProfile(8, False), outer_text="Count == 999")
    assert isinstance(result, Rejection) and result.kind is RejectionKind.LITERAL_OUT_OF_RANGE
    assert result.text == "Count == 999"
    def forbidden(*args):
        raise AssertionError("out-of-range source literal reached native factory")

    monkeypatch.setattr(paths, "_mk_val", forbidden)
    with pytest.raises(ValueError, match="rejected"):
        paths.make_val(Literal("999"), profile=BVProfile(8, False))
