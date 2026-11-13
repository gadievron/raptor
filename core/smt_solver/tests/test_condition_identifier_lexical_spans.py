"""Non-code text cannot nominate optional witness objectives."""

import pytest

from core.smt_solver.condition_syntax import plain_condition_identifiers


@pytest.mark.parametrize("text", [
    'R"d(Secret "Phantom" tail)d" == Value',
    'u8"Ghost" == Value',
    "L'X' == Value",
    '/* Ghost */ Value > 0',
    'Value > 0 // Ghost',
    'check /* Ghost */ (Hidden, nested(Other)) == Value',
])
def test_non_code_names_are_not_candidates(text):
    assert plain_condition_identifiers(text) == ("Value",)


@pytest.mark.parametrize("text", [
    'Value == "unfinished',
    'Value /* unfinished',
    'Value == R"d(unfinished',
    'Value == "bare\nnewline"',
])
def test_incomplete_lexical_structure_declines_candidates(text):
    assert plain_condition_identifiers(text) == ()


@pytest.mark.parametrize("text", [
    'check("??/") == Value',
    'check("escaped\\\nline") == Value',
])
def test_opaque_calls_keep_original_translation_refusals(text):
    assert plain_condition_identifiers(text) == ()


def test_code_identity_order_and_literal_prefix_boundaries():
    assert plain_condition_identifiers('Value + value + Value + NULL + null') == (
        "Value", "value", "null",
    )
    assert plain_condition_identifiers('myu8"Ghost" == Value') == ("myu8", "Value")
    assert plain_condition_identifiers('u"Ghost" + U"Other" + L"Tail" == Value') == ("Value",)
    assert plain_condition_identifiers("Value" * 410) == ()
