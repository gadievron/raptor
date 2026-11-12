"""Alternative operator words cannot be removed as surrounding prose."""

import pytest

from core.audit.invariant_smt import extract_invariants


@pytest.mark.parametrize("text", [
    "not Count <= Limit", "compl Count <= Limit",
    "Count bitand Mask <= Limit", "Count bitor Mask <= Limit", "Count xor Mask <= Limit",
    "Count <= Limit and Flag", "Count <= Limit or Flag", "Count <= not Limit", "Count <= compl Limit",
    "not\nCount <= Limit", "Count <= Limit\nand Flag > 0",
    "Count <= Limit and\nFlag > 0",
], ids=["not", "compl", "bitand", "bitor", "xor", "and", "or", "right-not", "right-compl",
        "multiline-not", "leading-join", "trailing-join"])
def test_alternative_operators_do_not_mint_a_different_invariant(text):
    assert extract_invariants(text) == []


@pytest.mark.parametrize("text,expected", [
    ("not <= Limit", ["not <= Limit"]),
    ("Count <= not", ["Count <= not"]),
    ("State.not <= State.compl", ["State.not <= State.compl"]),
    ("the invariant Not <= Limit holds", ["Not <= Limit"]),
    ("Count <= and\nUsed <= Capacity", ["Count <= and", "Used <= Capacity"]),
    ("Count <= Limit\nnot <= Capacity", ["Count <= Limit", "not <= Capacity"]),
])
def test_complete_identifier_uses_and_case_sensitive_prose_are_preserved(text, expected):
    assert extract_invariants(text) == expected


@pytest.mark.parametrize("word", ["and", "or", "xor", "bitand", "bitor", "and_eq", "or_eq", "xor_eq", "not_eq"])
@pytest.mark.parametrize("side", ["left", "right"])
def test_every_alternative_binary_operator_remains_attached(word, side):
    text = f"Other {word} Count <= Limit" if side == "left" else f"Count <= Limit {word} Other"
    assert extract_invariants(text) == []


@pytest.mark.parametrize("text", [
    "not largest_acked_pkt <= highest_sent",
    "largest_acked_pkt <= highest_sent and PeerFlag",
])
def test_protocol_dispatch_does_not_schedule_the_changed_question(text):
    from core.audit.protocol_state import classify_protocol_state_hypothesis

    _fires, invariant = classify_protocol_state_hypothesis(text)
    assert invariant is None
