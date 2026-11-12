"""Unadmitted Unicode operators and identifier continuations stay attached."""

import pytest

from core.audit.invariant_smt import extract_invariants


@pytest.mark.parametrize("text", [
    "Count <= Limit ≤ Other", "Count <= Limit ∧ Flag", "¬Count <= Limit",
    "Count × Scale <= Limit", "Count <= Limit → Other",
    "Count <= Limit\n∧ Flag > 0", "Count <= Limit ∧\nFlag > 0",
    "Count <= Limit\u0301", "A\u0301Count <= Limit",
    "Count <= Limit\u200dSuffix", "A\u200dCount <= Limit",
], ids=["comparison", "conjunction", "negation", "multiplication", "implication",
        "leading-join", "trailing-join", "right-mark", "left-mark", "right-format", "left-format"])
def test_unicode_boundaries_do_not_change_the_extracted_question(text):
    assert extract_invariants(text) == []


@pytest.mark.parametrize("text,expected", [
    ("Counté <= Limité", ["Counté <= Limité"]),
    ("State.Counté <= State.Limité.", ["State.Counté <= State.Limité"]),
    ("• Count <= Limit", ["Count <= Limit"]),
    ("Count <= Limit。", ["Count <= Limit"]),
])
def test_supported_identifiers_and_prose_punctuation_remain_available(text, expected):
    assert extract_invariants(text) == expected
