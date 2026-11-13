"""Alias lookup follows its regex without folding source identifier names."""

import pytest

from core.smt_solver.canonicalise import canonicalise


def test_regex_admitted_long_s_alias_uses_existing_equality_mapping():
    assert canonicalise('Count equalſ Limit') == 'Count == Limit'


@pytest.mark.parametrize('text,expected', [
    ('Count exceedſ Limit', 'Count > Limit'),
    ('Count EQUALſ Limit', 'Count == Limit'),
    ('Count EQUALS Limit', 'Count == Limit'),
    ('Count ExCeEdS Limit', 'Count > Limit'),
    ('Count BELOW Limit', 'Count < Limit'),
])
def test_existing_case_insensitive_alias_language(text, expected):
    rewritten = canonicalise(text)
    assert rewritten == expected
    assert canonicalise(rewritten) == rewritten


@pytest.mark.parametrize('text', [
    'equalſValue + Count < count',
    'Count equalß Limit',
    'equalſ Limit',
    'Count equalſ',
    '(Type) equalſ - 1',
    '(Type) equalſ (Count)',
    '"Count equalſ Limit"',
    'R"d(Count exceedſ Limit)d"',
    'Count /* equalſ Limit */ > 0',
    'Count // exceedſ Limit',
])
def test_source_identifiers_ambiguities_and_non_code_are_preserved(text):
    assert canonicalise(text) == text


def test_only_captured_operator_alias_is_case_folded():
    assert canonicalise('Count equalſ count') == 'Count == count'
