"""Necessary scan admission retains loop state and witness precedence."""

import pytest

from core.audit import resource_bounds as rb


def test_pending_loop_survives_brace_free_lines():
    lines = ['for (i=0; i<n; i++)', '', '{', 'work();',
             'while (next)', '{', 'work();', '}', '}', 'outside();']
    assert rb._loop_lines(lines, 10) == {12, 13, 14, 15, 16, 17}


def test_custom_code_keeps_original_loop_path():
    class Code(str):
        def __contains__(self, other):
            pytest.fail('Native-only admission called a custom method')

    class Raw(str):
        def split(self, separator, maxsplit):
            return [Code(str(self))]

    assert rb._loop_lines([Raw('for (;;) {'), Raw('work();'), Raw('}')], 1) == {1, 2}


def test_parenthesis_free_lines_skip_site_pattern(monkeypatch):
    class UnexpectedScan:
        def search(self, text):
            pytest.fail('Site scan ran without its required parenthesis')

    monkeypatch.setattr(rb, '_STEM_INSERT_RE', UnexpectedScan())
    assert rb._enumerate_sites(['alpha += beta;', 'ordinary_identifier;'], 1,
                               {}, {}, file_path='x.c') == []


def test_clamp_free_lines_skip_clamp_pattern(monkeypatch):
    class UnexpectedScan:
        def finditer(self, text):
            pytest.fail('Clamp scan ran without either required spelling')

    monkeypatch.setattr(rb, '_CLAMP_RE', UnexpectedScan())
    assert rb._clamp_witness(['count = length;', 'malloc(count);'], 1, 3,
                             None, frozenset(), file_path='x.c') is None


@pytest.mark.parametrize('name', ['min', 'MIN'], ids=['lowercase', 'uppercase'])
def test_both_clamp_spellings_keep_receipt(name):
    lines = [f'count = {name}(count, MAX);', 'for (i=0; i<count; i++) {',
             'malloc(1);', '}']
    assert rb._clamp_witness(lines, 10, 12, {'MAX': 100}, frozenset(),
                             file_path='x.c') == {
        'condition': 'for (i=0; i<count; i++) {', 'count': 'count', 'bound': 'MAX',
        'bound_source': 'clamp-min', 'clamp_line': 10,
    }


def test_exact_insert_keeps_precedence_over_naming_and_allocation():
    sites = rb._enumerate_sites(
        ['for (;;) {', 'queue_insert(x); malloc(y);', '}'], 7,
        {'queue_insert': ('study', 'learned')}, {'malloc': ('seed', 'seed')},
        file_path='x.c',
    )
    assert [(s.line, s.verb, s.kind, s.vocab_source) for s in sites] == [
        (8, 'queue_insert', 'insert', 'study'),
    ]
