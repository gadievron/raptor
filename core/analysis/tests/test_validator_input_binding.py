"""Primitive-entry facts must be local, exact-source and narrowly scoped."""
from hashlib import sha256

import pytest

from core.analysis.validator_input_binding import adjacent_native_string_input


def _source(binding):
    return 'function handle(other) {\n ' + binding + '\n if (!/^[a-z]+$/.test(value)) return;\n consume(value);\n}\n'


@pytest.mark.parametrize('binding', ['const value = "abc";', 'let value = ("abc");'], ids=['const', 'parenthesised-let'])
def test_one_adjacent_lexical_string_has_a_scoped_byte_bound_fact(binding):
    pytest.importorskip('tree_sitter_javascript')
    source = _source(binding)
    fact = adjacent_native_string_input(source, 'value', 3, language='javascript')
    assert fact is not None
    assert fact.source_digest == sha256(source.encode()).hexdigest()
    assert fact.variable == 'value'
    assert fact.binding_span[0] == fact.binding_span[2] == 2
    assert fact.validator_span[0] == 3
    assert fact.scope == 'primitive-string-at-validator-entry'
    assert fact.origin == 'adjacent-local-lexical-string-literal'
    changed = adjacent_native_string_input(source + '// source changed\n', 'value', 3, language='javascript')
    assert changed is not None and changed.source_digest != fact.source_digest


@pytest.mark.parametrize('binding', [
    'var value = "abc";', 'value = "abc";', 'const other = "abc";',
    'const value = {};', 'const value = ["abc"];', 'const value = String(other);',
    'const value = "abc", next = mutate();', 'const {value} = other;',
    'const value = "abc"; mutate();', 'if (other) { const value = "abc"; }',
], ids=['var', 'assignment', 'different-name', 'object', 'array', 'call',
        'later-initialiser', 'destructuring', 'intervening-call', 'different-scope'])
def test_other_bindings_cannot_supply_this_primitive_fact(binding):
    pytest.importorskip('tree_sitter_javascript')
    assert adjacent_native_string_input(_source(binding), 'value', 3, language='javascript') is None


def test_comments_are_not_intervening_execution():
    pytest.importorskip('tree_sitter_javascript')
    source = _source('const value = "abc"; /* comment */')
    assert adjacent_native_string_input(source, 'value', 3, language='javascript') is not None


@pytest.mark.parametrize('language', ['typescript', 'tsx'])
def test_native_typed_profiles_share_only_the_literal_fact(language):
    pytest.importorskip('tree_sitter_typescript')
    source = _source('const value: string = "abc";')
    assert adjacent_native_string_input(source, 'value', 3, language=language) is not None
    uninitialised = _source('let value: string;')
    assert adjacent_native_string_input(uninitialised, 'value', 3, language=language) is None


def test_a_parameter_annotation_alone_is_not_literal_evidence():
    pytest.importorskip('tree_sitter_typescript')
    source = 'function handle(value: string) {\n if (!/^[a-z]+$/.test(value)) return;\n consume(value);\n}\n'
    assert adjacent_native_string_input(source, 'value', 2, language='typescript') is None
