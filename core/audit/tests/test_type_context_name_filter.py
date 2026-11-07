"""Literal name admission avoids work without changing declaration evidence."""

import pytest

from core.audit import context


@pytest.fixture(autouse=True)
def owned_type_cache(monkeypatch):
    monkeypatch.setattr(context, '_type_definition_cache', context.BoundedMemo(64))
    monkeypatch.setattr(context, '_header_cache', context.BoundedMemo(16))


def test_absent_native_name_does_not_split_the_header(monkeypatch):
    def unexpected(*args):
        raise AssertionError('absent type caused a full-header split')

    monkeypatch.setattr(context, 'split_lines', unexpected)
    assert context._extract_type_definition_uncached('// unrelated declaration\n' * 20000, 'Token_t') is None


@pytest.mark.parametrize('declaration', [
    pytest.param('struct Token_t { int value; };', id='struct'),
    pytest.param('enum Token_t { READY };', id='enum'),
    pytest.param('typedef int Token_t;', id='scalar-alias'),
    pytest.param('typedef struct {\n int value;\n} Token_t;', id='anonymous-alias'),
    pytest.param('typedef struct Tagged {\n int value;\n} Token_t;', id='tagged-alias'),
])
def test_declarations_after_unrelated_lines_keep_coordinates_and_source(declaration):
    prefix = '// unrelated\n' * 200
    assert context._extract_type_definition_uncached(prefix + declaration + '\n', 'Token_t') == {
        'line': 201, 'source': declaration,
    }


def test_present_name_in_non_declaration_still_uses_declaration_rules():
    assert context._extract_type_definition_uncached('// Token_t\nToken_t *value;\n', 'Token_t') is None


def test_regex_metacharacters_in_requested_name_remain_literal():
    assert context._extract_type_definition_uncached('struct Token_t { int value; };', 'Token.*') is None
    assert context._extract_type_definition_uncached('struct Token.* { int value; };', 'Token.*') == {
        'line': 1, 'source': 'struct Token.* { int value; };',
    }


def test_crlf_and_unicode_do_not_change_the_source_line_model():
    source = '// unrelated\u2028text\r\nstruct Cañón_t { int value; };\r\n'
    assert context._extract_type_definition_uncached(source, 'Cañón_t') == {
        'line': 2, 'source': 'struct Cañón_t { int value; };',
    }


@pytest.mark.parametrize('subclass_argument', ['content', 'name'])
def test_string_subclasses_keep_legacy_splitting(monkeypatch, subclass_argument):
    class AdapterText(str):
        def __contains__(self, other):
            if other == 'Token_t':
                raise AssertionError('adapter type-name containment was called')
            return super().__contains__(other)

    actual_split = context.split_lines
    calls = []

    def counted(text):
        calls.append(text)
        return actual_split(text)

    monkeypatch.setattr(context, 'split_lines', counted)
    content, name = 'struct Other { int value; };', 'Token_t'
    if subclass_argument == 'content':
        content = AdapterText(content)
    else:
        name = AdapterText(name)
    assert context._extract_type_definition_uncached(content, name) is None
    assert len(calls) == 1


def test_resolver_keeps_first_header_and_rereads_after_edits(tmp_path):
    (tmp_path / 'first.h').write_text('struct Token_t { int first; };\n')
    (tmp_path / 'second.h').write_text('struct Token_t { int second; };\n')
    metadata = {'parameters': [{'type': 'struct Token_t *', 'name': 'value'}]}
    first = context._resolve_types(tmp_path, 'f.c', metadata, '')
    assert first == [{'name': 'Token_t', 'file': 'first.h', 'line': 1,
                      'source': 'struct Token_t { int first; };'}]
    (tmp_path / 'first.h').write_text('struct Other { int first; };\n')
    second = context._resolve_types(tmp_path, 'f.c', metadata, '')
    assert second == [{'name': 'Token_t', 'file': 'second.h', 'line': 1,
                       'source': 'struct Token_t { int second; };'}]


@pytest.mark.parametrize('unresolved,max_types,expected_reads', [
    pytest.param(False, 5, 1, id='all-names-resolved'),
    pytest.param(True, 5, 50, id='missing-name-needs-remaining-headers'),
    pytest.param(True, 1, 1, id='result-cap-still-stops-reads'),
])
def test_header_reads_stop_only_when_no_more_results_are_possible(
    tmp_path, monkeypatch, unresolved, max_types, expected_reads,
):
    for i in range(50):
        (tmp_path / f'{i:02d}.h').write_text('struct Token_t { int value; };\n')
    real_read = context._read_target_text
    reads = []

    def read(path, *, target_root=None):
        reads.append(path.name)
        assert target_root == tmp_path
        return real_read(path, target_root=target_root)

    monkeypatch.setattr(context, '_read_target_text', read)
    source = 'struct Token_t *value;' + (' struct Missing_t *other;' if unresolved else '')
    result = context._resolve_types(tmp_path, 'f.c', {}, source, max_types)
    assert result == [{'name': 'Token_t', 'file': '00.h', 'line': 1,
                       'source': 'struct Token_t { int value; };'}]
    assert reads == [f'{i:02d}.h' for i in range(expected_reads)]
