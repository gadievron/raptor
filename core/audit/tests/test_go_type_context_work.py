"""Go context avoids unused source copies while retaining parser offsets."""

from collections import OrderedDict

import pytest

from core.audit import callsite_consistency as parsing
from core.audit import go_type_context as types


@pytest.fixture(autouse=True)
def owned_parses(monkeypatch):
    monkeypatch.setattr(parsing, '_parse_cache', OrderedDict())
    if parsing.parse_source_cached('probe.go', 'package p\n')[0] is None:
        pytest.skip('requires tree-sitter Go')


def test_file_without_type_declarations_does_not_split_lines(monkeypatch):
    text = 'package p\n' + 'func read() { consume() }\n' * 100
    tree, _ = parsing.parse_source_cached('reader.go', text)

    def unexpected(*args):
        raise AssertionError('function-only file was split for type excerpts')

    monkeypatch.setattr(types, 'split_lines', unexpected)
    assert types._definitions(tree, text.encode(), text) == {}


def test_multiple_type_declarations_split_the_source_once(monkeypatch):
    text = 'package p\n// Handle aliases Record.\ntype Handle = Record\ntype Record struct { Value int }\n'
    tree, _ = parsing.parse_source_cached('reader.go', text)
    real_split = types.split_lines
    splits = []

    def split(source):
        splits.append(source)
        return real_split(source)

    monkeypatch.setattr(types, 'split_lines', split)
    result = types._definitions(tree, text.encode(), text)
    assert list(result) == ['Handle', 'Record']
    assert result['Handle'] == ({'name': 'Handle', 'line': 2,
        'source': '// Handle aliases Record.\ntype Handle = Record'}, ['Record'])
    assert result['Record'] == ({'name': 'Record', 'line': 4,
        'source': 'type Record struct { Value int }'}, [])
    assert splits == [text]


def test_string_adapter_retains_its_eager_split(monkeypatch):
    class Adapter(str):
        pass

    text = Adapter('package p\nfunc read() {}\n')
    tree, _ = parsing.parse_source_cached('reader.go', str(text))
    real_split = types.split_lines
    seen = []

    def split(source):
        seen.append(source)
        return real_split(source)

    monkeypatch.setattr(types, 'split_lines', split)
    assert types._definitions(tree, text.encode(), text) == {}
    assert len(seen) == 1 and seen[0] is text


@pytest.mark.parametrize('prefix', [
    pytest.param(b'// ASCII comment\n', id='ascii'),
    pytest.param('// Café\n'.encode(), id='unicode'),
    pytest.param(b'// \xff\xf0\x9f\n', id='invalid-utf8'),
])
def test_resolver_reuses_only_identical_ascii_source_bytes(tmp_path, monkeypatch, prefix):
    raw = b'package p\n' + prefix + b'type Record struct { Value int }\n'
    path = tmp_path / 'reader.go'
    path.write_bytes(raw)
    real_read = types.read_bytes_capped
    real_definitions = types._definitions
    reads = []
    encoded = []

    def read(*args, **kwargs):
        got = real_read(*args, **kwargs)
        if got is not None:
            reads.append(got[0])
        return got

    def definitions(tree, data, text):
        encoded.append(data)
        assert data == text.encode('utf-8', 'replace')
        return real_definitions(tree, data, text)

    monkeypatch.setattr(types, 'read_bytes_capped', read)
    monkeypatch.setattr(types, '_definitions', definitions)
    result = types.resolve_go_types(tmp_path, 'reader.go', {'class_name': 'Record'}, 'func (r *Record) Read() {}')
    expected_comment = prefix.decode('utf-8', 'replace').rstrip('\n')
    assert result == [{'name': 'Record', 'line': 2,
                      'source': expected_comment + '\ntype Record struct { Value int }', 'file': 'reader.go'}]
    assert len(reads) == len(encoded) == 1
    assert (encoded[0] is reads[0]) == (prefix.isascii())
