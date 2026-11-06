"""Go type lookup reuses canonical bytes and preserves discovery order."""

import pytest

from core.audit import go_type_context as types
from core.audit.callsite_consistency import parse_source_cached


@pytest.fixture(autouse=True)
def grammar():
    if parse_source_cached('a.go', 'package p\ntype Record struct{}\n')[0] is None:
        pytest.skip('requires tree-sitter Go')


def test_package_and_definition_lookup_share_encoded_text(tmp_path, monkeypatch):
    (tmp_path / 'record.go').write_text('package p\n// 界\ntype Record struct { Field string }\n')
    package_data = []
    definition_data = []
    package = types._package
    definitions = types._definitions

    def read_package(tree, data):
        package_data.append(data)
        return package(tree, data)

    def read_definitions(tree, data, text):
        definition_data.append(data)
        return definitions(tree, data, text)

    monkeypatch.setattr(types, '_package', read_package)
    monkeypatch.setattr(types, '_definitions', read_definitions)
    result = types.resolve_go_types(tmp_path, 'record.go', {'class_name': 'Record'}, '')
    assert [row['name'] for row in result] == ['Record']
    assert len(package_data) == len(definition_data) == 1
    assert package_data[0] is definition_data[0]


def test_invalid_utf8_uses_repaired_parse_offsets(tmp_path):
    (tmp_path / 'record.go').write_bytes(
        b'// malformed: \xff\npackage p\n// record\ntype Record struct { Field string }\n',
    )
    result = types.resolve_go_types(tmp_path, 'record.go', {'class_name': 'Record'}, '')
    assert [row['name'] for row in result] == ['Record']
    assert 'Field string' in result[0]['source']


def test_type_names_keep_first_occurrence_order_and_exclude_imports():
    text = 'package p\nfunc F(a Zed, b Alpha, c Zed, d pkg.External, e map[string]Beta) {}\n'
    tree, _ = parse_source_cached('a.go', text)
    assert types._type_names(tree, text.encode()) == ['Zed', 'Alpha', 'Beta']


def test_alias_reference_queue_keeps_existing_order_and_deduplicates(tmp_path):
    (tmp_path / 'record.go').write_text(
        'package p\ntype Head = Pair[Leaf, Leaf]\n'
        'type Pair[A, B any] struct {}\ntype Leaf struct {}\n',
    )
    result = types.resolve_go_types(tmp_path, 'record.go', {'class_name': 'Head'}, '', max_types=5)
    assert [row['name'] for row in result] == ['Head', 'Pair', 'Leaf']
