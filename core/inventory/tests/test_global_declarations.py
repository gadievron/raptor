"""Regression coverage for named declarations lost to interstitials (#1077)."""

import pytest

from core.inventory import build_inventory, extract_items, update_coverage
from core.inventory.extractors import KIND_CLASS, KIND_GLOBAL, _ts_parser_for


CASES = [
    ('rust', 'rs', 'const LIMIT: usize = 4;\nstatic READY: bool = false;\n', {'LIMIT', 'READY'}),
    ('csharp', 'cs', 'namespace App { class Config { const int A=1, B=2; static int state=3; } }', {'A', 'B', 'state'}),
    ('ruby', 'rb', 'LIMIT = 4\n$state = 1\na, b = 1, 2\n', {'LIMIT', '$state', 'a', 'b'}),
    ('php', 'php', '<?php namespace App { const A=1, B=2; $state=3; }', {'A', 'B', '$state'}),
    ('kotlin', 'kt', 'const val LIMIT = 4\nval (a, b) = Pair(1, 2)\n', {'LIMIT', 'a', 'b'}),
    ('swift', 'swift', 'let limit = 4, other = 2\nlet (a, b) = (1, 2)\n', {'limit', 'other', 'a', 'b'}),
    ('lua', 'lua', 'LIMIT = 4\nlocal state, other = 1, 2\n', {'LIMIT', 'state', 'other'}),
    ('scala', 'scala', 'object Config { val limit = 4; var state = 2; val (a, b) = (1, 2) }', {'limit', 'state', 'a', 'b'}),
]


def require_parser(language, source):
    parser = _ts_parser_for(language)
    if parser is None:
        pytest.skip(f'{language} grammar not installed')
    assert not parser.parse(source.encode()).root_node.has_error


@pytest.mark.parametrize('language,extension,source,names', CASES, ids=[row[0] for row in CASES])
def test_named_globals_and_exact_spans(language, extension, source, names):
    require_parser(language, source)
    items = [item for item in extract_items(f'example.{extension}', language, source)
             if item.kind == KIND_GLOBAL]
    assert {item.name for item in items} == names
    assert len(items) == len(names)
    lines = source.splitlines()
    for item in items:
        assert 1 <= item.line_start <= item.line_end <= len(lines)
        assert item.name in '\n'.join(lines[item.line_start - 1:item.line_end])


SCOPES = [
    ('rust', 'mod m { const VALUE: usize = 1; fn f() { const LOCAL: usize = 2; } }', {'VALUE'}),
    ('csharp', 'namespace App { class C { const int VALUE=1; void F(){ const int LOCAL=2; } } }', {'VALUE'}),
    ('ruby', 'module M\nVALUE = rhs\nclass C\n@@shared = 1\ndef f\nlocal = 2\nend\nend\nend\n', {'VALUE', '@@shared'}),
    ('php', '<?php namespace App { class C { const VALUE=1; public static $a=1, $b=2; function f(){ $local=3; } } }', {'VALUE', '$a', '$b'}),
    ('kotlin', 'object C {\nval VALUE = rhs\nfun f() {\nval LOCAL = 2\n}\n}\n', {'VALUE'}),
    ('swift', 'struct C { static let VALUE = rhs; func f() { let LOCAL = 2 } }', {'VALUE'}),
    ('lua', 'VALUE = rhs\nfunction f() local LOCAL = 2 end\ntable.field = 3\n', {'VALUE'}),
    ('scala', 'object C { val VALUE = rhs; def f(): Unit = { val LOCAL = 2 } }', {'VALUE'}),
]


@pytest.mark.parametrize('language,source,names', SCOPES, ids=[row[0] for row in SCOPES])
def test_declaration_scopes_exclude_locals_and_rhs(language, source, names):
    require_parser(language, source)
    items = extract_items('example', language, source)
    assert {item.name for item in items if item.kind == KIND_GLOBAL} == names


def test_rust_layouts_aliases_and_methods_remain_addressable(tmp_path):
    source = (
        '#[repr(C)]\nstruct Api { value: i32 }\n'
        'enum Mode { A, B }\nunion Bits { i: u32, f: f32 }\n'
        'type Handle = usize;\ntrait Access { fn read(&self); }\n'
        'mod inner { pub struct Nested; pub const VALUE: usize = 1; }\n'
        'impl Api { fn read(&self) {} }\n'
        'fn f() { struct Local; const LOCAL: usize = 2; }\n'
    )
    require_parser('rust', source)
    items = extract_items('ffi.rs', 'rust', source)
    types = [item for item in items if item.kind == KIND_CLASS]
    assert {item.name for item in types} == {'Api', 'Mode', 'Bits', 'Handle', 'Access', 'Nested'}
    assert len(types) == 6
    api, = [item for item in types if item.name == 'Api']
    assert api.line_start == 1 and api.line_end == 2
    assert {item.name for item in items if item.kind == KIND_GLOBAL} == {'VALUE'}
    assert any(item.name == 'read' and item.kind == 'function' for item in items)
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'ffi.rs').write_text(source)
    inventory = build_inventory(str(src), str(tmp_path / 'out'), parallel=False)
    entry, = inventory['files']
    by_name = {item['name']: item for item in entry['items']}
    assert by_name['Api']['kind'] == KIND_CLASS
    assert by_name['Handle']['kind'] == KIND_CLASS
    assert by_name['VALUE']['kind'] == KIND_GLOBAL
    update_coverage(inventory, [{'file': 'ffi.rs', 'function': name}
                                for name in ('Api', 'Handle', 'VALUE')], 'understand:map')
    assert all('understand:map' in by_name[name]['checked_by'] for name in ('Api', 'Handle', 'VALUE'))


@pytest.mark.parametrize('language,source,names', [
    ('ruby', '@state = rhs\nM::VALUE = rhs\n', {'@state', 'M::VALUE'}),
    ('php', '<?php [$a, $b] = source(); list($c, $d) = source();', {'$a', '$b', '$c', '$d'}),
    ('scala', 'object C { val a, b: Int = rhs }', {'a', 'b'}),
    ('rust', '#[allow(dead_code)]\nconst VALUE: usize = 1;\nconst _: () = ();\n', {'VALUE'}),
])
def test_additional_binding_shapes(language, source, names):
    require_parser(language, source)
    items = [item for item in extract_items('example', language, source) if item.kind == KIND_GLOBAL]
    assert {item.name for item in items} == names
    assert len(items) == len(names)
    if language == 'rust':
        assert items[0].line_start == 1 and items[0].line_end == 2


def test_rust_attributes_cross_comment_trivia_but_not_other_items():
    source = ('#[repr(C)]\n// FFI layout\n/* shared with C */\nstruct Api { value: i32 }\n'
              'struct Other;\n')
    require_parser('rust', source)
    items = {item.name: item for item in extract_items('ffi.rs', 'rust', source)
             if item.kind == KIND_CLASS}
    assert items['Api'].line_start == 1 and items['Api'].line_end == 4
    assert items['Other'].line_start == items['Other'].line_end == 5
