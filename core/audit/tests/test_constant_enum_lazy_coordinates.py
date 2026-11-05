"""Enum coordinates are prepared only for kept explicit assignments."""

import tracemalloc

import pytest

from core.audit import constant_resolution as cr


@pytest.mark.parametrize('with_macro', [False, True])
def test_mixed_blocks_keep_member_lines_and_conditional_depths(tmp_path, with_macro):
    source = (
        '#if defined(FEATURE)\n'
        'enum implicit { READY, RUNNING, DONE };\n'
        '#endif\n'
        'enum explicit { FIRST = 4,\n'
        ' SECOND = 5 };\n'
        '#ifdef FEATURE\n'
        'enum inner { THIRD = 6 };\n'
        '#endif\n'
    )
    if with_macro:
        source = '#define MACRO 1\n' + source
    (tmp_path / 'a.h').write_text(source)
    definitions = cr._scan_definitions(tmp_path)
    assert list(definitions) == (['MACRO'] if with_macro else []) + ['FIRST', 'SECOND', 'THIRD']
    delta = int(with_macro)
    for name, line, depth in [('FIRST', 4, 0), ('SECOND', 5, 0), ('THIRD', 7, 1)]:
        record = definitions[name][0]
        assert (record.line, record.conditional_depth) == (line + delta, depth)


def test_skipped_first_member_does_not_shift_later_members(tmp_path):
    (tmp_path / 'a.h').write_text(
        'enum implicit { READY, RUNNING };\n'
        'enum skipped { if = 1,\n'
        ' KEPT = 2 };\n'
        'enum later { LATER = 3 };\n',
    )
    definitions = cr._scan_definitions(tmp_path)
    assert list(definitions) == ['KEPT', 'LATER']
    assert definitions['KEPT'][0].line == 3
    assert definitions['LATER'][0].line == 4


def test_depth_remains_the_block_header_depth(tmp_path):
    (tmp_path / 'a.h').write_text(
        'enum members {\n#ifdef FEATURE\n KEPT = 1,\n#endif\n};\n',
    )
    record = cr._scan_definitions(tmp_path)['KEPT'][0]
    assert (record.line, record.conditional_depth) == (3, 0)


def test_implicit_only_file_avoids_unused_coordinate_tables(tmp_path):
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    source = '#if defined(FEATURE)\nenum state { READY, RUNNING, DONE };\n#endif\n' * 20000
    (tmp_path / 'a.c').write_text(source)
    cr._scan_definitions(tmp_path)
    tracemalloc.start()
    try:
        definitions = cr._scan_definitions(tmp_path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert definitions == {}
    assert peak < len(source) * 4
