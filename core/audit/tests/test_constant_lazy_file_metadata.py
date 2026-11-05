"""Unused file metadata stays lazy without leaking state between files."""

import tracemalloc

import pytest

from core.audit import constant_resolution as cr


def test_definitionless_files_preserve_later_file_coordinates(tmp_path):
    empty = '/* define */\n#ifdef FEATURE\nint ordinary;\n#endif\n'
    (tmp_path / 'a.c').write_text(empty)
    (tmp_path / 'b.h').write_text('prefix();\n#define VALUE 7\n')
    (tmp_path / 'c.h').write_text('#ifdef FEATURE\nenum { CODE = 9 };\n#endif\n')
    (tmp_path / 'z.c').write_text(empty)
    definitions = cr._scan_definitions(tmp_path)
    assert list(definitions) == ['VALUE', 'CODE']
    value = definitions['VALUE'][0]
    code = definitions['CODE'][0]
    assert (value.file, value.line, value.body, value.conditional_depth) == ('b.h', 2, '7', 0)
    assert (code.file, code.line, code.body, code.conditional_depth) == ('c.h', 2, '9', 1)


def test_conditional_file_without_definitions_avoids_dense_metadata(tmp_path):
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    source = '/* define */\n' + '#ifdef FEATURE\nint ordinary;\n#endif\n' * 30000
    (tmp_path / 'a.c').write_text(source)
    # Import and helper caches should not contribute to measured workspace.
    cr._scan_definitions(tmp_path)
    tracemalloc.start()
    try:
        definitions = cr._scan_definitions(tmp_path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert definitions == {}
    assert peak < len(source) * 6
