"""Reuse is operation-local and must preserve the complete function view."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import importlib
import os

import pytest

from core.inventory.extractors import TreeSitterExtractor

view_module = importlib.import_module('core.ast.view')


@pytest.mark.parametrize('language,suffix,source', [
    ('c', '.c', 'int g(int x) { return x+1; }\nint f(int x) { if(x) return g(x); return 0; }\n'),
    ('cpp', '.cpp', 'namespace ns { int g(int x) { return x; } }\nint f(int x) { return ns::g(x); }\n'),
    ('c', '.c', '/*\f*/\nint f(int x) { asm volatile("nop"); return x; }\n'),
    ('c', '.c', '#define K\nint f(int x) { if(x) return x; return 0; }\n'),
    ('c', '.c', 'int f(void) { return 1; }\nvoid broken( {\n'),
])
def test_one_parse_with_byte_equivalent_view(tmp_path, monkeypatch, language, suffix, source):
    pytest.importorskip('tree_sitter_cpp' if language == 'cpp' else 'tree_sitter_c')
    path = tmp_path / ('source' + suffix)
    path.write_text(source)
    parser_type = type(TreeSitterExtractor(language).parser)
    original_parse = parser_type.parse
    parsed = []

    def counted(self, content, *args, **kwargs):
        parsed.append(bytes(content))
        return original_parse(self, content, *args, **kwargs)

    monkeypatch.setattr(parser_type, 'parse', counted)
    actual = view_module.view(path, 'f')
    assert actual is not None
    assert len(parsed) == 1
    original_extract = view_module.extract_functions

    def independent_trees(*args, **kwargs):
        kwargs.pop('_tree_cache', None)
        return original_extract(*args, **kwargs)

    monkeypatch.setattr(view_module, 'extract_functions', independent_trees)
    parsed.clear()
    expected = view_module.view(path, 'f')
    assert len(parsed) == 3
    assert len(set(parsed)) == 1
    assert asdict(actual) == asdict(expected)


def test_no_reuse_between_views_even_with_same_size_and_mtime(tmp_path):
    pytest.importorskip('tree_sitter_c')
    path = tmp_path / 'source.c'
    path.write_text('int f(void) { return 1; }\n')
    stamp = path.stat()
    assert view_module.view(path, 'f').returns[0].value_text == '1'
    path.write_text('int f(void) { return 2; }\n')
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert view_module.view(path, 'f').returns[0].value_text == '2'


def test_parallel_views_do_not_share_source_trees(tmp_path):
    pytest.importorskip('tree_sitter_c')
    paths = []
    for i in range(16):
        path = tmp_path / f'source{i}.c'
        path.write_text(f'int f(void) {{ return {i}; }}\n')
        paths.append(path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda p: view_module.view(p, 'f'), paths))
    assert [r.returns[0].value_text for r in results] == [str(i) for i in range(16)]


def test_missing_shared_tree_retains_reparse_fallback(tmp_path, monkeypatch):
    pytest.importorskip('tree_sitter_c')
    path = tmp_path / 'source.c'
    path.write_text('int f(void) { return 1; }\n')
    original = view_module.extract_functions

    def no_tree(*args, **kwargs):
        kwargs.pop('_tree_cache', None)
        return original(*args, **kwargs)

    monkeypatch.setattr(view_module, 'extract_functions', no_tree)
    result = view_module.view(path, 'f')
    assert result is not None
    assert result.returns[0].value_text == '1'


def test_initial_parse_failure_keeps_independent_retry_paths(tmp_path, monkeypatch):
    pytest.importorskip('tree_sitter_c')
    path = tmp_path / 'source.c'
    path.write_text('int f(void) { return 1; }\n')
    parser_type = type(TreeSitterExtractor('c').parser)
    parse = parser_type.parse
    attempts = []

    def fail_first(self, content, *args, **kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError('transient first parse failure')
        return parse(self, content, *args, **kwargs)

    monkeypatch.setattr(parser_type, 'parse', fail_first)
    actual = view_module.view(path, 'f')
    actual_attempts = len(attempts)
    extract = view_module.extract_functions

    def independent_trees(*args, **kwargs):
        kwargs.pop('_tree_cache', None)
        return extract(*args, **kwargs)

    monkeypatch.setattr(view_module, 'extract_functions', independent_trees)
    attempts.clear()
    expected = view_module.view(path, 'f')
    assert actual is not None
    assert asdict(actual) == asdict(expected)
    assert actual_attempts == len(attempts)
    assert actual_attempts > 1
