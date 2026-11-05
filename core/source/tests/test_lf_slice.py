"""Raw LF excerpts retain exact content while avoiding full line lists."""

import sys
import tracemalloc

import pytest

from core.source.lines import join_lf_slice


def test_raw_window_preserves_cr_and_empty_lines():
    text = 'header' * 3000 + '\na\r\nb\rc\n\nz'
    assert join_lf_slice(text, 1, 4) == 'a\r\nb\rc\n'
    assert join_lf_slice(text, 1, 99) == 'a\r\nb\rc\n\nz'


def test_huge_end_retains_trailing_empty_element():
    text = 'header' * 3000 + '\na\n'
    assert join_lf_slice(text, 1, sys.maxsize * 4) == 'a\n'
    assert join_lf_slice(text, -2, -1) == 'a'


@pytest.mark.parametrize('end', [128, 129], ids=['native-search', 'bounded-split'])
def test_window_boundary_preserves_unicode_separators(end):
    text = ('x' * 200 + '\n') * 130 + 'a\x85b\u2028c\n'
    assert join_lf_slice(text, end - 1, end) == 'x' * 200
    assert join_lf_slice(text, 130, 131) == 'a\x85b\u2028c'


def test_subclass_keeps_original_split_call():
    calls = []

    class Source(str):
        def split(self, *args, **kwargs):
            calls.append((args, kwargs))
            return super().split(*args, **kwargs)

    assert join_lf_slice(Source('x' * 20000 + '\na\n'), 1, 2) == 'a'
    assert calls == [(('\n',), {})]


def test_early_window_does_not_materialize_whole_file_lines():
    if tracemalloc.is_tracing():
        pytest.skip('Requires an independently owned allocation tracer')
    text = 'source line with content\n' * 100000
    try:
        tracemalloc.start()
        result = join_lf_slice(text, 10, 20)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == '\n'.join(['source line with content'] * 10)
    assert peak < 128 * 1024, f'Excerpt extraction allocated {peak} bytes'
