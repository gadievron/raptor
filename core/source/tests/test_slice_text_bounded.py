"""Bounded canonical windows preserve global trailing-line normalization."""

import tracemalloc

import pytest

from core.source.lines import slice_text


@pytest.mark.parametrize(('tail', 'end', 'expected'), [
    pytest.param('a\n', 99, 'a', id='final-empty-dropped'),
    pytest.param('a\n\n', 99, 'a\n', id='only-one-final-empty-dropped'),
    pytest.param('a\n\nz', 3, 'a\n', id='interior-empty-kept'),
    pytest.param('a\n\r', 99, 'a', id='final-cr-only-dropped'),
    pytest.param('a\n\r\nz', 3, 'a\n', id='interior-cr-only-kept'),
    pytest.param('a\r\r', 99, 'a\r', id='only-one-cr-trimmed'),
    pytest.param('a\x85b\u2028c\r\n', 99, 'a\x85b\u2028c', id='unicode-breakers-retained'),
])
def test_large_window_trailing_line_rules(tail, end, expected):
    text = 'header' * 3000 + '\n' + tail
    assert slice_text(text, 2, end) == expected


def test_large_subclass_keeps_original_split():
    calls = []

    class Text(str):
        def split(self, *args, **kwargs):
            calls.append((args, kwargs))
            return super().split(*args, **kwargs)

    assert slice_text(Text('header' * 3000 + '\na\r\n'), 2, 2) == 'a'
    assert calls == [(('\n',), {})]


def test_early_canonical_window_does_not_split_the_whole_file():
    if tracemalloc.is_tracing():
        pytest.skip('Requires an independently owned allocation tracer')
    text = 'source line\r\n' * 100000
    try:
        tracemalloc.start()
        result = slice_text(text, 10, 20)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == '\n'.join(['source line'] * 11)
    assert peak < 128 * 1024, f'Canonical extraction allocated {peak} bytes'
