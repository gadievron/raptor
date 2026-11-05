"""Range rendering preserves blanking semantics with bounded workspace."""

import random
import tracemalloc

import pytest

from core.audit.source_view import _blank, _render_c_blank_ranges, sanitized_view_with_status


def test_generated_ranges_preserve_every_character_and_newline():
    rng = random.Random(786)
    for _ in range(500):
        source = ''.join(rng.choices('abc\n\r\vé🙂\x00\u2028', k=rng.randrange(2000)))
        cuts = sorted(rng.sample(range(len(source) + 1), min(40, len(source) + 1)))
        ranges = list(zip(cuts[::2], cuts[1::2]))
        chars = list(source)
        for start, end in ranges:
            _blank(chars, start, end)
        assert _render_c_blank_ranges(source, ranges) == ''.join(chars)


@pytest.mark.parametrize('ranges', [
    [(1, 6), (3, 10)],
    [(8, 12), (1, 5)],
    [(-1, 3)],
    [(4, 4), (10, 2)],
    [(0, 100)],
])
def test_unexpected_ranges_retain_character_operation(ranges):
    source = 'abc\ndef\r\nghi'
    results = []
    for render in [False, True]:
        try:
            if render:
                result = _render_c_blank_ranges(source, ranges)
            else:
                chars = list(source)
                for start, end in ranges:
                    _blank(chars, start, end)
                result = ''.join(chars)
        except IndexError as exc:
            result = (type(exc), str(exc))
        results.append(result)
    assert results[0] == results[1]


@pytest.mark.parametrize('dense_newlines', [False, True])
def test_large_views_do_not_expand_temporary_storage(dense_newlines):
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    source = ('/*' + '\n' * 20000 + '*/' if dense_newlines
              else 'int live;\n' * 100000 + '/* hide */')
    tracemalloc.start()
    try:
        result = sanitized_view_with_status(source, 'a.c')
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(result.text) == len(source)
    assert result.text.count('\n') == source.count('\n')
    assert 'hide' not in result.text
    assert not result.ambiguous
    assert peak < len(source) * (12 if dense_newlines else 4)


def test_dense_tiny_comments_retain_legacy_allocation_bound():
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    source = '/**/' * 20000
    tracemalloc.start()
    try:
        result = sanitized_view_with_status(source, 'a.c')
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.text == ' ' * len(source)
    assert not result.ambiguous
    assert peak < len(source) * 12
