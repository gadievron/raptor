"""Streaming source lines preserve the canonical LF/CR contract."""
import itertools
import random

import pytest

from core.source import lines


@pytest.mark.parametrize('chunk', [1, 2, 3, 7, 64, 4096])
def test_source_line_values_match_canonical_split_at_every_chunk_size(monkeypatch, chunk):
    monkeypatch.setattr(lines, '_SOURCE_LINES_CHUNK_CHARS', chunk)
    alphabet = ['a', '\n', '\r', '\v', '\f', '\x85', '\u2028', '\udcff']
    for size in range(4):
        for values in itertools.product(alphabet, repeat=size):
            text = ''.join(values)
            assert list(lines.iter_source_lines(text)) == lines.split_lines(text), (chunk, repr(text))
    for text in ['a' * 9000 + '\r\nlast\r', '\n' * 5000, ('a\r\n\r\nb\v\nc\r') * 100, 'a\n\r', '\r', '\r\r']:
        assert list(lines.iter_source_lines(text)) == lines.split_lines(text), (chunk, repr(text[:40]))


def test_generated_source_line_boundaries_match_split():
    rng = random.Random(51612)
    for _ in range(500):
        text = ''.join(rng.choice(['a', 'wide\U0001f600', '\n', '\r', '\r\n', '\x1c', '\x1d', '\x1e', '\u2029']) for _ in range(rng.randrange(100)))
        assert list(lines.iter_source_lines(text)) == lines.split_lines(text), repr(text)


def test_source_adapter_keeps_original_split_and_cr_operations():
    events = []

    class Source(str):
        def split(self, separator):
            events.append(('split', separator))
            return super().split(separator)

        def __contains__(self, value):
            events.append(('contains', value))
            return super().__contains__(value)

    source = Source('a\r\nb\r')
    expected = lines.split_lines(source)
    expected_events = events.copy()
    events.clear()
    assert list(lines.iter_source_lines(source)) == expected
    assert events == expected_events


def test_first_source_line_can_be_consumed_without_consuming_the_iterator():
    iterator = lines.iter_source_lines('first\n' + 'padding\n' * 10000)
    assert next(iterator) == 'first'
    del iterator
