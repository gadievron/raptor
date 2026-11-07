"""Display-line iteration matches Python while leaving unused tails unread."""

import random

import pytest

from core.source.lines import iter_splitlines


@pytest.mark.parametrize('text', [
    pytest.param('', id='empty'), pytest.param('one', id='one-line'),
    pytest.param('\n', id='one-empty-line'), pytest.param('\n\n', id='two-empty-lines'),
    pytest.param('one\r\ntwo\r\n', id='crlf'), pytest.param('one\rtwo\r', id='bare-cr'),
    pytest.param('\r\r\n', id='adjacent-cr-and-crlf'),
    pytest.param('a\v\f\x1c\x1d\x1e\x85\u2028\u2029z', id='exotic-breakers'),
    pytest.param('\x1f a\x00b\ud800', id='nonbreakers-and-surrogate'),
])
def test_display_lines_match_splitlines(text):
    assert list(iter_splitlines(text)) == text.splitlines()


def test_random_display_line_combinations():
    rng = random.Random(741)
    alphabet = ['a', '界', '\r', '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029', '\x00']
    for _ in range(200):
        text = ''.join(rng.choices(alphabet, k=rng.randrange(300)))
        assert list(iter_splitlines(text)) == text.splitlines()


def test_iteration_can_stop_before_a_large_tail():
    source = 'first\r\nsecond\n' + 'x' * 1000000
    iterator = iter_splitlines(source)
    assert next(iterator) == 'first'
    assert next(iterator) == 'second'
    iterator.close()


def test_string_adapter_keeps_its_splitlines_override():
    calls = []

    class Adapter(str):
        def splitlines(self):
            calls.append(self)
            return ['custom', 'lines']

    source = Adapter('ignored')
    assert list(iter_splitlines(source)) == ['custom', 'lines']
    assert len(calls) == 1 and calls[0] is source


@pytest.mark.parametrize('chunk_chars', [1, 2, 7, 4096])
def test_chunks_preserve_crlf_and_long_partial_lines(monkeypatch, chunk_chars):
    from core.source import lines

    monkeypatch.setattr(lines, '_SPLITLINES_CHUNK_CHARS', chunk_chars)
    source = 'a\r\r\n\n\v\f\x1c\x1d\x1e\x85\u2028\u2029' * 30 + 'z' * 10000 + '\r\nend\r'
    assert list(lines.iter_splitlines(source)) == source.splitlines()
