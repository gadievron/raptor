"""Raw literal search preserves boundaries and EOF reporting."""

import pytest

from core.audit.source_view import _string_end, sanitized_view_with_status


@pytest.mark.parametrize(('source', 'start', 'quote', 'end', 'eof'), [
    ('``', 0, '`', 2, False),
    ('`a\\`tail', 0, '`', 4, False),
    ('`a\nb\r\né🙂`tail', 0, '`', 9, False),
    ('prefix `body` tail', 7, '`', 13, False),
    ('`unterminated\n', 0, '`', 14, True),
    ('`trailing\\', 0, '`', 10, True),
    ('', 0, '`', 0, True),
    ('`x`', 10, '`', 3, True),
    ('"x\n"', 0, '"', 4, False),
])
def test_raw_boundaries_and_eof(source, start, quote, end, eof):
    calls = []
    assert _string_end(source, start, quote, raw=True,
                       on_eof=lambda: calls.append('eof')) == end
    assert calls == (['eof'] if eof else [])


def test_doubled_quotes_keep_existing_grammar():
    assert _string_end('`a``b`tail', 0, '`', raw=True, doubling=True) == 6


def test_subclass_keeps_character_access_path():
    class Source(str):
        def find(self, *args):
            raise AssertionError('must retain subclass behavior')

    assert _string_end(Source('`a\nb`tail'), 0, '`', raw=True) == 5


def test_go_raw_contents_and_following_code():
    result = sanitized_view_with_status('x := `a\\\nb /* data */`\nlive()\n', 'a.go')
    assert 'live()' in result.text
    assert 'data' not in result.text
    assert result.text.count('\n') == 3
