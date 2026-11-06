"""Simple native source spans bypass character walks without changing lexical output."""

import pytest

from core.source import strip


@pytest.mark.parametrize('quote', ['"', "'"], ids=['string', 'char'])
@pytest.mark.parametrize('tail', ['', '\n', '\\'], ids=['eof', 'newline', 'escape'])
def test_unterminated_literals_keep_comment_markers(quote, tail):
    text = 'prefix ' + quote + 'literal /* keep */ // keep' + tail
    assert strip.strip_c_comments(text) == text
    assert strip.strip_c_comments(text, comment_replacement=' ') == text


def test_first_escaped_quote_does_not_close_literal():
    text = '"escaped \\" // keep" /* remove */ tail'
    assert strip.strip_c_comments(text) == '"escaped \\" // keep"  tail'
    assert strip.strip_c_comments(text, comment_replacement=' ') == '"escaped \\" // keep"   tail'


@pytest.mark.parametrize('slashes', range(1, 9))
def test_backslash_parity_retains_existing_quote_handling(slashes):
    text = '"literal ' + '\\' * slashes + '" // tail'
    expected = '"literal ' + '\\' * slashes + '" ' if slashes % 2 == 0 else text
    assert strip.strip_c_comments(text) == expected


def test_plain_blanking_skips_character_list(monkeypatch):
    def forbidden(*args):
        pytest.fail('plain source was copied into a character list')
    monkeypatch.setattr(strip, 'list', forbidden, raising=False)
    text = 'int f(int x) { return x / 2; }\n' * 10000
    assert strip.blank_c_noncode(text) == text
    assert strip.blank_c_noncode(text, allow_digit_separators=True) == text


def test_blank_source_subclasses_keep_iteration_hooks():
    class Source(str):
        def __iter__(self):
            return iter('HOOK')
    assert strip.blank_c_noncode(Source('ordinary source')) == 'HOOK'


def test_noncode_blanking_preserves_offsets_with_digit_separators():
    text = 'unsigned n = 1\'000; char *s="// literal"; /* comment\n */ int live;\n'
    result = strip.blank_c_noncode(text, allow_digit_separators=True)
    assert len(result) == len(text)
    assert "1'000" in result
    assert 'literal' not in result and 'comment' not in result
    assert result.index('int live') == text.index('int live')
    assert [i for i, c in enumerate(result) if c == '\n'] == [i for i, c in enumerate(text) if c == '\n']
