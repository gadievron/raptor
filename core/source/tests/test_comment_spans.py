"""Span-based C comment removal preserves both removal and token-spacing modes."""

import pytest

from core.source import strip_c_comments
from core.source import strip as implementation


@pytest.mark.parametrize(('text', 'removed', 'spaced'), [
    ('', '', ''),
    ('ab/**/cd', 'abcd', 'ab cd'),
    ('a//gone\nb', 'a\nb', 'a \nb'),
    ('/*gone*/', '', ' '),
    ('/*unclosed', '', ' '),
    ('// tail', '', ' '),
    ('a/b + c/d', 'a/b + c/d', 'a/b + c/d'),
    ('a /*first\nsecond*/ b', 'a  b', 'a   b'),
    ('\x00雪/**/é', '\x00雪é', '\x00雪 é'),
    ('a/*one*//*two*/b', 'ab', 'a  b'),
    ('a/*one*/ /*two*/b', 'a b', 'a   b'),
    ('#define A(x) /*multi\nline*/ (x)\n', '#define A(x)  (x)\n', '#define A(x)   (x)\n'),
], ids=['empty', 'tokens', 'line-comment', 'block-comment', 'open-block',
        'open-line', 'division', 'multiline', 'unicode', 'adjacent', 'spacing', 'macro'])
def test_comment_replacements(text, removed, spaced):
    assert strip_c_comments(text) == removed
    assert strip_c_comments(text, comment_replacement=' ') == spaced


@pytest.mark.parametrize('text', [
    r'"/* literal */ // literal"',
    r'"escaped \" quote // keep"',
    r"'escaped \' char /*keep*/'",
    '"unterminated // text /* text',
    '"unterminated\\',
    "'unterminated\\",
    '"multiline\n//still quoted"',
], ids=['markers', 'escaped-double', 'escaped-single', 'open-literal',
        'open-double-escape', 'open-single-escape', 'literal-newline'])
def test_literals_are_preserved(text):
    assert strip_c_comments(text) == text
    assert strip_c_comments(text, comment_replacement=' ') == text


def test_plain_spans_do_not_scan_per_character(monkeypatch):
    original = implementation._C_NONCODE_START_RE
    calls = []
    class Scanner:
        def search(self, text, offset):
            calls.append(offset)
            return original.search(text, offset)
    monkeypatch.setattr(implementation, '_C_NONCODE_START_RE', Scanner())
    plain = 'int declaration;\n' * 100000
    text = plain + '/* tail */'
    assert strip_c_comments(text) == plain
    assert calls == [0, len(text)]


def test_string_subclasses_keep_the_legacy_scanner(monkeypatch):
    class Source(str):
        pass
    def forbidden(*args):
        pytest.fail('a string subclass entered the native span scanner')
    monkeypatch.setattr(implementation, '_strip_c_comment_spans', forbidden)
    assert strip_c_comments(Source('a/**/b')) == 'ab'
    assert strip_c_comments(Source('a/**/b'), comment_replacement=' ') == 'a b'


def test_comment_free_native_text_skips_span_scanning(monkeypatch):
    def forbidden(*args):
        pytest.fail('comment-free text entered the span scanner')
    monkeypatch.setattr(implementation, '_strip_c_comment_spans', forbidden)
    text = 'int declaration;\n' * 100000 + "''" * 1000
    assert strip_c_comments(text) == text
    assert strip_c_comments(text, comment_replacement=' ') == text


def test_replacement_uses_string_content_even_with_custom_truthiness():
    class Replacement(str):
        def __bool__(self):
            return False
    assert strip_c_comments('a/**/b', comment_replacement=Replacement(' ')) == 'a b'
