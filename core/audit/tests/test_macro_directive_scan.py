"""Directive discovery preserves logical-line semantics without splitting plain files."""

import pytest

from core.audit import defassign


@pytest.mark.parametrize(('text', 'expected'), [
    ('', []),
    ('int x; #define HIDDEN 1\n"#define QUOTED 1"\n', []),
    ('#defined #define HIDDEN 1\n#define A #define B\n', [' A #define B']),
    (' \t#define A 1\n', [' A 1']),
    ('#define A 1\nint x;\n# define B 2\n', [' A 1', ' B 2']),
    ('#defined A\n#define9 A\n#defineé A\n#DEFINE A\n', []),
    ('#define\u200b A 1\n', ['\u200b A 1']),
    ('#\tdefine\tA 1\r\n', ['\tA 1\r']),
    ('#define A 1\n\n#define\n', [' A 1', '']),
    ('#define(A)\n', ['(A)']),
    ('#define A \\\n 1\n', [' A   1']),
    ('#define A 1\\', [' A 1']),
    ('#de\\\nfine A 1\n', []),
    ('#define A \\\r\n 1\n', [' A \\\r']),
    ('/*\n#define IN_COMMENT 1\n*/\n', [' IN_COMMENT 1']),
    ('\f#define A 1\n', []),
], ids=['empty', 'inline-lookalikes', 'embedded-marker', 'indent', 'plain', 'keyword-boundaries', 'nonword-boundary', 'crlf',
        'empty-body', 'punctuation-body', 'continuation', 'terminal-backslash',
        'split-keyword', 'raw-crlf-continuation', 'raw-comment', 'indentation'])
def test_directive_bodies_match_legacy_semantics(text, expected):
    assert list(defassign._iter_define_directives(text)) == expected


def test_plain_text_does_not_build_logical_line_list(monkeypatch):
    def forbidden(text):
        pytest.fail('plain source was split into all logical lines')
    monkeypatch.setattr(defassign, '_join_continuations', forbidden)
    text = '#define EARLY 1\n' + 'int declaration;\n' * 100000
    assert list(defassign._iter_define_directives(text)) == [' EARLY 1']


def test_special_input_keeps_split_override():
    class Source(str):
        def split(self, separator):
            assert separator == '\n'
            return ['#define CUSTOM 2']
    assert list(defassign._iter_define_directives(Source('ordinary text'))) == [' CUSTOM 2']


def test_directives_are_yielded_without_collecting_all_matches(monkeypatch):
    original = defassign._DEFINE_DIRECTIVE_RE
    visited = []
    class Scanner:
        def finditer(self, text):
            for match in original.finditer(text):
                visited.append(match.group(1))
                yield match
    monkeypatch.setattr(defassign, '_DEFINE_DIRECTIVE_RE', Scanner())
    iterator = defassign._iter_define_directives('#define FIRST 1\n#define SECOND 2\n')
    try:
        assert next(iterator) == ' FIRST 1'
        assert visited == [' FIRST 1']
    finally:
        iterator.close()
