"""Bulk continuation shaping agrees with the legacy logical-line contract."""

import pytest

from core.audit import defassign


@pytest.mark.parametrize(('text', 'lines'), [
    ('', ['']),
    ('plain\n', ['plain', '']),
    ('left\\\nright', ['left right']),
    ('left\\\n\nright', ['left ', 'right']),
    ('left\\\\\nright', ['left\\ right']),
    ('\\\n\\\n\\', ['  ']),
    ('terminal\\', ['terminal']),
    ('terminal\\\\', ['terminal\\']),
    ('left\\\n', ['left ']),
    ('left\\\n\\', ['left ']),
    ('left\\\r\nright', ['left\\\r', 'right']),
    ('雪\\\n界\u2028third', ['雪 界\u2028third']),
    ('\t\\\n\t', ['\t \t']),
], ids=['empty', 'final-newline', 'splice', 'empty-line', 'double-backslash',
        'consecutive', 'terminal', 'terminal-pair', 'spliced-eof', 'spliced-terminal',
        'raw-crlf', 'unicode', 'tabs'])
def test_bulk_shaping_matches_logical_lines(text, lines):
    assert defassign._normalise_continuations(text).split('\n') == lines
    assert defassign._join_continuations(text) == lines


def test_continued_native_catalogue_does_not_build_logical_line_list(monkeypatch):
    def forbidden(text):
        pytest.fail('continued native source built a logical-line list')
    monkeypatch.setattr(defassign, '_join_continuations', forbidden)
    text = '#define A(x) \\\n ((x)+1)\n' + 'int declaration;\n' * 100000 + '#define LAST 2\\'
    assert list(defassign._iter_define_directives(text)) == [' A(x)   ((x)+1)', ' LAST 2']


@pytest.mark.parametrize("large", [False, True], ids=["small", "bulk"])
def test_spliced_keyword_and_embedded_directive_keep_legacy_matching(large):
    text = '#de\\\nfine HIDDEN 1\n#define A first\\\n#define INNER 2\n#define LAST 3\n'
    if large:
        text = 'int padding;\n' * 100 + text
    assert list(defassign._iter_define_directives(text)) == [' A first #define INNER 2', ' LAST 3']


def test_custom_source_retains_split_and_replace_hooks():
    class Source(str):
        def replace(self, *args):
            pytest.fail('custom source entered native normalization')
        def split(self, separator):
            assert separator == '\n'
            return ['#define CUSTOM \\', ' line']
    assert list(defassign._iter_define_directives(Source('ordinary source'))) == [' CUSTOM   line']


@pytest.mark.parametrize('delta', [-400, -1, 0, 1],
                         ids=['short', 'before-boundary', 'at-boundary', 'after-boundary'])
def test_terminal_pair_is_removed_exactly_once_at_bulk_boundary(delta):
    body = '#define LAST 1\\\\'
    size = defassign._CONTINUATION_BULK_MIN_CHARS + delta
    text = ' ' * (size-len(body)) + body
    assert len(text) == size
    assert list(defassign._iter_define_directives(text)) == [' LAST 1\\']
