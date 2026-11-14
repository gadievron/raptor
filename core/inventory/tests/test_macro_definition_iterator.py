"""Macro prefilter retains directive whitespace and match coordinates."""

import pytest

from core.inventory import macro_resolve as mr
from core.inventory.macro_resolve import _iter_macro_definitions


@pytest.fixture(params=['normal', 'sparse'], autouse=True)
def macro_matching_mode(request, monkeypatch):
    if request.param == 'sparse':
        monkeypatch.setattr(mr, '_MACRO_SPARSE_MIN_SOURCE', 0)
        monkeypatch.setattr(mr, '_MACRO_SPARSE_MIN_CHARS_PER_HASH', 1)


@pytest.mark.parametrize('whitespace', [' ', '\t', '\n', '\r', '\v', '\u2003'])
def test_original_whitespace_and_match_offsets(whitespace):
    source = 'prefix\n#' + whitespace + 'define' + whitespace + 'NAME' + whitespace + '2\n'
    matches = list(_iter_macro_definitions(source))
    if whitespace == "\n":
        assert matches == []
        return
    assert len(matches) == 1
    match = matches[0]
    assert match.groups() == ('NAME', None, '2')
    assert match.start() == len('prefix\n')
    assert match.string is source


@pytest.mark.parametrize('source', [
    'ordinary defined prose\n',
    '#defined NAME 2\n',
    'text #define NAME 2\n',
    '#define NAME\n',
    'enum { NAME = 2 };\n',
])
def test_possible_prefix_keeps_full_directive_validation(source):
    assert list(_iter_macro_definitions(source)) == []


@pytest.mark.parametrize(('source', 'expected'), [
    ('#define OUTER #define INNER 2\n', [('OUTER', None, '#define INNER 2')]),
    ('code #define BAD 1; #define ALSO_BAD 2\n#define GOOD 3\n',
     [('GOOD', None, '3')]),
    ('#\n define F(\nx)\n 4\n', []),
    ('#define BROKEN\n#define GOOD 3\n', [('GOOD', None, '3')]),
    ('#define F(\nmissing\n#define GOOD 3\n', [('GOOD', None, '3')]),
])
def test_candidate_lines_preserve_multiline_and_nonoverlap_rules(source, expected):
    assert [match.groups() for match in _iter_macro_definitions(source)] == expected


def test_sparse_large_source_keeps_indentation_in_match_span():
    prefix = 'ordinary();\n' * 3000
    source = prefix + '   #define GOOD 3\n'
    matches = list(_iter_macro_definitions(source))
    assert len(matches) == 1
    assert matches[0].start() == len(prefix)
    assert matches[0].group(0) == '   #define GOOD 3'
    assert matches[0].string is source


def test_empty_definition_does_not_capture_next_declaration():
    source = "#define EMPTY\n__attribute__((warn_unused_result)) int owned(void);\n"
    assert list(_iter_macro_definitions(source)) == []


@pytest.mark.parametrize("source, expected", [
    ("#define OWNED()__attribute__((warn_unused_result))\n", ("OWNED", "()", "__attribute__((warn_unused_result))")),
    ("#define OWNED(x) value\n", ("OWNED", "(x)", "value")),
    ("#define OWNED (x) value\n", ("OWNED", None, "(x) value")),
    ("#define 雪 value\n", ("雪", None, "value")),
    ("#define OWNED value \\\n", ("OWNED", None, "value")),
], ids=["adjacent-function", "spaced-function", "object-parentheses", "unicode-name", "trailing-continuation"])
def test_single_logical_line_forms_keep_three_capture_groups(source, expected):
    assert [match.groups() for match in _iter_macro_definitions(source)] == [expected]
