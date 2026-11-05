"""Macro prefilter retains directive whitespace and match coordinates."""

import pytest

from core.inventory.macro_resolve import _iter_macro_definitions


@pytest.mark.parametrize('whitespace', [' ', '\t', '\n', '\r', '\v', '\u2003'])
def test_original_whitespace_and_match_offsets(whitespace):
    source = 'prefix\n#' + whitespace + 'define' + whitespace + 'NAME' + whitespace + '2\n'
    matches = list(_iter_macro_definitions(source))
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
