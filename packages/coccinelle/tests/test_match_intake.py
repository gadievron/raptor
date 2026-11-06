"""Malformed optional match fields preserve usable Coccinelle evidence."""

import pytest

from packages.coccinelle.models import SpatchMatch


@pytest.mark.parametrize('field,attribute', [('line', 'line'), ('col', 'column'),
                                            ('line_end', 'line_end'), ('col_end', 'column_end')])
@pytest.mark.parametrize('value,expected', [
    pytest.param(True, 0, id='boolean'), pytest.param(1.5, 0, id='fraction'),
    pytest.param(float('inf'), 0, id='infinity'), pytest.param(float('nan'), 0, id='nan'),
    pytest.param({}, 0, id='object'), pytest.param([], 0, id='array'),
    pytest.param('bad', 0, id='invalid-string'), pytest.param(-1, 0, id='negative'),
    pytest.param('12', 12, id='legacy-integer-string'), pytest.param(12.0, 12, id='integral-float'),
])
def test_coordinate_intake_never_truncates_or_raises(field, attribute, value, expected):
    match = SpatchMatch.from_dict({'file': 'a.c', field: value})
    assert getattr(match, attribute) == expected
    assert match.file == 'a.c'


def test_malformed_text_fields_do_not_become_unhashable_match_identity():
    match = SpatchMatch.from_dict({'file': ['a.c'], 'rule': {}, 'message': []})
    assert (match.file, match.rule, match.message) == ('', '', '')
    assert SpatchMatch.from_dict({'file': 'bad\x00name.c'}).file == ''


@pytest.mark.parametrize('primary,expected', [(None, 7), (0, 0), ([], 0)])
def test_column_alias_precedence_does_not_replace_explicit_unknown(primary, expected):
    match = SpatchMatch.from_dict({'file': 'a.c', 'col': primary, 'column': 7,
                                   'col_end': primary, 'column_end': 7})
    assert match.column == match.column_end == expected
