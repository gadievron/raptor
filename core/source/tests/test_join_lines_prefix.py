"""Bounded LF joining preserves prefixes without consuming unused lines."""

import pytest

from core.source.lines import join_lines_prefix


@pytest.mark.parametrize('lines', [[], [''], ['', ''], ['abc'], ['abc', 'def'], ['', '界🙂', ''], ['a\rb', 'x\u2028y'], ['x' * 10000, 'tail']])
@pytest.mark.parametrize('cap', [0, 1, 2, 3, 4, 8, 800, 801, 20000])
def test_prefix_matches_complete_join(lines, cap):
    assert join_lines_prefix(iter(lines), cap) == '\n'.join(lines)[:cap]


def test_does_not_consume_unused_tail():
    def lines():
        yield 'x' * 10000
        raise AssertionError('consumed a line outside the prefix')

    assert join_lines_prefix(lines(), 801) == 'x' * 801


def test_zero_cap_does_not_consume_lines():
    def lines():
        raise AssertionError('consumed an empty prefix')
        yield ''

    assert join_lines_prefix(lines(), 0) == ''


def test_negative_cap_is_rejected():
    with pytest.raises(ValueError, match='nonnegative'):
        join_lines_prefix([], -1)
