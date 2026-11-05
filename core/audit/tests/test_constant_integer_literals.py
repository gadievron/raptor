"""Direct literal evaluation retains Python syntax and literal caps."""

import pytest

from core.audit.constant_resolution import _try_evaluate


@pytest.mark.parametrize(('body', 'expected'), [
    ('0', 0), ('00', 0), ('+000', 0), ('-000', 0),
    ('42', 42), ('+42', 42), ('-42', -42),
    ('0x10', 16), ('+0XfF', 255), ('-0x10', -16),
    ('010', None), ('-010', None), ('+010', None),
    ('0x', None), ('0xG', None), ('1_000', None),
    ('1e2', None), ('1.0', None), ('0b10', 2),
    (' + 42 ', 42), ('(-42)', -42), ('1 + 2', 3),
    ('1 < 2', None), ('2**4', None),
    (str(2**64), 2**64), (str(-(2**64)), -(2**64)),
    (str(2**64 + 1), None), (str(-(2**64 + 1)), None),
    ('0x10000000000000000', 2**64),
    ('-0x10000000000000001', None),
    ('0' * 512, 0), ('0' * 513, None),
])
def test_integer_literal_syntax_and_boundaries(body, expected):
    assert _try_evaluate(body) == expected
