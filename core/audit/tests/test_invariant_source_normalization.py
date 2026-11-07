"""Field normalization preserves operand text and adjacent operators."""

from itertools import product
import re

import pytest

from core.audit.invariant_source import _compact_field_access


def test_bounded_normalization_matches_previous_behavior():
    previous = re.compile(r"\s*(->|\.)\s*")
    for size in range(6):
        for parts in product("a-.> ", repeat=size):
            text = "".join(parts)
            assert _compact_field_access(text) == previous.sub(r"\1", text).strip()


@pytest.mark.parametrize(("text", "expected"), [
    ("\u2003obj\t->\nfield . value\u00a0", "obj->field.value"),
    (" a + b -> c + d ", "a + b->c + d"),
    (" a . -> . b ", "a.->.b"),
    (" a - > b ", "a - > b"),
])
def test_operand_spacing_and_unicode_whitespace(text, expected):
    assert _compact_field_access(text) == expected
