"""Sparse preprocessor-depth lookup must retain the dense line contract."""

import random

import pytest

from core.audit.constant_resolution import (
    _compute_conditional_depths,
    _conditional_depth_lookup,
)


@pytest.mark.parametrize("text", [
    "", "\r", "\r\r", "\n", "\n\r", "\r\n\r",
    "#if X", "#if X\n", "#if X\n\r", "#if X\n\r\r",
    "#\nif X\n", "#\r\nif X\n", "#\vif X\n#\u2028endif\n",
    "x\r#if X\nx\u2028#endif\n", "#ifx\n#elif X\n#else\n#endifx\n",
    "#if X\n#ifndef Y\n#else\n#elif Z\n#endif\n#endif\n#endif\n",
    "#IF X\n", "/* comment\n#if X\n*/\n#endif\n",
    "#if X #endif\nbody\n", "#unsupported #if X\n",
    "  #if X #if Y\n", "#endif #if X\n",

    "\x1c#if X\n\x1f#endif\r\n",
    "#if X\nbody\n#endif\n" * 100,
    "#define X 1\n" * 100,

])
def test_sparse_depths_match_dense_line_boundaries(text):
    expected = _compute_conditional_depths(text)
    lookup = _conditional_depth_lookup(text)
    for line in [*range(-2, len(expected) + 4), 10**40]:
        assert lookup(line) == expected.get(line, 0)


def test_generated_directives_whitespace_and_line_breaks():
    rng = random.Random(917)
    fragments = [
        "#if X", "#ifdef X", "#ifndef X", "#endif", "#else", "#elif X",
        "#ifx", "#endifx", "#\nif X", "#\r\nendif", "text", "",
    ]
    whitespace = ["", " ", "\t", "\r", "\v", "\f", "\x85", "\u2028", "\x1c"]
    for _ in range(1000):
        text = "".join(
            rng.choice(whitespace) + rng.choice(fragments)
            + rng.choice(["\n", "\r\n", "\r", "\u2028", ""])
            for _ in range(rng.randrange(50))
        )
        expected = _compute_conditional_depths(text)
        lookup = _conditional_depth_lookup(text)
        for line in range(-1, len(expected) + 3):
            assert lookup(line) == expected.get(line, 0), (repr(text), line)


def test_string_subclasses_keep_dense_behavior():
    class CustomText(str):
        def count(self, *args, **kwargs):
            raise AssertionError("custom source must keep the dense path")

    text = CustomText("#if X\nbody\n#endif\n")
    expected = _compute_conditional_depths(text)
    lookup = _conditional_depth_lookup(text)
    assert [lookup(line) for line in range(6)] == [expected.get(line, 0) for line in range(6)]
