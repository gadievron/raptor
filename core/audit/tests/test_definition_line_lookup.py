"""Definition coordinates retain the exact backslash-LF joining model."""

import random

import pytest

from core.audit.constant_resolution import _definition_line_lookup


def _joined_lines(text):
    chars = []
    lines = []
    line = 1
    offset = 0
    while offset < len(text):
        lines.append(line)
        if text.startswith("\\\n", offset):
            chars.append(" ")
            line += 1
            offset += 2
        else:
            chars.append(text[offset])
            if text[offset] == "\n":
                line += 1
            offset += 1
    return "".join(chars), [*lines, line]


@pytest.mark.parametrize("text", [
    "", "a", "a\n", "\n", "\\\n", "\\\n\\\n", "a\\\nb\n",
    "a\\\r\nb\n", "é🙂\\\nβ\n", "\r", "\v\u2028\n",
])
def test_joined_coordinates_and_eof(text):
    joined, lines = _joined_lines(text)
    assert joined == text.replace("\\\n", " ")
    lookup = _definition_line_lookup(text)
    for offset in reversed(range(len(joined) + 1)):
        assert lookup(offset) == lines[offset]
    assert lookup(-1) == 0
    assert lookup(10**40) == lines[-1]


def test_generated_coordinates_support_out_of_order_queries():
    rng = random.Random(812)
    for _ in range(500):
        text = "".join(rng.choices("ab\\\n\r\v\u2028é🙂", k=rng.randrange(200)))
        joined, lines = _joined_lines(text)
        assert joined == text.replace("\\\n", " ")
        lookup = _definition_line_lookup(text)
        offsets = list(range(len(joined) + 1))
        rng.shuffle(offsets)
        for offset in offsets:
            assert lookup(offset) == lines[offset]


def test_unused_lookup_does_not_scan_and_repeated_queries_reuse_index():
    class CountedText(str):
        calls = 0

        def find(self, *args, **kwargs):
            self.calls += 1
            return super().find(*args, **kwargs)

    text = CountedText("a\\\nb\n#define X 1\n")
    lookup = _definition_line_lookup(text)
    assert text.calls == 0
    assert lookup(4) == 3
    calls = text.calls
    assert calls > 0
    assert lookup(4) == 3
    assert lookup(0) == 1
    assert text.calls == calls


def test_lookup_indexes_are_scoped_to_each_input():
    first = _definition_line_lookup("first\\\ncontinued\n")
    second = _definition_line_lookup("x\ny\nz\n")
    assert first(6) == 2
    assert second(4) == 3
    assert first(0) == 1
    assert second(0) == 1


def test_early_queries_do_not_walk_unused_tail_lines():
    class CountedText(str):
        calls = 0

        def find(self, *args, **kwargs):
            self.calls += 1
            return super().find(*args, **kwargs)

    text = CountedText("#define EARLY 1\n" + "int value;\n" * 1000)
    lookup = _definition_line_lookup(text)
    assert lookup(0) == 1
    assert text.calls < 10
    assert lookup(len(text)) == 1002
