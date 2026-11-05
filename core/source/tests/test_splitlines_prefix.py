"""Display prefixes preserve Python splitlines while bounding temporary data."""

import tracemalloc

import pytest

from core.source import splitlines_prefix


@pytest.mark.parametrize("separator", ["\n", "\r\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"], ids=["lf", "crlf", "cr", "vt", "ff", "fs", "gs", "rs", "nel", "ls", "ps"])
@pytest.mark.parametrize("limit", [0, 1, 2, 3, 20, 128, 129, -1, None, True])
def test_mixed_separator_prefix_is_exact(separator, limit):
    text = separator.join(["one", "", "three", "four"]) + "\n\n" + "tail\n" * 5000
    assert splitlines_prefix(text, limit) == text.splitlines()[:limit]


def test_cut_after_consecutive_lf_keeps_empty_line():
    text = "one\n\n" + "tail\n" * 5000
    assert splitlines_prefix(text, 2) == ["one", ""]


def test_sparse_lf_layout_keeps_original_display_model():
    text = "line\r\u2028" * 5000
    assert splitlines_prefix(text, 20) == text.splitlines()[:20]


def test_long_first_line_keeps_original_result():
    text = "x" * 20000 + "\nnext\n" * 100
    assert splitlines_prefix(text, 2) == text.splitlines()[:2]


def test_subclass_retains_splitlines_override():
    class Text(str):
        calls = 0

        def splitlines(self):
            self.calls += 1
            return ["custom", "second", "third"]

        def find(self, *args):
            raise AssertionError("custom text must retain its splitlines method")

    text = Text("tail\n" * 5000)
    assert splitlines_prefix(text, 2) == ["custom", "second"]
    assert text.calls == 1


def test_large_unused_tail_is_not_split_or_copied():
    if tracemalloc.is_tracing():
        pytest.skip("requires ownership of allocation tracing")
    text = "header\n" * 20 + "unused tail\n" * 100000
    tracemalloc.start()
    try:
        result = splitlines_prefix(text, 20)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == ["header"] * 20
    assert peak < 128 * 1024
