"""Tests for ``_strip_think_blocks`` and ``_StreamThinkFilter``."""
from __future__ import annotations

from core.llm.providers import _StreamThinkFilter, _strip_think_blocks


class TestStripThinkBlocks:
    def test_no_think_tags_unchanged(self):
        assert _strip_think_blocks("hello world") == "hello world"

    def test_empty_string(self):
        assert _strip_think_blocks("") == ""

    def test_strips_matched_pair(self):
        text = "<think>reasoning here</think>actual answer"
        assert _strip_think_blocks(text) == "actual answer"

    def test_strips_multiline_block(self):
        text = "<think>\nstep 1\nstep 2\n</think>\n\nfinal answer"
        assert _strip_think_blocks(text) == "final answer"

    def test_strips_multiple_blocks(self):
        text = "<think>first</think>middle<think>second</think>end"
        assert _strip_think_blocks(text) == "middleend"

    def test_case_insensitive(self):
        text = "<Think>reasoning</Think>answer"
        assert _strip_think_blocks(text) == "answer"

    def test_lone_closer_drops_prefix_when_json_follows(self):
        text = 'reasoning noise here</think>{"x": 1}'
        assert _strip_think_blocks(text) == '{"x": 1}'

    def test_lone_closer_array_follows(self):
        text = 'reasoning noise</think>[1, 2, 3]'
        assert _strip_think_blocks(text) == '[1, 2, 3]'

    def test_lone_closer_no_json_leaves_text_intact(self):
        text = "reasoning noise here</think>actual answer"
        assert _strip_think_blocks(text) == text.strip()

    def test_think_with_attributes(self):
        text = '<think type="reasoning">stuff</think>answer'
        assert _strip_think_blocks(text) == "answer"

    def test_preserves_json_after_block(self):
        text = '<think>let me think</think>{"key": "value"}'
        result = _strip_think_blocks(text)
        assert result == '{"key": "value"}'

    def test_whitespace_in_closer(self):
        text = "<think>reasoning</think  >answer"
        assert _strip_think_blocks(text) == "answer"

    def test_closer_inside_json_string_not_corrupted(self):
        text = '{"reasoning": "checked </think> and found it"}'
        assert _strip_think_blocks(text) == text


def _collect(filt: _StreamThinkFilter, chunks: list[str]) -> str:
    """Feed chunks through a filter and return the assembled output."""
    parts: list[str] = []
    for c in chunks:
        out = filt.feed(c)
        if out:
            parts.append(out)
    rem = filt.flush()
    if rem:
        parts.append(rem)
    return "".join(parts)


class TestStreamThinkFilter:
    def test_no_think_passthrough(self):
        f = _StreamThinkFilter()
        assert _collect(f, ["hello", " world"]) == "hello world"

    def test_json_passthrough_immediate(self):
        f = _StreamThinkFilter()
        assert _collect(f, ['{"x":', ' 1}']) == '{"x": 1}'

    def test_strips_leading_think_block(self):
        f = _StreamThinkFilter()
        chunks = ["<think>", "step 1\nstep 2", "</think>", "answer"]
        assert _collect(f, chunks) == "answer"

    def test_think_tag_split_across_chunks(self):
        f = _StreamThinkFilter()
        chunks = ["<thi", "nk>reasoning</think>", "result"]
        assert _collect(f, chunks) == "result"

    def test_closer_split_across_chunks(self):
        f = _StreamThinkFilter()
        chunks = ["<think>reason", "ing</thi", "nk>answer"]
        assert _collect(f, chunks) == "answer"

    def test_no_closer_flushes_buffer(self):
        f = _StreamThinkFilter()
        chunks = ["<think>", "unclosed reasoning"]
        result = _collect(f, chunks)
        # Unclosed opener is ambiguous (truncation?) — _strip_think_blocks
        # passes it through; flush surfaces whatever it returns.
        assert result == "<think>unclosed reasoning"

    def test_passthrough_after_think_block(self):
        f = _StreamThinkFilter()
        f.feed("<think>r</think>")
        out = f.feed("more text")
        assert out == "more text"

    def test_whitespace_before_non_think_content(self):
        f = _StreamThinkFilter()
        chunks = ["  ", " ", "hello"]
        assert _collect(f, chunks).strip() == "hello"

    def test_empty_answer_after_think(self):
        f = _StreamThinkFilter()
        chunks = ["<think>all reasoning</think>"]
        assert _collect(f, chunks) == ""

    def test_multiple_think_blocks_stripped(self):
        f = _StreamThinkFilter()
        chunks = ["<think>a</think>", "<think>b</think>answer"]
        assert _collect(f, chunks) == "answer"

    def test_adjacent_think_blocks_in_one_chunk(self):
        f = _StreamThinkFilter()
        chunks = ["<think>a</think><think>b</think>result"]
        assert _collect(f, chunks) == "result"
