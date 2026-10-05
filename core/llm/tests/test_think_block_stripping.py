"""Tests for ``_strip_think_blocks`` — inline reasoning tag removal."""
from __future__ import annotations

from core.llm.providers import _strip_think_blocks


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
