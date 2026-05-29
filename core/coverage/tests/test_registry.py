"""Tests for the coverage tool registry (category / depth classification)."""

from __future__ import annotations

from core.coverage.registry import category_of, classify, depth_of


def test_known_tools_classify():
    assert category_of("semgrep") == "static"
    assert category_of("codeql") == "static"
    assert category_of("gcov") == "runtime"
    assert depth_of("gcov") == "runtime-tested"
    assert classify("claude") == ("llm", "analysed")


def test_labelled_tool_uses_base():
    # The label's base (before ":") drives classification.
    assert category_of("claude:audit") == "llm"
    assert category_of("gcov:campaign-1") == "runtime"
    assert depth_of("claude:stage-a") == "analysed"


def test_command_source_labels_are_llm():
    # checked_by source_labels (command:stage) classify as llm.
    assert category_of("validate:stage-a") == "llm"
    assert category_of("agentic:post-pass") == "llm"
    assert category_of("annotations") == "llm"


def test_read_and_understand_are_llm_but_not_reviewed():
    # read (whole-file read) and understand (structural attack-surface map) are
    # llm-EXTENT but only scanned depth -- NOT a per-function vuln review. The
    # review axis is depth >= analysed, so neither counts as reviewed.
    assert classify("read") == ("llm", "scanned")
    assert classify("understand") == ("llm", "scanned")
    # Actual review tools stay at analysed depth (= reviewed).
    for tool in ("claude", "audit", "validate:stage-a", "annotations", "agentic"):
        assert category_of(tool) == "llm"
        assert depth_of(tool) == "analysed"


def test_unknown_tool_is_conservative():
    # Unknown producers are never credited as deep coverage.
    assert classify("mystery-tool") == ("unknown", "scanned")
    assert category_of("mystery-tool:v2") == "unknown"
