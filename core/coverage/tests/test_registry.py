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


def test_machine_annotations_are_hint_tier_not_reviewed():
    # Agent-written (and non-TTY-stamped) notes import under
    # annotations:machine — hint-tier by doctrine, so llm-extent but
    # scanned depth: they must NOT clear the LLM-review gap.
    assert classify("annotations:machine") == ("llm", "scanned")
    # Human-grade annotations keep full review credit (both-direction).
    assert classify("annotations") == ("llm", "analysed")


def test_backlog_drain_is_static_but_never_review_credit():
    # backlog-drain journal rows carry a synthesized STATIC checker
    # witness (pattern-scanner extent, not an LLM review), so the
    # category is static -- but the depth stays at the unknown/scanned
    # default: drain marks must never count as reviewed or clear the
    # LLM-review gap (both-direction with the reviewed tools above).
    assert classify("backlog-drain") == ("static", "scanned")


def test_journal_records_are_review_grade():
    # coverage-journal.json (build_from_journal; /agentic) derives every
    # functions_analysed entry from a per-function review-journal verdict,
    # so the label classifies as an actual review. Pre-registration it fell
    # to unknown/scanned and journal-derived marks never counted as reviewed.
    assert classify("journal") == ("llm", "analysed")
