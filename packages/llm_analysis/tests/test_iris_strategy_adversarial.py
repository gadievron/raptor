"""Adversarial + E2E coverage for the cwe_strategies wire-in to
IRIS's dataflow validator.

Probes hostile inputs and verifies the rendered Hypothesis context
is well-formed across realistic IRIS finding shapes. Covers the
gaps left by ``test_iris_strategy_wiring.py`` (which focuses on
happy-path picks).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from packages.llm_analysis.dataflow_validation import (
    _build_hypothesis,
    _build_strategy_block,
)


# ---------------------------------------------------------------------------
# Hostile finding fields
# ---------------------------------------------------------------------------


class TestHostileFindingFields:
    def test_newline_in_file_path_no_fake_heading(self, tmp_path):
        """Hostile file_path with ``\\n## INJECTED`` must not echo a fake
        heading into trusted-parts. ``_sanitize_for_prompt`` →
        ``neutralize_tag_forgery`` defangs line-start ``#`` runs with a
        leading ``\\`` so visual heading recognition fails while the
        legitimate strategy block (``## Strategy: ...``) renders
        unchanged from operator-curated YAML."""
        finding = {
            "file_path": "src/foo.py\n## INJECTED",
            "start_line": 1, "rule_id": "x", "function": "f",
            "cwe_id": "CWE-89",
        }
        h = _build_hypothesis(finding, {}, tmp_path)
        # Strategy block fires and renders cleanly.
        assert "Bug-class lenses" in h.context
        assert "## Strategy: input_handling" in h.context
        # No bare ``## INJECTED`` heading anywhere — defanged form is
        # ``\## INJECTED``, which the model parses as text, not a
        # heading peer of the legitimate ``## Strategy:`` markers.
        assert "\n## INJECTED" not in h.context
        assert "\\## INJECTED" in h.context

    def test_newline_in_function_name_no_fake_heading(self, tmp_path):
        finding = {
            "file_path": "src/x.py", "start_line": 1,
            "rule_id": "x",
            "function": "parse\n## INJECTED_HEADING",
            "cwe_id": "CWE-89",
        }
        h = _build_hypothesis(finding, {}, tmp_path)
        assert "## INJECTED_HEADING" not in h.context
        # The legitimate ``parse`` token still pins input_handling.
        assert "## Strategy: input_handling" in h.context

    def test_huge_cwe_id_doesnt_blow_up_context(self, tmp_path):
        finding = {
            "file_path": "src/x.py", "start_line": 1,
            "rule_id": "x", "function": "f",
            "cwe_id": "CWE-" + "9" * 50_000,
        }
        h = _build_hypothesis(finding, {}, tmp_path)
        # Picker treats it as no-match (no strategy declares such
        # a CWE). Context bounded; no echo of the giant string.
        assert "CWE-99999999999999" not in h.context
        # Still under a reasonable size.
        assert len(h.context) < 10_000

    def test_hostile_metadata_calls_with_none_member(self, tmp_path):
        """A None entry in metadata.calls list shouldn't crash the
        picker — operator-supplied lists may be sloppy."""
        finding = {
            "file_path": "src/x.py", "start_line": 1,
            "rule_id": "x", "function": "f",
            "metadata": {"calls": ["mutex_lock", None, "kfree"]},
        }
        h = _build_hypothesis(finding, {}, tmp_path)
        # No crash; whatever the picker filtered on still produces
        # output. concurrency strategy fires on mutex_lock.
        assert "## Strategy:" in h.context

    def test_hostile_metadata_huge_calls_list(self, tmp_path):
        """1000-entry calls list — picker scales, render_strategies
        caps total output."""
        finding = {
            "file_path": "src/x.py", "start_line": 1,
            "rule_id": "x", "function": "f",
            "metadata": {
                "calls": (
                    ["mutex_lock"]
                    + [f"noise_{i}" for i in range(1000)]
                ),
            },
        }
        h = _build_hypothesis(finding, {}, tmp_path)
        # Concurrency fires (mutex_lock); context bounded.
        assert "## Strategy: concurrency" in h.context
        assert len(h.context) < 32_000


# ---------------------------------------------------------------------------
# CWE precedence (analysis vs finding)
# ---------------------------------------------------------------------------


class TestCwePrecedence:
    def test_analysis_cwe_wins_over_finding_cwe(self, tmp_path):
        """When both finding.cwe_id and analysis.cwe_id are set,
        the LLM analysis's CWE is the more recent / specific
        signal — it should drive strategy selection."""
        finding = {
            "file_path": "src/x.py", "start_line": 1,
            "rule_id": "x", "function": "f",
            "cwe_id": "CWE-89",  # SQL injection (input_handling)
        }
        analysis = {
            # LLM refined to the structural cause.
            "cwe_id": "CWE-416",  # use-after-free (memory_management)
        }
        h = _build_hypothesis(finding, analysis, tmp_path)
        assert "## Strategy: memory_management" in h.context

    def test_finding_cwe_used_when_analysis_has_none(self, tmp_path):
        finding = {
            "file_path": "src/x.py", "start_line": 1,
            "rule_id": "x", "function": "f",
            "cwe_id": "CWE-78",
        }
        analysis = {}  # no cwe_id
        h = _build_hypothesis(finding, analysis, tmp_path)
        assert "## Strategy: input_handling" in h.context


# ---------------------------------------------------------------------------
# Strategy block placement (trusted, not untrusted)
# ---------------------------------------------------------------------------


class TestStrategyPlacement:
    def test_strategy_block_above_untrusted_envelope(self, tmp_path):
        """Strategy guidance is operator-curated trusted content —
        it must appear in the trusted region of the Hypothesis
        context, BEFORE the untrusted_finding_context envelope."""
        finding = {
            "file_path": "src/x.py", "start_line": 1,
            "rule_id": "x", "function": "f",
            "cwe_id": "CWE-89",
            "message": "scanner reflected message",
        }
        analysis = {"reasoning": "LLM reflected reasoning"}
        h = _build_hypothesis(finding, analysis, tmp_path)
        ctx = h.context
        # Both blocks present.
        bug_pos = ctx.find("Bug-class lenses")
        envelope_pos = ctx.find("<untrusted_finding_context>")
        assert bug_pos > 0
        assert envelope_pos > 0
        # Strategy block precedes the untrusted envelope.
        assert bug_pos < envelope_pos


# ---------------------------------------------------------------------------
# E2E — realistic IRIS finding shapes producing distinct strategies
# ---------------------------------------------------------------------------


class TestE2EDistinctStrategies:
    """Sanity check that the wire-in actually shapes output —
    different CWEs produce demonstrably different validator
    contexts."""

    def test_path_traversal_finding(self, tmp_path):
        """CWE-22 path-traversal IRIS pack scenario: the validator
        gets input_handling lenses + CVE-2023-0179 exemplar."""
        finding = {
            "file_path": "src/api/upload.py",
            "start_line": 87,
            "rule_id": "py/path-injection",
            "cwe_id": "CWE-22",
            "function": "save_user_upload",
            "message": "User-controlled path component in file open",
        }
        analysis = {
            "cwe_id": "CWE-22",
            "dataflow_summary": "request → safe_join → open",
            "reasoning": "the path component is concatenated with user input",
        }
        h = _build_hypothesis(finding, analysis, tmp_path)
        assert "## Strategy: input_handling" in h.context
        assert "CVE-2023-0179" in h.context  # input_handling exemplar

    def test_uaf_finding(self, tmp_path):
        finding = {
            "file_path": "src/buf.c", "start_line": 50,
            "rule_id": "cpp/use-after-free", "cwe_id": "CWE-416",
            "function": "release_buf",
        }
        analysis = {"cwe_id": "CWE-416"}
        h = _build_hypothesis(finding, analysis, tmp_path)
        assert "## Strategy: memory_management" in h.context
        # memory_management exemplars include CVE-2024-1086 and
        # CVE-2022-2588.
        assert "CVE-2024-1086" in h.context or "CVE-2022-2588" in h.context

    def test_path_traversal_vs_uaf_produce_different_content(self, tmp_path):
        """Two findings with different CWEs must produce different
        validator contexts — pin that the wiring actually shapes
        output, not just adds a fixed boilerplate."""
        f_path = {
            "file_path": "src/x.py", "start_line": 1,
            "rule_id": "x", "function": "f", "cwe_id": "CWE-22",
        }
        f_uaf = {
            "file_path": "src/x.c", "start_line": 1,
            "rule_id": "x", "function": "f", "cwe_id": "CWE-416",
        }
        h_path = _build_hypothesis(f_path, {"cwe_id": "CWE-22"}, tmp_path)
        h_uaf = _build_hypothesis(f_uaf, {"cwe_id": "CWE-416"}, tmp_path)

        assert "input_handling" in h_path.context
        assert "memory_management" in h_uaf.context
        # The two contexts are demonstrably distinct.
        assert h_path.context != h_uaf.context


# ---------------------------------------------------------------------------
# Size bound across realistic flows
# ---------------------------------------------------------------------------


class TestSizeBounds:
    def test_full_signal_stack_stays_bounded(self, tmp_path):
        """Worst case: CWE pin + strong path + multiple callees +
        long reasoning + scanner message. Total Hypothesis context
        should still fit within prompt budget."""
        finding = {
            "file_path": "kernel/locking/rwsem.c",
            "start_line": 287,
            "rule_id": "cpp/use-after-free",
            "cwe_id": "CWE-416",
            "function": "rwsem_acquire_locked",
            "message": "x" * 1000,  # bounded message
            "metadata": {
                "calls": ["mutex_lock", "kfree", "refcount_dec_and_test"],
                "includes": ["linux/mutex.h", "linux/refcount.h"],
            },
        }
        analysis = {
            "cwe_id": "CWE-416",
            "reasoning": "x" * 5000,  # bounded reasoning
            "dataflow_summary": "y" * 1000,  # bounded summary
        }
        h = _build_hypothesis(finding, analysis, tmp_path)
        # Even with multiple strategy matches + capped reasoning +
        # bounded message + scanner content, total under 16KB.
        assert len(h.context) < 16_000
