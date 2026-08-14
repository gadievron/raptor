"""Tests for the rationale-consistency gate in core.audit.llm_review."""

from __future__ import annotations

from core.audit.llm_review import _rationale_consistency_should_demote


class TestRationaleConsistencyGate:
    def test_clean_phrase_demotes(self):
        assert _rationale_consistency_should_demote(
            status="finding",
            body="The function is safe and follows best practices.",
            hypothesis="potential overflow",
            evidence_tool="",
        )

    def test_no_vulnerability_demotes(self):
        assert _rationale_consistency_should_demote(
            status="suspicious",
            body="There is no vulnerability in this code path.",
            hypothesis="possible null deref",
            evidence_tool="",
        )

    def test_clean_status_not_demoted(self):
        assert not _rationale_consistency_should_demote(
            status="clean",
            body="Function is safe.",
            hypothesis="",
            evidence_tool="",
        )

    def test_dormant_status_not_demoted(self):
        assert not _rationale_consistency_should_demote(
            status="dormant",
            body="Function is safe.",
            hypothesis="",
            evidence_tool="",
        )

    def test_hedging_hypothesis_blocks_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="The function is safe overall.",
            hypothesis="overflow however constrained by caller",
            evidence_tool="",
        )

    def test_qualifier_except_blocks_demotion(self):
        """'properly validated except the length field' should NOT demote."""
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="All inputs are properly validated except the length field "
                 "which is taken directly from the network packet.",
            hypothesis="unchecked length",
            evidence_tool="",
        )

    def test_qualifier_but_blocks_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="The function is safe but the cast on line 47 is unchecked.",
            hypothesis="type cast issue",
            evidence_tool="",
        )

    def test_qualifier_however_blocks_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="No vulnerability in the main path however the error "
                 "handler lacks bounds checking.",
            hypothesis="error path overflow",
            evidence_tool="",
        )

    def test_qualifier_unless_blocks_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="Safely handled unless the caller passes a negative length.",
            hypothesis="negative length",
            evidence_tool="",
        )

    def test_qualifier_with_the_exception_blocks_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="suspicious",
            body="All paths are guarded with the exception of the fallthrough "
                 "case in the switch statement.",
            hypothesis="missing case",
            evidence_tool="",
        )

    def test_qualifier_apart_from_blocks_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="No exploitable condition apart from the integer wraparound.",
            hypothesis="integer overflow",
            evidence_tool="",
        )

    def test_qualifier_other_than_blocks_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="Correctly bounded other than the final iteration.",
            hypothesis="off-by-one",
            evidence_tool="",
        )

    def test_qualifier_excluding_blocks_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="No bug in the normal path excluding the error recovery.",
            hypothesis="error recovery bug",
            evidence_tool="",
        )

    def test_evidence_tool_blocks_demotion(self):
        """Mechanical corroboration overrides body text."""
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="The function is safe and clean.",
            hypothesis="overflow",
            evidence_tool="smt:check-overflow",
        )

    def test_semgrep_evidence_blocks_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="suspicious",
            body="No vulnerability detected in this function.",
            hypothesis="taint flow",
            evidence_tool="semgrep:taint-rule-42",
        )

    def test_qualifier_far_away_does_not_block(self):
        """Qualifier >60 chars after phrase should NOT block demotion."""
        padding = "x" * 70
        assert _rationale_consistency_should_demote(
            status="finding",
            body=f"The function is safe. {padding} except for edge cases.",
            hypothesis="edge case",
            evidence_tool="",
        )

    def test_no_clean_phrase_no_demotion(self):
        assert not _rationale_consistency_should_demote(
            status="finding",
            body="The function processes network data and has complex logic.",
            hypothesis="buffer overflow",
            evidence_tool="",
        )

    def test_multiple_phrases_first_qualified_second_not(self):
        """If first phrase is qualified but second is not, should demote."""
        assert _rationale_consistency_should_demote(
            status="finding",
            body="Properly validated except for len. But overall no bug "
                 "in the main code path.",
            hypothesis="len issue",
            evidence_tool="",
        )

    def test_case_insensitive(self):
        assert _rationale_consistency_should_demote(
            status="finding",
            body="The FUNCTION IS SAFE and well-tested.",
            hypothesis="possible issue",
            evidence_tool="",
        )

    def test_whitespace_only_evidence_tool_ignored(self):
        assert _rationale_consistency_should_demote(
            status="finding",
            body="No vulnerability found.",
            hypothesis="test",
            evidence_tool="   ",
        )
