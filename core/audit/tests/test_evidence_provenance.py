"""Tests for evidence provenance — receipts vs model claims.

G2 [TOOL-GROUNDED] can only hold if a value stamped by the orchestrator
after a real tool run is structurally distinguishable from a value the
model typed into its own response. These tests pin that boundary.
"""

from __future__ import annotations

from core.audit._util import (
    BARE_TOOL_EVIDENCE,
    LLM_CLAIM_PREFIX,
    TOOL_EVIDENCE_NAMESPACES,
    is_stamped_tool_evidence,
    sanitize_llm_evidence_tool,
)
from core.audit.evidence_grade import Confidence, grade_review_result
from core.audit.llm_review import _normalize_evidence_tool
from core.audit.orchestrator import (
    ReviewOutcome,
    _check_finding_gates,
    _is_evidence_only_gate_demotion,
    _is_tool_confirmed,
    _is_ungrounded_evidence,
)


class TestIsStampedToolEvidence:
    def test_real_stamps_are_receipts(self):
        for stamp in (
            "prefilter:unchecked_index",
            "smt:check-oob",
            "joern:live",
            "joern:pre_sweep",
            "semgrep:hypothesis",
            "coccinelle:missing_bounds_check",
            "codeql:dataflow",
            "sarif_cache:semgrep",
            "critique:prefilter:rule_7",
        ):
            assert is_stamped_tool_evidence(stamp), stamp

    def test_bare_dynamic_tokens_are_receipts(self):
        for token in BARE_TOOL_EVIDENCE:
            assert is_stamped_tool_evidence(token)

    def test_combined_stamp_is_a_receipt(self):
        assert is_stamped_tool_evidence("smt:check-oob+coccinelle:bounds")

    def test_bare_tool_name_is_not_a_receipt(self):
        # The exact values the review schema invites the model to emit.
        for claim in ("prefilter", "semgrep", "joern", "codeql", "smt",
                      "coccinelle", "sweep", "critique", "taint_approx"):
            assert not is_stamped_tool_evidence(claim), claim

    def test_unknown_namespace_is_not_a_receipt(self):
        assert not is_stamped_tool_evidence("prefilter-fake:rule")
        assert not is_stamped_tool_evidence("sweepstakes:win")
        assert not is_stamped_tool_evidence("madeup:thing")

    def test_namespace_without_detail_is_not_a_receipt(self):
        assert not is_stamped_tool_evidence("prefilter:")

    def test_receipt_detail_may_contain_a_plus(self):
        """Validation anchors on the leading component, deliberately.

        A composite label is `"+".join(...)` over receipts the
        orchestrator just issued, and details are free text — a Semgrep
        rule_id or a Coccinelle rule stem can contain `+`. Demanding
        every `+`-fragment parse would reject real receipts, and a
        false negative here silently downgrades genuine evidence.
        The prefix is what a claim cannot forge.
        """
        assert is_stamped_tool_evidence("semgrep:rules/a+b.yaml")
        assert is_stamped_tool_evidence("coccinelle:lock+unlock")

    def test_leading_component_still_governs(self):
        assert not is_stamped_tool_evidence("joern+smt:check-oob")
        assert not is_stamped_tool_evidence("llm-claimed:joern+smt:check-oob")

    def test_critique_validates_the_wrapped_receipt(self):
        assert is_stamped_tool_evidence("critique:semgrep:r1")
        assert not is_stamped_tool_evidence("critique:madeup:x")
        assert not is_stamped_tool_evidence("critique:joern")

    def test_retired_sweep_namespace_is_not_a_receipt(self):
        """`sweep` had no issuer; an unissuable receipt shape is surface."""
        assert not is_stamped_tool_evidence("sweep:anything")

    def test_empty_is_not_a_receipt(self):
        assert not is_stamped_tool_evidence("")
        assert not is_stamped_tool_evidence(None)


class TestSanitizeLlmEvidenceTool:
    def test_no_model_value_can_become_a_receipt(self):
        # Every namespace the model might guess, bare and namespaced.
        candidates = list(TOOL_EVIDENCE_NAMESPACES) + [
            f"{ns}:whatever" for ns in TOOL_EVIDENCE_NAMESPACES
        ] + list(BARE_TOOL_EVIDENCE)
        for raw in candidates:
            assert not is_stamped_tool_evidence(sanitize_llm_evidence_tool(raw)), raw

    def test_claim_is_preserved_for_the_audit_trail(self):
        assert sanitize_llm_evidence_tool("joern") == f"{LLM_CLAIM_PREFIX}joern"

    def test_explicit_no_tool_values_collapse_to_llm(self):
        for raw in ("llm", "LLM", "manual review", "none", "n/a", "", "  "):
            assert sanitize_llm_evidence_tool(raw) == "llm"

    def test_idempotent(self):
        once = sanitize_llm_evidence_tool("semgrep")
        assert sanitize_llm_evidence_tool(once) == once

    def test_llm_review_normalizer_uses_the_sanitizer(self):
        assert _normalize_evidence_tool("prefilter") == f"{LLM_CLAIM_PREFIX}prefilter"
        assert _normalize_evidence_tool("llm") == "llm"


class TestIsToolConfirmed:
    def test_model_claim_does_not_short_circuit_validation(self):
        # This is the regression: a model answering evidence_tool="prefilter"
        # used to satisfy _is_tool_confirmed and skip _sweep_validate's
        # entire tool chain.
        assert not _is_tool_confirmed(_normalize_evidence_tool("prefilter"))
        assert not _is_tool_confirmed(_normalize_evidence_tool("joern"))

    def test_real_stamp_still_short_circuits(self):
        assert _is_tool_confirmed("prefilter:unchecked_index")
        assert _is_tool_confirmed("codeql:dataflow")


class TestG2Gate:
    def _finding(self, evidence_tool):
        return ReviewOutcome(
            file="src/x.c",
            function="parse",
            status="finding",
            body="tested with a tool",
            hypothesis="unchecked length reaches memcpy",
            evidence_tool=evidence_tool,
        )

    def test_model_claimed_tool_fails_g2(self):
        violations = _check_finding_gates(
            self._finding(_normalize_evidence_tool("joern"))
        )
        assert any(v.startswith("G2") for v in violations), violations

    def test_real_receipt_passes_g2(self):
        violations = _check_finding_gates(self._finding("joern:live"))
        assert not any(v.startswith("G2") for v in violations), violations

    def test_explicit_llm_still_fails_g2(self):
        violations = _check_finding_gates(self._finding("llm"))
        assert any(v.startswith("G2") for v in violations)

    def test_ungrounded_predicate(self):
        assert _is_ungrounded_evidence("llm")
        assert _is_ungrounded_evidence("")
        assert _is_ungrounded_evidence(f"{LLM_CLAIM_PREFIX}semgrep")
        assert not _is_ungrounded_evidence("semgrep:rule")


class TestEvidenceGradingNotLaundered:
    def test_model_claim_does_not_grade_as_high_confidence(self):
        """A claimed 'joern' must not export as 'confirmed by Joern'."""
        claimed = _normalize_evidence_tool("joern")
        items = grade_review_result(
            {"hypothesis": "tainted length reaches memcpy"},
            evidence_tool=claimed,
        )
        descriptions = [i.description for i in items]
        assert not any("confirmed by Joern" in d for d in descriptions), descriptions
        assert not any(
            i.confidence == Confidence.HIGH for i in items
        ), [(i.source, i.confidence) for i in items]


class TestReviewResultIsSanitizedToo:
    """The nested model dict must not smuggle the raw claim past the gate.

    G2, ``_sweep_validate`` and ``_proactive_validate`` all read
    ``review_result["evidence_tool"]`` in preference to the outcome
    field, so sanitizing only the outcome left the boundary open.
    """

    def _outcome_from_model(self, claimed):
        """Mirror what make_review_fn builds from a model response."""
        result = {
            "status": "finding",
            "hypothesis": "unchecked length reaches memcpy",
            "body": "tested",
            "evidence_tool": claimed,
        }
        evidence_tool = _normalize_evidence_tool(result.get("evidence_tool") or "")
        if claimed:
            result["evidence_tool_claim"] = claimed
        result["evidence_tool"] = evidence_tool
        return ReviewOutcome(
            file="src/x.c", function="parse", status="finding",
            body=result["body"], hypothesis=result["hypothesis"],
            evidence_tool=evidence_tool, review_result=result,
        )

    def test_nested_value_is_sanitized(self):
        for claimed in ("joern:live", "dynamic", "frida", "prefilter", "joern"):
            o = self._outcome_from_model(claimed)
            nested = o.review_result["evidence_tool"]
            assert not _is_tool_confirmed(nested), (claimed, nested)

    def test_nested_value_fails_g2(self):
        for claimed in ("joern:live", "dynamic", "prefilter", "semgrep"):
            o = self._outcome_from_model(claimed)
            violations = _check_finding_gates(o)
            assert any(v.startswith("G2") for v in violations), claimed

    def test_original_claim_is_preserved_for_the_trail(self):
        o = self._outcome_from_model("joern")
        assert o.review_result["evidence_tool_claim"] == "joern"


class TestG2RequiresAReceipt:
    def _finding(self, evidence_tool):
        return ReviewOutcome(
            file="src/x.c", function="parse", status="finding",
            body="tested", hypothesis="unchecked length reaches memcpy",
            evidence_tool=evidence_tool,
        )

    def test_arbitrary_strings_fail(self):
        for bogus in ("madeup:thing", "sweepstakes:win", "joern",
                      "prefilter", "totally arbitrary text", "compilation"):
            v = _check_finding_gates(self._finding(bogus))
            assert any(x.startswith("G2") for x in v), bogus

    def test_every_registered_bare_receipt_passes(self):
        for token in BARE_TOOL_EVIDENCE:
            v = _check_finding_gates(self._finding(token))
            assert not any(x.startswith("G2") for x in v), token


class TestGateDemotionRecoverability:
    def test_g2_only_demotion_is_recoverable(self):
        body = "[gate violation: G2: finding emitted without tool-grounded evidence]\n\nx"
        assert _is_evidence_only_gate_demotion(body)

    def test_mixed_demotion_is_terminal(self):
        body = ("[gate violation: G2: finding emitted without tool-grounded "
                "evidence; G5: memory CWE in a memory-safe language]\n\nx")
        assert not _is_evidence_only_gate_demotion(body)

    def test_non_g2_demotion_is_terminal(self):
        body = "[gate violation: G1: finding emitted without testable hypothesis]\n\nx"
        assert not _is_evidence_only_gate_demotion(body)

    def test_non_gate_body_is_not_matched(self):
        assert not _is_evidence_only_gate_demotion("[guarded-sink: all guarded]")
        assert not _is_evidence_only_gate_demotion("ordinary body")


class TestCritiqueNestingIsBounded:
    def test_single_nesting_is_a_receipt(self):
        assert is_stamped_tool_evidence("critique:semgrep:r1")

    def test_pathological_nesting_terminates_and_rejects(self):
        assert not is_stamped_tool_evidence("critique:" * 5000 + "semgrep:r")

    def test_critique_without_a_wrapped_receipt_fails(self):
        assert not is_stamped_tool_evidence("critique:critique:critique:")
