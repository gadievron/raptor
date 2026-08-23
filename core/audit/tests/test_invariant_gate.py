"""Receipt-tier invariant gate.

The G2 designed exception ("a hypothesis matching a domain-model
invariant may ship as finding without tool evidence") is justified by
the invariant's MECHANICAL provenance — so only receipt-checked
invariants (actionable tier + verified receipt), in scope for the
outcome's file, with a source-anchored identifier shared with the
hypothesis may license it.  ``llm_summarized`` study leftovers never
qualify: word overlap between two pieces of LLM prose is not
mechanical provenance.
"""

from __future__ import annotations

from core.audit.invariant_gate import (
    match_receipted_invariants,
    resolve_hypothesis,
    reverify_bypass,
)

HYP = "unsanitised input reaches query"

_RECEIPT = {
    "file": "src/auth.py",
    "line": 12,
    "quote": 'cursor.execute("SELECT %s" % query)',
    "verified": True,
    "sha256": "ab" * 8,
    "tier": "verbatim",
}


def _inv(**overrides):
    inv = {
        "id": "INV-1",
        "statement": (
            "user input must be sanitised before it reaches the sql query"
        ),
        "negation": "unsanitised input reaches the query",
        "provenance": "verbatim",
        "receipt": dict(_RECEIPT),
    }
    inv.update(overrides)
    return inv


def _dm(*invariants):
    return {"invariants": list(invariants)}


class TestReceiptTier:
    def test_verbatim_receipted_invariant_matches(self):
        matched = match_receipted_invariants(HYP, "src/auth.py", _dm(_inv()))
        assert [m["id"] for m in matched] == ["INV-1"]
        assert matched[0]["tier"] == "verbatim"
        assert "query" in matched[0]["anchors"]

    def test_llm_summarized_never_matches(self):
        # The exploited population: quote-less invariants the study
        # pipeline keeps demoted to llm_summarized (receipt=None).
        inv = _inv(provenance="llm_summarized", receipt=None)
        assert match_receipted_invariants(HYP, "src/auth.py", _dm(inv)) == []

    def test_llm_prior_never_matches(self):
        inv = _inv(provenance="llm_prior")
        assert match_receipted_invariants(HYP, "src/auth.py", _dm(inv)) == []

    def test_unverified_receipt_never_matches(self):
        receipt = dict(_RECEIPT, verified=False)
        inv = _inv(receipt=receipt)
        assert match_receipted_invariants(HYP, "src/auth.py", _dm(inv)) == []

    def test_missing_provenance_never_matches(self):
        inv = _inv(provenance="")
        assert match_receipted_invariants(HYP, "src/auth.py", _dm(inv)) == []

    def test_mechanical_tier_matches(self):
        inv = _inv(provenance="mechanical")
        matched = match_receipted_invariants(HYP, "src/auth.py", _dm(inv))
        assert [m["tier"] for m in matched] == ["mechanical"]


class TestStructuralAnchor:
    def test_generic_prose_overlap_alone_is_not_a_match(self):
        # Word overlap without any source-anchored identifier: the
        # "generic invariant word-overlaps with virtually every
        # hypothesis" shape. Receipt quote shares no identifier with
        # the hypothesis.
        inv = _inv(receipt=dict(
            _RECEIPT, quote="if (len > buf_size) return -1;",
        ))
        assert match_receipted_invariants(HYP, "src/auth.py", _dm(inv)) == []

    def test_anchor_from_mechanical_rule_counts(self):
        inv = _inv(
            receipt=dict(_RECEIPT, quote="a verified but unrelated quote"),
            mechanical_rule="taint(query) -> sink(execute)",
        )
        matched = match_receipted_invariants(HYP, "src/auth.py", _dm(inv))
        assert [m["id"] for m in matched] == ["INV-1"]

    def test_word_overlap_floor_still_applies(self):
        # An anchored identifier alone is not enough — the historical
        # >=3-word / >=15% floor stays as a necessary condition.
        inv = _inv(
            statement="query results are cached per session",
            negation="",
        )
        assert match_receipted_invariants(HYP, "src/auth.py", _dm(inv)) == []


class TestFileScope:
    def test_scoped_invariant_does_not_match_other_files(self):
        inv = _inv(files=["src/other.c"])
        assert match_receipted_invariants(HYP, "src/auth.py", _dm(inv)) == []

    def test_scoped_invariant_matches_its_own_file(self):
        inv = _inv(files=["src/auth.py"])
        matched = match_receipted_invariants(HYP, "src/auth.py", _dm(inv))
        assert [m["id"] for m in matched] == ["INV-1"]

    def test_unscoped_invariant_stays_global(self):
        matched = match_receipted_invariants(HYP, "lib/util.c", _dm(_inv()))
        assert [m["id"] for m in matched] == ["INV-1"]


class TestG2GateIntegration:
    def _outcome(self, review_result=None):
        from core.audit.orchestrator import ReviewOutcome

        return ReviewOutcome(
            file="src/auth.py",
            function="check_pw",
            status="finding",
            body="finding body",
            hypothesis=HYP,
            review_result=review_result if review_result is not None else {},
        )

    def test_g2_violation_on_llm_summarized_invariant(self):
        from core.audit.orchestrator import _check_finding_gates

        dm = _dm(_inv(provenance="llm_summarized", receipt=None))
        outcome = self._outcome()
        violations = _check_finding_gates(outcome, domain_model=dm)
        assert any(v.startswith("G2:") for v in violations)
        assert "g2_invariant_bypass" not in (outcome.review_result or {})

    def test_g2_exception_stamps_ids_and_tiers(self):
        from core.audit.orchestrator import _check_finding_gates

        outcome = self._outcome()
        violations = _check_finding_gates(outcome, domain_model=_dm(_inv()))
        assert not any(v.startswith("G2:") for v in violations)
        assert outcome.review_result["g2_invariant_bypass"] == ["INV-1"]
        assert outcome.review_result["g2_invariant_bypass_tiers"] == {
            "INV-1": "verbatim",
        }


class TestReverifyBypass:
    def test_no_domain_model_fails_closed(self, tmp_path):
        outcome = TestG2GateIntegration()._outcome(
            review_result={"g2_invariant_bypass": ["INV-1"]},
        )
        assert reverify_bypass(tmp_path, outcome) is False

    def test_receipted_match_reverifies(self, tmp_path):
        import json

        (tmp_path / "domain-model.json").write_text(json.dumps(_dm(_inv())))
        outcome = TestG2GateIntegration()._outcome(
            review_result={"g2_invariant_bypass": ["INV-1"]},
        )
        assert reverify_bypass(tmp_path, outcome) is True


class TestResolveHypothesis:
    def test_prefers_review_result_hypothesis(self):
        class _O:
            hypothesis = "outer"
            review_result = {"hypothesis": "inner"}
            hypotheses = []

        assert resolve_hypothesis(_O()) == "inner"

    def test_falls_back_to_best_confidence_mechanism(self):
        class _O:
            hypothesis = ""
            review_result = {"hypotheses": [
                {"mechanism": "low mech", "confidence": "low"},
                {"mechanism": "high mech", "confidence": "high"},
            ]}
            hypotheses = []

        assert resolve_hypothesis(_O()) == "high mech"
