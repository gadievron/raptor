"""Tests for CWE fallback inference and unmapped-CWE visibility.

Reviews frequently emit ``cwe: ""`` even for non-clean verdicts, which
starved every CWE-seeded tool chain. These tests pin:

- ``_effective_cwe``: keyword inference from hypothesis texts when the
  review field is empty, marked in review_result and tier telemetry.
- Chain seeding uses the inferred value.
- A review-emitted CWE with no dispatch entry logs one line instead of
  silently dispatching nothing.
- The review schema demands a CWE for non-clean / hypothesis-bearing
  verdicts without making the field structurally required.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace


def _outcome(status="suspicious", cwe="", hypothesis="", hypotheses=None):
    from core.audit.orchestrator import ReviewOutcome
    o = ReviewOutcome(
        file="a.c", function="f", status=status,
        body="", hypothesis=hypothesis, line=1,
    )
    o.hypotheses = hypotheses
    o.review_result = {
        "cwe": cwe,
        "hypothesis": hypothesis,
        "hypotheses": hypotheses or [],
    }
    return o


class TestEffectiveCwe:
    def test_prefers_review_value(self):
        from core.audit.orchestrator import _effective_cwe
        o = _outcome(cwe="CWE-79", hypothesis="integer overflow in calc")
        assert _effective_cwe(o) == "CWE-79"
        assert "cwe_inferred" not in o.review_result

    def test_infers_from_primary_hypothesis(self):
        from core.audit.orchestrator import _effective_cwe, _make_tier_counters
        tc = _make_tier_counters()
        o = _outcome(hypothesis="integer overflow in size calculation")
        assert _effective_cwe(o, tc) == "CWE-190"
        assert o.review_result["cwe_inferred"] == "CWE-190"
        assert tc["cwe_inference"].confirmed == 1

    def test_infers_from_hypothesis_array_mechanism(self):
        from core.audit.orchestrator import _effective_cwe, _make_tier_counters
        tc = _make_tier_counters()
        o = _outcome(hypotheses=[
            {"mechanism": "use-after-free of ctx->buf on error path",
             "confidence": "refuted"},
        ])
        assert _effective_cwe(o, tc) == "CWE-416"
        assert o.review_result["cwe_inferred"] == "CWE-416"
        assert tc["cwe_inference"].confirmed == 1

    def test_no_texts_returns_empty(self):
        from core.audit.orchestrator import _effective_cwe
        o = _outcome()
        assert _effective_cwe(o) == ""

    def test_unmatchable_text_counts_inconclusive(self):
        from core.audit.orchestrator import _effective_cwe, _make_tier_counters
        tc = _make_tier_counters()
        o = _outcome(hypothesis="business logic error in refund flow")
        assert _effective_cwe(o, tc) == ""
        assert tc["cwe_inference"].inconclusive == 1

    def test_reuses_prior_inference_without_recount(self):
        from core.audit.orchestrator import _effective_cwe, _make_tier_counters
        tc = _make_tier_counters()
        o = _outcome(hypothesis="integer overflow in size calculation")
        assert _effective_cwe(o, tc) == "CWE-190"
        assert _effective_cwe(o, tc) == "CWE-190"
        assert tc["cwe_inference"].confirmed == 1


class TestInferredChainSeeding:
    def test_promote_suspicious_seeds_chain_with_inferred_cwe(
        self, tmp_path, monkeypatch,
    ):
        """Empty review cwe + overflow hypothesis → the sweep's tool
        chain is seeded with the inferred CWE (previously cwe="")."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _promote_suspicious,
        )
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=tmp_path, out_dir=out)

        outcome = _outcome(
            status="suspicious",
            hypothesis="integer overflow in size calculation before memcpy",
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1

        seeded_cwes = []

        def fake_chain(hypothesis, file_path, cwe=""):
            seeded_cwes.append(cwe)
            return []

        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain", fake_chain,
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain", lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: SimpleNamespace(hits=[]),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int f(int x) { return x + 1; }",
        )
        # The chain-less suspicious outcome falls through to on-demand
        # verification-rule synthesis, which builds a REAL LLMClient —
        # on a host with `claude` on PATH that spawned live `claude -p`
        # subprocesses (1 call + 3 retries) from this unit test: paid
        # calls on connected hosts, multi-minute hangs on hosts without
        # a route. Stub it like TestOnDemandHookInPromoteSuspicious
        # does; this test only asserts the inferred-CWE seeding.
        monkeypatch.setattr(
            "core.audit.checker_synthesis.synthesize_verification_rule",
            lambda *a, **kw: None,
        )
        _promote_suspicious(result, config)
        assert seeded_cwes == ["CWE-190"]
        assert outcome.review_result["cwe_inferred"] == "CWE-190"
        assert result.tier_counters["cwe_inference"].confirmed == 1


class TestUnmappedCweVisibility:
    def _reset(self):
        from core.audit import orchestrator
        orchestrator._UNMAPPED_CWES_LOGGED.clear()

    def test_unmapped_cwe_logs_one_line(self, caplog):
        from core.audit.orchestrator import _cwe_fallback_chain
        self._reset()
        with caplog.at_level(logging.WARNING, logger="core.audit.orchestrator"):
            chain = _cwe_fallback_chain("CWE-440")
        assert chain == []
        warnings = [
            r for r in caplog.records
            if "CWE-440" in r.getMessage() and "no tool-chain dispatch" in r.getMessage()
        ]
        assert len(warnings) == 1

    def test_unmapped_cwe_logged_once_per_run(self, caplog):
        from core.audit.orchestrator import _cwe_fallback_chain
        self._reset()
        with caplog.at_level(logging.WARNING, logger="core.audit.orchestrator"):
            _cwe_fallback_chain("CWE-440")
            _cwe_fallback_chain("CWE-440")
            _cwe_fallback_chain("cwe-440")
        warnings = [
            r for r in caplog.records
            if "CWE-440" in r.getMessage() and "no tool-chain dispatch" in r.getMessage()
        ]
        assert len(warnings) == 1

    def test_mapped_cwe_does_not_log(self, caplog):
        from core.audit.orchestrator import _cwe_fallback_chain
        self._reset()
        with caplog.at_level(logging.WARNING, logger="core.audit.orchestrator"):
            chain = _cwe_fallback_chain("CWE-190")
        assert chain  # dispatch entries exist
        assert not [
            r for r in caplog.records
            if "no tool-chain dispatch" in r.getMessage()
        ]


class TestSchemaCweWording:
    def test_description_demands_cwe_for_non_clean_and_hypotheses(self):
        from core.audit.llm_review import REVIEW_SCHEMA
        desc = REVIEW_SCHEMA["properties"]["cwe"]["description"]
        assert "most specific" in desc
        assert "NOT clean" in desc
        assert "hypotheses" in desc
        # Clean verdicts may still leave it empty — the demand is
        # prompt-side, not structural.
        assert "clean" in desc

    def test_blind_schema_shares_cwe_field(self):
        from core.audit.llm_review import REVIEW_SCHEMA, REVIEW_SCHEMA_BLIND
        assert (
            REVIEW_SCHEMA_BLIND["properties"]["cwe"]
            is REVIEW_SCHEMA["properties"]["cwe"]
        )
