"""Tests for secondary-hypothesis dispatch and multiplicity export.

Reviews return a hypotheses array; only the primary drove dispatch.
The secondary lane dispatches non-primary medium/high entries through
tool chains. No real tools or LLM calls — the chain is stubbed."""

from __future__ import annotations


def _outcome(status="suspicious", hypotheses=None, function="multi_fn"):
    from core.audit.orchestrator import ReviewOutcome
    primary = "integer overflow in size calculation before malloc"
    o = ReviewOutcome(
        file="a.c", function=function, status=status,
        body="two independent problems here", hypothesis=primary, line=5,
    )
    o.hypotheses = hypotheses or []
    o.review_result = {
        "hypothesis": primary,
        "hypotheses": o.hypotheses,
    }
    return o


def _config(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=tmp_path, out_dir=out)


def _result(outcomes):
    from core.audit.orchestrator import OrchestratorResult
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
    r.findings = sum(1 for o in outcomes if o.status == "finding")
    return r


def _patch_chain(monkeypatch, confirmations, chain_calls=None):
    def fake_chain(hypothesis, file_path, cwe=""):
        if chain_calls is not None:
            chain_calls.append(hypothesis)
        return [{"type": "semgrep", "config": {}}]

    monkeypatch.setattr(
        "core.audit.orchestrator._hypothesis_to_tool_chain", fake_chain,
    )
    monkeypatch.setattr(
        "core.audit.orchestrator._run_tool_chain",
        lambda *a, **kw: list(confirmations),
    )
    monkeypatch.setattr(
        "core.audit.orchestrator._read_raw_source",
        lambda *a, **kw: "void multi_fn(void) { }",
    )


class TestDispatchSecondaryHypotheses:
    def test_confirmed_secondary_promotes_suspicious(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _dispatch_secondary_hypotheses,
        )
        secondary_mech = "missing auth check before admin_reset() call"
        outcome = _outcome(hypotheses=[
            {"mechanism": secondary_mech, "confidence": "medium"},
        ])
        result = _result([outcome])
        _patch_chain(monkeypatch, ["semgrep:auth-rule"])

        _dispatch_secondary_hypotheses(result, _config(tmp_path))

        promoted = result.outcomes[0]
        assert promoted.status == "finding"
        assert promoted.evidence_tool == "semgrep:auth-rule"
        assert promoted.hypothesis == secondary_mech
        assert promoted.body.startswith(
            "[secondary-hypothesis-confirmed via semgrep:auth-rule]",
        )
        assert promoted.hypotheses == outcome.hypotheses
        assert result.secondary_confirmed == 1
        assert result.sweep_promoted == 1
        assert result.suspicious == 0
        assert result.findings == 1
        rr = promoted.review_result
        assert rr["secondary_hypothesis_confirmed"] is True
        assert rr["secondary_confirmations"][0]["mechanism"] == secondary_mech
        tc = result.tier_counters["secondary_sweep"]
        assert tc.confirmed == 1

    def test_confirmed_secondary_on_finding_records_only(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _dispatch_secondary_hypotheses,
        )
        outcome = _outcome(status="finding", hypotheses=[
            {"mechanism": "use-after-free of conn on retry path",
             "confidence": "high"},
        ])
        outcome.evidence_tool = "smt:check-overflow"
        result = _result([outcome])
        _patch_chain(monkeypatch, ["coccinelle:uaf-rule"])

        _dispatch_secondary_hypotheses(result, _config(tmp_path))

        kept = result.outcomes[0]
        assert kept.status == "finding"
        # Original receipt untouched; extra mechanism recorded.
        assert kept.evidence_tool == "smt:check-overflow"
        assert result.secondary_confirmed == 1
        assert result.findings == 1
        secs = kept.review_result["secondary_confirmations"]
        assert secs[0]["evidence_tool"] == "coccinelle:uaf-rule"

    def test_refuted_and_low_entries_not_dispatched(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _dispatch_secondary_hypotheses,
        )
        outcome = _outcome(hypotheses=[
            {"mechanism": "refuted mechanism", "confidence": "refuted"},
            {"mechanism": "low-confidence mechanism", "confidence": "low"},
        ])
        result = _result([outcome])
        chain_calls: list = []
        _patch_chain(monkeypatch, [], chain_calls=chain_calls)

        _dispatch_secondary_hypotheses(result, _config(tmp_path))

        assert chain_calls == []
        assert result.outcomes[0].status == "suspicious"

    def test_primary_duplicate_skipped(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            _dispatch_secondary_hypotheses,
        )
        outcome = _outcome(hypotheses=[
            {"mechanism": "integer overflow in size calculation before "
                          "malloc",
             "confidence": "high"},
        ])
        result = _result([outcome])
        chain_calls: list = []
        _patch_chain(monkeypatch, [], chain_calls=chain_calls)

        _dispatch_secondary_hypotheses(result, _config(tmp_path))

        assert chain_calls == []

    def test_dispatches_capped_per_function(self, tmp_path, monkeypatch):
        from core.audit import orchestrator as orch

        hyps = [
            {"mechanism": f"distinct mechanism variant number {n} in "
                          f"handler_{n}() at line {100 + n}",
             "confidence": "medium"}
            for n in range(6)
        ]
        outcome = _outcome(hypotheses=hyps)
        result = _result([outcome])
        chain_calls: list = []
        _patch_chain(monkeypatch, [], chain_calls=chain_calls)

        orch._dispatch_secondary_hypotheses(result, _config(tmp_path))

        assert len(chain_calls) == orch._MAX_REFUTED_DISPATCHES_PER_FN

    def test_detection_only_confirmation_does_not_promote(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _dispatch_secondary_hypotheses,
        )
        outcome = _outcome(hypotheses=[
            {"mechanism": "missing bounds check on idx before array write",
             "confidence": "high"},
        ])
        result = _result([outcome])
        _patch_chain(monkeypatch, ["coccinelle:det-rule"])
        monkeypatch.setattr(
            "core.audit.orchestrator._is_detection_only",
            lambda tool_id: True,
        )

        _dispatch_secondary_hypotheses(result, _config(tmp_path))

        assert result.outcomes[0].status == "suspicious"
        assert result.secondary_confirmed == 0

    def test_clean_outcomes_skipped(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            _dispatch_secondary_hypotheses,
        )
        outcome = _outcome(status="clean", hypotheses=[
            {"mechanism": "some live mechanism", "confidence": "high"},
        ])
        result = _result([outcome])
        chain_calls: list = []
        _patch_chain(monkeypatch, [], chain_calls=chain_calls)

        _dispatch_secondary_hypotheses(result, _config(tmp_path))

        assert chain_calls == []

    def test_high_confidence_ranked_before_medium(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            _dispatch_secondary_hypotheses,
        )
        outcome = _outcome(hypotheses=[
            {"mechanism": "medium mechanism with detail_fn() at line 120",
             "confidence": "medium"},
            {"mechanism": "high mechanism", "confidence": "high"},
        ])
        result = _result([outcome])
        chain_calls: list = []
        _patch_chain(monkeypatch, [], chain_calls=chain_calls)

        _dispatch_secondary_hypotheses(result, _config(tmp_path))

        assert chain_calls[0] == "high mechanism"


class TestMultiplicityExport:
    def _outcome_for_export(self, status="suspicious", hypotheses=None,
                            review_extra=None):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="a.c", function="f", status=status,
            body="b", hypothesis="primary mechanism", line=1,
        )
        o.hypotheses = hypotheses
        o.review_result = {"hypothesis": "primary mechanism"}
        if hypotheses is not None:
            o.review_result["hypotheses"] = hypotheses
        if review_extra:
            o.review_result.update(review_extra)
        return o

    def test_multiplicity_exported(self):
        from core.audit.findings_export import build_graded_finding
        outcome = self._outcome_for_export(hypotheses=[
            {"mechanism": "primary mechanism", "confidence": "high"},
            {"mechanism": "second mechanism", "confidence": "medium"},
            {"mechanism": "third mechanism", "confidence": "refuted"},
        ])
        finding = build_graded_finding(outcome)
        mult = finding["hypothesis_multiplicity"]
        assert mult["count"] == 3
        assert mult["mechanisms"][1] == {
            "mechanism": "second mechanism", "confidence": "medium",
        }
        assert mult["mechanisms"][2]["confidence"] == "refuted"

    def test_no_array_no_multiplicity(self):
        from core.audit.findings_export import build_graded_finding
        outcome = self._outcome_for_export(hypotheses=None)
        finding = build_graded_finding(outcome)
        assert "hypothesis_multiplicity" not in finding

    def test_secondary_confirmations_exported(self):
        from core.audit.findings_export import build_graded_finding
        outcome = self._outcome_for_export(review_extra={
            "secondary_confirmations": [
                {"mechanism": "second mechanism",
                 "evidence_tool": "semgrep:rule-x",
                 "confidence": "medium"},
            ],
        })
        finding = build_graded_finding(outcome)
        assert finding["secondary_confirmations"][0]["evidence_tool"] == (
            "semgrep:rule-x"
        )

    def test_multiplicity_falls_back_to_review_result(self):
        from core.audit.findings_export import build_graded_finding
        outcome = self._outcome_for_export(hypotheses=None)
        outcome.review_result["hypotheses"] = [
            {"mechanism": "from review result", "confidence": "medium"},
        ]
        finding = build_graded_finding(outcome)
        assert finding["hypothesis_multiplicity"]["count"] == 1

    def test_mechanisms_capped_at_eight(self):
        from core.audit.findings_export import build_graded_finding
        outcome = self._outcome_for_export(hypotheses=[
            {"mechanism": f"mechanism {n}", "confidence": "medium"}
            for n in range(12)
        ])
        finding = build_graded_finding(outcome)
        mult = finding["hypothesis_multiplicity"]
        assert mult["count"] == 12
        assert len(mult["mechanisms"]) == 8
