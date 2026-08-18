"""Tests for Bayesian multi-channel aggregation at the promote decision.

No real tools or LLM calls — the tool chain is stubbed; the shipped
packages.hypothesis_validation.posterior machinery runs for real."""

from __future__ import annotations

from types import SimpleNamespace


def _outcome(status="suspicious", function="agg_fn"):
    from core.audit.orchestrator import ReviewOutcome
    hypothesis = "double free of ctx on the error path"
    o = ReviewOutcome(
        file="a.c", function=function, status=status,
        body="needs corroboration", hypothesis=hypothesis, line=3,
    )
    o.review_result = {"hypothesis": hypothesis}
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


class TestAggregateChannelConfirmations:
    def test_two_distinct_channels_cross_threshold(self):
        from core.audit.orchestrator import (
            _aggregate_channel_confirmations,
        )
        channels, mean = _aggregate_channel_confirmations(
            ["coccinelle:det-a", "smt:check-det"],
        )
        assert channels == ["coccinelle", "smt"]
        assert abs(mean - 0.75) < 1e-9

    def test_single_channel_below_threshold(self):
        from core.audit.orchestrator import (
            _aggregate_channel_confirmations,
        )
        channels, _mean = _aggregate_channel_confirmations(
            ["coccinelle:det-a"],
        )
        assert channels == []

    def test_same_engine_receipts_are_correlated_not_independent(self):
        from core.audit.orchestrator import (
            _aggregate_channel_confirmations,
        )
        channels, _mean = _aggregate_channel_confirmations(
            ["coccinelle:det-a", "coccinelle:det-b", "coccinelle:det-c"],
        )
        assert channels == []

    def test_three_channels(self):
        from core.audit.orchestrator import (
            _aggregate_channel_confirmations,
        )
        channels, mean = _aggregate_channel_confirmations(
            ["coccinelle:det-a", "smt:check-det", "semgrep:det-x"],
        )
        assert channels == ["coccinelle", "semgrep", "smt"]
        assert abs(mean - 0.8) < 1e-9

    def test_empty_input(self):
        from core.audit.orchestrator import (
            _aggregate_channel_confirmations,
        )
        assert _aggregate_channel_confirmations([]) == ([], 0.0)


class TestPromoteSuspiciousAggregation:
    def _patch_environment(self, monkeypatch, confirmations):
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: [{"type": "coccinelle", "config": {}}],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: list(confirmations),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: SimpleNamespace(hits=[]),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "void agg_fn(void) { }",
        )
        # All chain confirmations in these tests are detection-role.
        monkeypatch.setattr(
            "core.audit.orchestrator._is_detection_only",
            lambda tool_id: True,
        )

    def test_two_detection_channels_promote(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(
            monkeypatch, ["coccinelle:det-a", "smt:check-det"],
        )
        outcome = _outcome()
        result = _result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        promoted = result.outcomes[0]
        assert promoted.status == "finding"
        assert promoted.evidence_tool == "coccinelle:det-a+smt:check-det"
        assert result.aggregation_promoted == 1
        assert result.sweep_promoted == 1
        assert result.findings == 1
        assert result.suspicious == 0
        agg = promoted.review_result["aggregated_promotion"]
        assert agg["channels"] == ["coccinelle", "smt"]
        assert agg["posterior_mean"] == 0.75
        assert agg["receipts"] == ["coccinelle:det-a", "smt:check-det"]
        tc = result.tier_counters["adapter_aggregation"]
        assert tc.confirmed == 1

    def test_single_detection_channel_still_blocked(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(monkeypatch, ["coccinelle:det-a"])
        outcome = _outcome()
        result = _result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        assert result.outcomes[0].status == "suspicious"
        assert result.aggregation_promoted == 0
        tc = result.tier_counters["adapter_aggregation"]
        assert tc.inconclusive == 1
        assert tc.confirmed == 0

    def test_same_engine_detection_receipts_blocked(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(
            monkeypatch, ["coccinelle:det-a", "coccinelle:det-b"],
        )
        outcome = _outcome()
        result = _result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        assert result.outcomes[0].status == "suspicious"
        assert result.aggregation_promoted == 0

    def test_high_precision_receipt_unaffected(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(
            monkeypatch, ["semgrep:precise-rule", "coccinelle:det-a"],
        )
        # semgrep receipt is high-precision; coccinelle is detection.
        monkeypatch.setattr(
            "core.audit.orchestrator._is_detection_only",
            lambda tool_id: tool_id.startswith("coccinelle:"),
        )
        outcome = _outcome()
        result = _result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        promoted = result.outcomes[0]
        assert promoted.status == "finding"
        assert promoted.evidence_tool == "semgrep:precise-rule"
        assert result.aggregation_promoted == 0
        assert "aggregated_promotion" not in promoted.review_result


class TestSweepValidateAggregation:
    def _patch_environment(self, monkeypatch, confirmations):
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: [{"type": "coccinelle", "config": {}}],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: list(confirmations),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: SimpleNamespace(hits=[]),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._is_detection_only",
            lambda tool_id: True,
        )

    def test_aggregated_channels_stamp_evidence(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            _make_tier_counters,
            _sweep_validate,
        )

        self._patch_environment(
            monkeypatch, ["coccinelle:det-a", "smt:check-det"],
        )
        outcome = _outcome(status="finding")
        tier_counters = _make_tier_counters()

        validated = _sweep_validate(
            outcome, _config(tmp_path),
            tier_counters=tier_counters,
            source_override="void agg_fn(void) { }",
        )

        assert validated.evidence_tool == "coccinelle:det-a+smt:check-det"
        agg = validated.review_result["aggregated_promotion"]
        assert agg["channels"] == ["coccinelle", "smt"]
        assert tier_counters["adapter_aggregation"].confirmed == 1

    def test_single_channel_not_stamped(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import (
            _make_tier_counters,
            _sweep_validate,
        )

        self._patch_environment(monkeypatch, ["coccinelle:det-a"])
        outcome = _outcome(status="finding")
        tier_counters = _make_tier_counters()

        validated = _sweep_validate(
            outcome, _config(tmp_path),
            tier_counters=tier_counters,
            source_override="void agg_fn(void) { }",
        )

        assert validated.evidence_tool != "coccinelle:det-a"
        assert tier_counters["adapter_aggregation"].inconclusive == 1
