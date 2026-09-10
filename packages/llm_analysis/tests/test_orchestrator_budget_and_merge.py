"""Orchestrator budget estimation, fallback shape, and merge statuses.

* ``CostTracker.estimate_cost`` must resolve model ids through the
  canonical chain (dated snapshots, Bedrock forms) instead of a direct
  table lookup that silently falls to the flat default, and must
  estimate CC phases at the observed CC rate.
* ``_cc_fallback_role_resolution`` collapses the analysis-model list
  so the CC fallback dispatches once per finding, not once per failed
  external model.
* ``_classify_absent_consensus`` distinguishes budget-skip from
  all-errored even when every call RAISED (no spend booked).
* ``_merge_results`` stamps failed-analysis findings with the
  canonical ``error`` field (status derives ``error``, not
  ``skipped``), and ``_cap_findings`` stamps the dropped tail with
  ``skipped_over_budget`` at skip time.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.llm.model_data import MODEL_COSTS  # noqa: E402
from core.run.finding_status import get_status  # noqa: E402
from packages.llm_analysis.finding_adapter import FindingAdapter  # noqa: E402
from packages.llm_analysis.orchestrator import (  # noqa: E402
    CostTracker,
    _cap_findings,
    _cc_fallback_role_resolution,
    _classify_absent_consensus,
    _merge_results,
    _per_model_failure_summary,
    _select_primary_dispatch_result,
)
from packages.llm_analysis.tasks import AnalysisTask  # noqa: E402


class TestEstimateCost:

    def test_dated_snapshot_resolves_real_rates(self):
        base = next(iter(MODEL_COSTS))
        dated = f"{base}-20991231"
        tracker = CostTracker(0)
        assert tracker.estimate_cost(10, model_name=dated) == (
            tracker.estimate_cost(10, model_name=base)
        )

    def test_unknown_model_falls_to_default(self):
        tracker = CostTracker(0)
        assert tracker.estimate_cost(10, model_name="no-such-model") == 0.3

    def test_cc_phase_estimated_at_cc_rate(self):
        tracker = CostTracker(0)
        assert tracker.estimate_cost(10, is_cc=True) == 2.0

    def test_should_skip_phase_honours_is_cc(self):
        # $1 budget: 10 CC calls (~$2) must gate; the same 10 calls
        # under the $0.03 default (~$0.30) would sail through.
        tracker = CostTracker(max_cost=1.0)
        assert tracker.should_skip_phase(10, "", 0.7, "test", is_cc=True)
        assert not tracker.should_skip_phase(10, "", 0.7, "test")

    def test_heterogeneous_panel_sums_each_models_estimate(
        self,
        monkeypatch,
    ):
        rates = {
            "cheap": {"input": 0.001, "output": 0.002},
            "expensive": {"input": 0.01, "output": 0.02},
        }
        monkeypatch.setattr(
            "core.llm.model_data.resolve_model_costs",
            lambda name: rates.get(name),
        )
        tracker = CostTracker(max_cost=0.8)

        estimate = tracker.estimate_model_panel_cost(
            10,
            ["cheap", "expensive"],
        )
        assert estimate == pytest.approx(0.33)
        skip, _reason = tracker.check_phase_budget(
            10,
            "",
            0.70,
            "mixed-panel",
            model_names=["cheap", "expensive"],
        )

        assert skip is False
        # The old max-rate multiplication estimated 20 expensive calls
        # ($0.60) and incorrectly crossed the $0.56 phase cap.
        assert tracker.estimate_cost(
            20,
            model_name="expensive",
        ) > 0.8 * 0.70

    def test_authoritative_failed_spend_drives_soft_gate_and_report(self):
        provider_spend = [0.8]
        tracker = CostTracker(max_cost=1.0)
        tracker.bind_authoritative_spend(
            lambda: provider_spend[0],
            provider_spend_getter=lambda: provider_spend[0],
        )

        assert tracker.total_cost == 0.8
        assert tracker.fraction_used == 0.8
        assert tracker.should_skip_phase(
            0, "unknown-model", 0.7, "consensus",
        )
        summary = tracker.get_summary()
        assert summary["total_cost"] == 0.8
        assert summary["accounted_result_cost"] == 0.0
        assert summary["authoritative_provider_spend"] == 0.8
        assert summary["unattributed_provider_spend"] == 0.8
        assert summary["budget_remaining"] == 0.2

    def test_budget_remaining_distinguishes_unbounded_from_empty(self):
        unbounded = CostTracker(max_cost=0.0).get_summary()
        assert unbounded["budget_limited"] is False
        assert unbounded["budget_remaining"] is None

        exhausted = CostTracker(max_cost=1.0)
        exhausted.add_cost("m", 1.25)
        summary = exhausted.get_summary()
        assert summary["budget_limited"] is True
        assert summary["budget_remaining"] == 0.0


class TestCcFallbackRoleResolution:

    def test_collapses_analysis_models(self):
        class _M:
            def __init__(self, name):
                self.model_name = name

        original = {
            "analysis_models": [_M("pro"), _M("flash")],
            "analysis_model": _M("pro"),
            "consensus_models": ["kept"],
        }
        cc = _cc_fallback_role_resolution(original)
        # One CC dispatch per finding: get_models resolves to no
        # named model, which the dispatcher maps to a single None
        # (CC) work item per finding.
        assert AnalysisTask().get_models(cc) == []
        assert cc["consensus_models"] == []
        assert cc["code_model"] is None
        assert cc["judge_models"] == []
        assert cc["aggregate_models"] == []
        assert cc["fallback_models"] == []
        # Original untouched.
        assert len(original["analysis_models"]) == 2


class TestClassifyAbsentConsensus:

    def test_no_records_no_spend_is_budget_skip(self):
        assert _classify_absent_consensus([], 0.0) == (True, False)

    def test_records_without_spend_is_all_errored(self):
        # Raised errors never book cost — the records alone prove
        # calls were attempted.
        records = [{"finding_id": "f1", "error": "bad api key"}]
        assert _classify_absent_consensus(records, 0.0) == (False, True)

    def test_spend_without_records_is_all_errored(self):
        assert _classify_absent_consensus([], 0.02) == (False, True)

    def test_budget_record_is_budget_skip_even_with_spend(self):
        records = [{
            "finding_id": "f1",
            "error": "LLM budget exceeded",
            "error_type": "budget",
            "status": "skipped_over_budget",
        }]
        assert _classify_absent_consensus(
            records, 0.25,
        ) == (True, False)


def _prep_report(results):
    return {"mode": "prep_only", "results": results}


class TestMergeResultsStatuses:

    def test_errored_dispatch_gets_error_field_and_status(self):
        prep = _prep_report([{"finding_id": "f1", "rule_id": "r"}])
        cc = [{"finding_id": "f1", "error": "timeout after 300s",
               "error_type": "timeout"}]
        merged = _merge_results(prep, cc)
        f = merged["results"][0]
        assert f["error"] == "timeout after 300s"
        assert f["error_type"] == "timeout"
        assert f["cc_error"] == "timeout after 300s"
        assert get_status(f) == "error"

    def test_not_dispatched_gets_explicit_skip(self):
        prep = _prep_report([{"finding_id": "f1", "rule_id": "r"}])
        merged = _merge_results(prep, [])
        f = merged["results"][0]
        assert f["status"] == "skipped"
        assert f["skip_reason"] == "not_dispatched"
        assert f["cc_error"] == "not dispatched"

    def test_producer_stamped_skip_preserved(self):
        prep = _prep_report([
            {"finding_id": "f1", "rule_id": "r",
             "status": "skipped_over_budget",
             "skip_reason": "max_findings cap"},
        ])
        merged = _merge_results(prep, [])
        f = merged["results"][0]
        assert f["status"] == "skipped_over_budget"
        # No generic cc_error noise over the specific producer stamp.
        assert "cc_error" not in f

    def test_budget_dispatch_record_merges_as_skip_not_error(self):
        prep = _prep_report([{"finding_id": "f1", "rule_id": "r"}])
        reason = (
            "analysis dispatch stopped: LLM budget exceeded at $1.00"
        )
        cc = [{
            "finding_id": "f1",
            "error": reason,
            "error_type": "budget",
            "status": "skipped_over_budget",
            "skip_reason": reason,
        }]
        merged = _merge_results(prep, cc)
        finding = merged["results"][0]
        assert finding["status"] == "skipped_over_budget"
        assert finding["skip_reason"] == reason
        assert "error" not in finding
        assert "cc_error" not in finding

    def test_status_only_budget_skip_is_not_counted_as_analyzed(self):
        prep = _prep_report([{"finding_id": "f1", "rule_id": "r"}])
        cc = [{
            "finding_id": "f1",
            "status": "skipped_over_budget",
            "skip_reason": "phase budget pre-check",
        }]

        merged = _merge_results(prep, cc)

        assert merged["analyzed"] == 0
        assert merged["results"][0]["status"] == "skipped_over_budget"
        assert "verification_tier" not in merged["results"][0]

    def test_successful_merge_not_stamped_error(self):
        # Two-direction: a healthy result keeps flowing as analysed.
        prep = _prep_report([{"finding_id": "f1", "rule_id": "r"}])
        cc = [{"finding_id": "f1", "is_true_positive": True,
               "is_exploitable": False, "exploitability_score": 0.1}]
        merged = _merge_results(prep, cc)
        f = merged["results"][0]
        assert "error" not in f
        assert get_status(f) == "analysed"


class TestCapFindings:

    def test_dropped_tail_stamped(self):
        findings = [{"finding_id": f"f{i}"} for i in range(5)]
        kept = _cap_findings(findings, 3)
        assert len(kept) == 3
        assert all("status" not in f for f in kept)
        assert findings[3]["status"] == "skipped_over_budget"
        assert findings[4]["skip_reason"] == "max_findings cap"

    def test_no_cap_no_stamp(self):
        findings = [{"finding_id": "f0"}]
        assert _cap_findings(findings, 0) is findings
        assert "status" not in findings[0]


class TestFailureSummary:

    def test_budget_skips_are_not_provider_failures(self):
        results = [
            {
                "finding_id": "f1",
                "error": "LLM budget exceeded",
                "error_type": "budget",
                "status": "skipped_over_budget",
                "analysed_by": "model-a",
            },
            {
                "finding_id": "f2",
                "error": "provider outage",
                "error_type": "network",
                "analysed_by": "model-a",
            },
        ]
        assert _per_model_failure_summary(results) == {
            "model-a": {
                "count": 1,
                "first_error": "provider outage",
            },
        }

    def test_budget_record_wins_mixed_all_error_panel(self):
        provider_error = {
            "finding_id": "f1",
            "error": "provider outage",
            "error_type": "network",
        }
        budget_skip = {
            "finding_id": "f1",
            "error": "LLM budget exceeded",
            "error_type": "budget",
            "status": "skipped_over_budget",
            "skip_reason": "analysis stopped at the run cost cap",
        }
        selected = _select_primary_dispatch_result(
            [provider_error, budget_skip],
            FindingAdapter(),
        )
        assert selected == budget_skip
