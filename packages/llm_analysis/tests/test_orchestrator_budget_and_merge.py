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

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.llm.model_data import MODEL_COSTS  # noqa: E402
from core.run.finding_status import get_status  # noqa: E402
from packages.llm_analysis.orchestrator import (  # noqa: E402
    CostTracker,
    _cap_findings,
    _cc_fallback_role_resolution,
    _classify_absent_consensus,
    _merge_results,
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
        assert cc["consensus_models"] == ["kept"]
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
