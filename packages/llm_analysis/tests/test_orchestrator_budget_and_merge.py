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
    _panel_summary_parts,
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


class TestMergeContradictionFloor:

    def test_abstained_tp_never_demotes_exploitable(self):
        # Response validation nulls a malformed is_true_positive —
        # an abstention, not a "false positive" verdict. Pre-fix the
        # floor's truthiness check read the None as not-a-true-positive
        # and flipped a voted is_exploitable=True to False at the final
        # merge, dropping the exploit artifact with it.
        prep = _prep_report([{"finding_id": "f1", "rule_id": "r"}])
        cc = [{"finding_id": "f1", "is_true_positive": None,
               "is_exploitable": True, "exploitability_score": 0.9,
               "exploit_code": "poc"}]
        merged = _merge_results(prep, cc)
        f = merged["results"][0]
        assert f["is_exploitable"] is True
        assert f["exploitable"] is True
        assert f["has_exploit"] is True
        assert merged["exploitable"] == 1

    def test_explicit_false_tp_still_demotes(self):
        # Two-direction: the floor still enforces the invariant on an
        # EXPLICIT contradiction (is_true_positive=False + exploitable).
        prep = _prep_report([{"finding_id": "f1", "rule_id": "r"}])
        cc = [{"finding_id": "f1", "is_true_positive": False,
               "is_exploitable": True, "exploitability_score": 0.9,
               "exploit_code": "poc"}]
        merged = _merge_results(prep, cc)
        f = merged["results"][0]
        assert f["is_exploitable"] is False
        assert f["exploitable"] is False
        assert f["has_exploit"] is False
        assert "exploit_code" not in f


class TestMergeAbstainedExploitability:

    def test_abstained_exploitability_merges_as_none(self):
        # read_verdict at the merge: a schema-nulled OR missing
        # is_exploitable is an abstention. It must land on the report
        # record as None (no verdict), never be fabricated into an
        # explicit False, and never count toward the exploitable
        # headline.
        prep = _prep_report([{"finding_id": "f1", "rule_id": "r"},
                             {"finding_id": "f2", "rule_id": "r"}])
        cc = [{"finding_id": "f1", "is_true_positive": True,
               "is_exploitable": None},
              {"finding_id": "f2", "is_true_positive": True}]
        merged = _merge_results(prep, cc)
        assert [f["is_exploitable"] for f in merged["results"]] == [None, None]
        assert [f["exploitable"] for f in merged["results"]] == [None, None]
        assert merged["exploitable"] == 0
        assert all(f["has_exploit"] is False for f in merged["results"])

    def test_explicit_negative_exploitability_stays_false(self):
        # Two-direction: an explicit False is a verdict and is
        # preserved as one.
        prep = _prep_report([{"finding_id": "f1", "rule_id": "r"}])
        cc = [{"finding_id": "f1", "is_true_positive": True,
               "is_exploitable": False}]
        merged = _merge_results(prep, cc)
        assert merged["results"][0]["is_exploitable"] is False


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


class TestPanelSummaryParts:
    """The agreed/disputed counts must partition panels that ran —
    all-abstain panels resolve to "no-verdict" and the printed line
    silently undercounted them."""

    def test_no_verdict_panels_are_counted(self):
        assert _panel_summary_parts(2, 1, 3) == [
            "2 agreed", "1 disputed", "3 no-verdict",
        ]

    def test_zero_counts_are_omitted(self):
        assert _panel_summary_parts(2, 0, 0) == ["2 agreed"]
        assert _panel_summary_parts(0, 0, 1) == ["1 no-verdict"]
        assert _panel_summary_parts(0, 0, 0) == []

    def test_panel_verdict_panels_are_counted(self):
        # Panels that voted on an abstained primary (consensus and
        # judge both stamp "panel-verdict") join the printed line.
        assert _panel_summary_parts(1, 0, 0, 2) == [
            "1 agreed", "2 panel-verdict",
        ]

    def test_junk_primary_snapshot_is_an_abstention(self):
        # The pre-judge/pre-retry snapshots feed the scorecard
        # producers: a junk shape bool()-coerced at snapshot time
        # became a phantom primary vote that could break a genuine
        # judge tie and mint a fabricated "correct" JUDGE_REVIEW
        # event. Tri-state read: junk snapshots as abstention.
        from packages.llm_analysis.orchestrator import _snapshot_verdicts
        snap = _snapshot_verdicts({
            "f1": {"is_exploitable": "yes"},
            "f2": {"is_exploitable": True},
            "f3": {"is_exploitable": None},
            "f4": {"is_exploitable": False},
            "f5": {"is_exploitable": True, "error": "boom"},
        })
        assert snap["f1"] is None
        assert snap["f2"] is True
        assert snap["f3"] is None
        assert snap["f4"] is False
        assert "f5" not in snap

    def test_count_panel_stamps_counts_every_stage_outcome(self):
        # The summary counters for BOTH stages come from this one
        # counter — including the panel-verdict bucket for panels
        # that voted on an abstained primary. Junk rows (non-dict,
        # unknown stamp, absent stamp) count nowhere.
        from packages.llm_analysis.orchestrator import _count_panel_stamps
        rows = [
            {"consensus": "agreed"},
            {"consensus": "disputed"},
            {"consensus": "no-verdict"},
            {"consensus": "panel-verdict"},
            {"consensus": "panel-verdict", "judge": "agreed"},
            {"judge": "panel-verdict"},
            {"consensus": "bogus"},
            {},
            "not-a-dict",
        ]
        assert _count_panel_stamps(rows, "consensus") == {
            "agreed": 1, "disputed": 1,
            "no-verdict": 1, "panel-verdict": 2,
        }
        assert _count_panel_stamps(rows, "judge") == {
            "agreed": 1, "disputed": 0,
            "no-verdict": 0, "panel-verdict": 1,
        }
