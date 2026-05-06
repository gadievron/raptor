"""Tests for the generic dispatch framework (dispatch.py + tasks.py)."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# packages/llm_analysis/tests/test_dispatch.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.llm_analysis.dispatch import (
    DispatchTask, DispatchResult, dispatch_task, _format_elapsed,
    _classify_error,
)
from packages.llm_analysis.tasks import (
    AggregationTask, AnalysisTask, ExploitTask, PatchTask, ConsensusTask,
    GroupAnalysisTask, JudgeTask, RetryTask,
)
from packages.llm_analysis.orchestrator import CostTracker


def _make_finding(finding_id, rule_id="sqli", file_path="db.py", start_line=42):
    return {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": start_line + 3,
        "level": "error",
        "message": f"Potential {rule_id}",
        "code": "bad()",
        "surrounding_context": "context",
    }


def _make_dispatch_result(exploitable=True, score=0.85):
    return DispatchResult(
        result={
            "is_true_positive": True,
            "is_exploitable": exploitable,
            "exploitability_score": score,
            "reasoning": "test reasoning",
        },
        cost=0.10, tokens=500, model="test-model", duration=5.0,
    )


class TestDispatchTask:
    def test_base_class_raises_on_build_prompt(self):
        task = DispatchTask()
        with pytest.raises(NotImplementedError):
            task.build_prompt({})

    def test_select_items_default_returns_all(self):
        task = DispatchTask()
        items = [{"a": 1}, {"b": 2}]
        assert task.select_items(items, {}) == items

    def test_get_models_from_role_resolution(self):
        task = DispatchTask()
        task.model_role = "analysis"
        model = MagicMock()
        resolution = {"analysis_model": model}
        assert task.get_models(resolution) == [model]

    def test_get_models_returns_none_list_when_missing(self):
        task = DispatchTask()
        task.model_role = "analysis"
        assert task.get_models({}) == []

    def test_process_result_adds_metadata(self):
        task = DispatchTask()
        item = {"finding_id": "f-001"}
        dr = _make_dispatch_result()
        processed = task.process_result(item, dr)
        assert processed["cost_usd"] == 0.10
        assert processed["analysed_by"] == "test-model"
        assert processed["duration_seconds"] == 5.0

    def test_finalize_default_noop(self):
        task = DispatchTask()
        results = [{"a": 1}]
        assert task.finalize(results, {}) is results


class TestAnalysisTask:
    def test_builds_prompt(self):
        task = AnalysisTask()
        finding = _make_finding("f-001")
        prompt = task.build_prompt(finding)
        assert "sqli" in prompt
        assert "db.py" in prompt

    def test_has_schema(self):
        task = AnalysisTask()
        schema = task.get_schema(_make_finding("f-001"))
        assert "is_exploitable" in schema

    def test_system_prompt(self):
        task = AnalysisTask()
        assert task.get_system_prompt() is not None


    def test_get_models_returns_analysis_models_list(self):
        task = AnalysisTask()
        m1 = MagicMock()
        m2 = MagicMock()
        resolution = {"analysis_models": [m1, m2]}
        assert task.get_models(resolution) == [m1, m2]

    def test_get_models_fallback_to_singular(self):
        task = AnalysisTask()
        m1 = MagicMock()
        resolution = {"analysis_model": m1}
        assert task.get_models(resolution) == [m1]


class TestSelectPrimaryResult:
    """Coverage of FindingAdapter.select_primary, the substrate-backed
    replacement for the legacy _select_primary_result function.

    PR3 Option A migrated /agentic's selection logic to the multi-model
    substrate. Behaviour is preserved: prefer is_exploitable=True, then
    higher _quality, then higher exploitability_score.

    Substrate's select_primary expects valid (non-error) inputs — error
    filtering is the caller's responsibility (in the orchestrator the
    filter happens upstream of this call).
    """

    def _select(self, results):
        from packages.llm_analysis.finding_adapter import FindingAdapter
        return FindingAdapter().select_primary(results)

    def test_prefers_exploitable(self):
        r1 = {"is_exploitable": False, "exploitability_score": 0.9, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "exploitability_score": 0.5, "analysed_by": "m2"}
        assert self._select([r1, r2])["analysed_by"] == "m2"

    def test_prefers_higher_quality(self):
        r1 = {"is_exploitable": True, "_quality": 0.5, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "_quality": 0.9, "analysed_by": "m2"}
        assert self._select([r1, r2])["analysed_by"] == "m2"

    def test_prefers_higher_score_on_tie(self):
        r1 = {"is_exploitable": True, "_quality": 1.0, "exploitability_score": 0.7, "analysed_by": "m1"}
        r2 = {"is_exploitable": True, "_quality": 1.0, "exploitability_score": 0.9, "analysed_by": "m2"}
        assert self._select([r1, r2])["analysed_by"] == "m2"

    def test_single_result(self):
        r1 = {"is_exploitable": True, "analysed_by": "m1"}
        result = self._select([r1])
        assert result["analysed_by"] == "m1"


class TestExploitTask:
    def test_selects_only_exploitable(self):
        task = ExploitTask()
        findings = [_make_finding("f-001"), _make_finding("f-002")]
        prior = {
            "f-001": {"is_exploitable": True},
            "f-002": {"is_exploitable": False},
        }
        selected = task.select_items(findings, prior)
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "f-001"

    def test_skips_findings_with_existing_exploit(self):
        task = ExploitTask()
        findings = [_make_finding("f-001"), _make_finding("f-002")]
        prior = {
            "f-001": {"is_exploitable": True, "exploit_code": "# already generated"},
            "f-002": {"is_exploitable": True},
        }
        selected = task.select_items(findings, prior)
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "f-002"

    def test_no_schema_freeform(self):
        task = ExploitTask()
        assert task.get_schema(_make_finding("f-001")) is None

    def test_budget_cutoff(self):
        assert ExploitTask.budget_cutoff == 0.85

    def test_finalize_attaches_exploit_code(self):
        task = ExploitTask()
        prior = {"f-001": {"is_exploitable": True}}
        results = [{"finding_id": "f-001", "content": "import requests\n..."}]
        task.finalize(results, prior)
        assert prior["f-001"]["exploit_code"] == "import requests\n..."
        assert prior["f-001"]["has_exploit"] is True

    def test_finalize_skips_errors(self):
        task = ExploitTask()
        prior = {"f-001": {"is_exploitable": True}}
        results = [{"finding_id": "f-001", "error": "timeout"}]
        task.finalize(results, prior)
        assert "exploit_code" not in prior["f-001"]

    def test_finalize_skips_empty_content(self):
        task = ExploitTask()
        prior = {"f-001": {"is_exploitable": True}}
        results = [{"finding_id": "f-001", "content": ""}]
        task.finalize(results, prior)
        assert "exploit_code" not in prior["f-001"]


class TestPatchTask:
    def test_selects_only_exploitable(self):
        task = PatchTask()
        findings = [_make_finding("f-001")]
        prior = {"f-001": {"is_exploitable": False}}
        assert task.select_items(findings, prior) == []

    def test_skips_findings_with_existing_patch(self):
        task = PatchTask()
        findings = [_make_finding("f-001"), _make_finding("f-002")]
        prior = {
            "f-001": {"is_exploitable": True, "patch_code": "# already generated"},
            "f-002": {"is_exploitable": True},
        }
        selected = task.select_items(findings, prior)
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "f-002"

    def test_finalize_attaches_patch_code(self):
        task = PatchTask()
        prior = {"f-001": {"is_exploitable": True}}
        results = [{"finding_id": "f-001", "content": "def safe_query(...):\n..."}]
        task.finalize(results, prior)
        assert prior["f-001"]["patch_code"] == "def safe_query(...):\n..."
        assert prior["f-001"]["has_patch"] is True

    def test_finalize_skips_errors(self):
        task = PatchTask()
        prior = {"f-001": {"is_exploitable": True}}
        results = [{"finding_id": "f-001", "error": "LLM exploded"}]
        task.finalize(results, prior)
        assert "patch_code" not in prior["f-001"]


class TestConsensusTask:
    def test_gets_consensus_models(self):
        task = ConsensusTask()
        m1 = MagicMock()
        m2 = MagicMock()
        resolution = {"consensus_models": [m1, m2]}
        assert task.get_models(resolution) == [m1, m2]

    def test_selects_successfully_analysed(self):
        task = ConsensusTask()
        findings = [_make_finding("f-001"), _make_finding("f-002")]
        prior = {
            "f-001": {"is_exploitable": True},
            "f-002": {"error": "failed"},
        }
        selected = task.select_items(findings, prior)
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "f-001"

    def test_finalize_single_consensus_preserves_primary(self):
        task = ConsensusTask()
        # Consensus says exploitable, primary says not — primary preserved, disputed
        consensus_results = [
            {"finding_id": "f-001", "is_exploitable": True, "analysed_by": "gemini",
             "reasoning": "yes"}
        ]
        prior = {"f-001": {"is_exploitable": False, "finding_id": "f-001"}}
        task.finalize(consensus_results, prior)
        assert prior["f-001"]["is_exploitable"] is False
        assert prior["f-001"]["consensus"] == "disputed"

    def test_finalize_single_consensus_primary_exploitable_preserved(self):
        task = ConsensusTask()
        # Primary says exploitable, consensus says not — primary preserved, disputed
        consensus_results = [
            {"finding_id": "f-001", "is_exploitable": False, "analysed_by": "gemini",
             "reasoning": "no"}
        ]
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize(consensus_results, prior)
        assert prior["f-001"]["is_exploitable"] is True
        assert prior["f-001"]["consensus"] == "disputed"

    def test_finalize_agreed(self):
        task = ConsensusTask()
        consensus_results = [
            {"finding_id": "f-001", "is_exploitable": True, "analysed_by": "gemini",
             "reasoning": "yes"}
        ]
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize(consensus_results, prior)
        assert prior["f-001"]["consensus"] == "agreed"

    def test_finalize_multi_consensus_majority_wins(self):
        task = ConsensusTask()
        # 2 consensus models + primary: 2 exploitable vs 1 not → majority wins
        consensus_results = [
            {"finding_id": "f-001", "is_exploitable": True, "analysed_by": "gemini",
             "reasoning": "yes"},
            {"finding_id": "f-001", "is_exploitable": False, "analysed_by": "mistral",
             "reasoning": "no"},
        ]
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize(consensus_results, prior)
        # 2 of 3 say exploitable → majority = True
        assert prior["f-001"]["is_exploitable"] is True
        assert prior["f-001"]["consensus"] == "disputed"

    def test_finalize_multi_consensus_majority_not_exploitable(self):
        task = ConsensusTask()
        consensus_results = [
            {"finding_id": "f-001", "is_exploitable": False, "analysed_by": "gemini",
             "reasoning": "no"},
            {"finding_id": "f-001", "is_exploitable": False, "analysed_by": "mistral",
             "reasoning": "no"},
        ]
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize(consensus_results, prior)
        # 2 of 3 say not exploitable → majority = False
        assert prior["f-001"]["is_exploitable"] is False
        assert prior["f-001"]["consensus"] == "disputed"

    def test_skips_false_positives(self):
        task = ConsensusTask()
        findings = [_make_finding("f-001"), _make_finding("f-002"), _make_finding("f-003")]
        prior = {
            "f-001": {"is_exploitable": True, "is_true_positive": True},
            "f-002": {"is_exploitable": False, "is_true_positive": False},
            "f-003": {"error": "failed"},
        }
        selected = task.select_items(findings, prior)
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "f-001"


    def test_skips_cross_family_agreed(self):
        task = ConsensusTask()
        findings = [_make_finding("f-001"), _make_finding("f-002")]
        prior = {
            "f-001": {"is_exploitable": True, "cross_family_agreed": True},
            "f-002": {"is_exploitable": True},
        }
        selected = task.select_items(findings, prior)
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "f-002"

    def test_consensus_reasoning_in_output(self):
        task = ConsensusTask()
        consensus_results = [
            {"finding_id": "f-001", "is_exploitable": True, "analysed_by": "gemini",
             "reasoning": "consensus reasoning text"}
        ]
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize(consensus_results, prior)
        analyses = prior["f-001"]["consensus_analyses"]
        assert len(analyses) == 1
        assert analyses[0]["reasoning"] == "consensus reasoning text"


class TestGroupAnalysisTask:
    def test_selects_groups_of_two_plus(self):
        task = GroupAnalysisTask()
        groups = [
            {"group_id": "G-001", "finding_ids": ["f-001", "f-002"]},
            {"group_id": "G-002", "finding_ids": ["f-003"]},
        ]
        selected = task.select_items(groups, {})
        assert len(selected) == 1
        assert selected[0]["group_id"] == "G-001"

    def test_builds_prompt_with_results(self):
        results = {
            "f-001": {"is_exploitable": True, "exploitability_score": 0.9,
                       "reasoning": "injectable"},
            "f-002": {"is_exploitable": False, "reasoning": "parameterised"},
        }
        task = GroupAnalysisTask(results_by_id=results)
        group = {"group_id": "G-001", "criterion": "rule_id",
                 "criterion_value": "sqli", "finding_ids": ["f-001", "f-002"]}
        # Post anti-prompt-injection migration: prior LLM reasoning lands in the
        # user message (untrusted block); task instructions ("root cause", etc.)
        # land in the system message.
        prompt = task.build_prompt(group)
        system = task.get_system_prompt()
        assert "injectable" in prompt
        assert "parameterised" in prompt
        assert "root cause" in system.lower()

    def test_item_id_is_group_id(self):
        task = GroupAnalysisTask()
        assert task.get_item_id({"group_id": "G-001"}) == "G-001"


class TestDispatchTaskIntegration:
    def test_dispatch_with_mock_fn(self):
        """Full dispatch_task with a mock dispatch_fn."""
        findings = [_make_finding("f-001"), _make_finding("f-002")]

        def mock_fn(prompt, schema, system_prompt, temperature, model):
            return _make_dispatch_result(exploitable=True, score=0.9)

        results = dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=mock_fn,
            role_resolution={},  # No models — dispatch_task uses [None]
            prior_results={},
            cost_tracker=CostTracker(0),
            max_parallel=2,
        )

        assert len(results) == 2
        assert all(r.get("is_exploitable") for r in results)
        assert all(r.get("cost_usd") == 0.10 for r in results)
        assert all(r.get("analysed_by") == "test-model" for r in results)

    def test_dispatch_feeds_cost_tracker(self):
        """dispatch_task feeds per-item costs to CostTracker."""
        findings = [_make_finding("f-001"), _make_finding("f-002")]
        ct = CostTracker(max_cost=10.0)

        def mock_fn(prompt, schema, system_prompt, temperature, model):
            return _make_dispatch_result(exploitable=True, score=0.9)

        dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=mock_fn,
            role_resolution={},
            prior_results={},
            cost_tracker=ct,
            max_parallel=2,
        )

        assert ct.total_cost == 0.20  # 2 findings * $0.10 each
        summary = ct.get_summary()
        assert "test-model" in summary["cost_by_model"]

    def test_dispatch_handles_errors(self):
        """dispatch_task handles exceptions gracefully."""
        findings = [_make_finding("f-001")]

        def failing_fn(prompt, schema, system_prompt, temperature, model):
            raise RuntimeError("LLM exploded")

        results = dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=failing_fn,
            role_resolution={},
            prior_results={},
            cost_tracker=CostTracker(0),
            max_parallel=1,
        )

        assert len(results) == 1
        assert "error" in results[0]

    def test_dispatch_auth_abort(self):
        """Auth error aborts remaining dispatches."""
        findings = [_make_finding("f-001"), _make_finding("f-002"), _make_finding("f-003")]

        def auth_fail_fn(prompt, schema, system_prompt, temperature, model):
            raise RuntimeError("Error 401 Unauthorized")

        results = dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=auth_fail_fn,
            role_resolution={},
            prior_results={},
            cost_tracker=CostTracker(0),
            max_parallel=1,
        )

        # All should have errors (dispatched or aborted)
        assert all("error" in r for r in results)

    def test_dispatch_consecutive_failure_abort(self):
        """3 consecutive failures with no successes aborts remaining."""
        findings = [_make_finding(f"f-{i:03d}") for i in range(6)]

        def failing_fn(prompt, schema, system_prompt, temperature, model):
            raise RuntimeError("Structured generation failed")

        results = dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=failing_fn,
            role_resolution={},
            prior_results={},
            cost_tracker=CostTracker(0),
            max_parallel=1,  # Sequential to ensure consecutive
        )

        # Should abort after 3, remaining get aborted error
        assert all("error" in r for r in results)
        assert len(results) == 6  # All accounted for (3 dispatched + 3 aborted)

    def test_dispatch_no_abort_when_some_succeed(self):
        """Failures after successes don't trigger consecutive abort."""
        findings = [_make_finding("f-001"), _make_finding("f-002"),
                    _make_finding("f-003"), _make_finding("f-004")]
        call_count = [0]

        def mixed_fn(prompt, schema, system_prompt, temperature, model):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_dispatch_result()  # First succeeds
            raise RuntimeError("Failed")

        results = dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=mixed_fn,
            role_resolution={},
            prior_results={},
            cost_tracker=CostTracker(0),
            max_parallel=1,
        )

        # All 4 should be dispatched (1 success resets consecutive counter)
        assert len(results) == 4
        successes = [r for r in results if "error" not in r]
        assert len(successes) >= 1

    def test_dispatch_budget_skip(self):
        """Budget pre-check skips the phase."""
        findings = [_make_finding("f-001")]
        ct = CostTracker(max_cost=10.0)
        ct.add_cost("test", 9.0)  # 90% spent

        results = dispatch_task(
            task=ExploitTask(),  # budget_cutoff = 0.85
            items=findings,
            dispatch_fn=lambda *a: _make_dispatch_result(),
            role_resolution={},
            prior_results={"f-001": {"is_exploitable": True}},
            cost_tracker=ct,
            max_parallel=1,
        )

        assert results == []  # Skipped due to budget


class TestRetryTask:
    def test_selects_low_confidence(self):
        task = RetryTask()
        findings = [_make_finding("f-001"), _make_finding("f-002"), _make_finding("f-003")]
        prior = {
            "f-001": {"exploitability_score": 0.5},   # In range
            "f-002": {"exploitability_score": 0.9},   # Too high
            "f-003": {"exploitability_score": 0.1},   # Too low
        }
        selected = task.select_items(findings, prior)
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "f-001"

    def test_selects_boundaries(self):
        task = RetryTask()
        findings = [_make_finding("f-001"), _make_finding("f-002")]
        prior = {
            "f-001": {"exploitability_score": 0.3},   # At LOW boundary
            "f-002": {"exploitability_score": 0.7},   # At HIGH boundary
        }
        selected = task.select_items(findings, prior)
        assert len(selected) == 2

    def test_skips_missing_score(self):
        task = RetryTask()
        findings = [_make_finding("f-001")]
        prior = {"f-001": {"is_exploitable": True}}  # No score
        assert task.select_items(findings, prior) == []

    def test_finalize_decisive_replaces(self):
        task = RetryTask()
        prior = {"f-001": {"exploitability_score": 0.5, "reasoning": "old"}}
        results = [{"finding_id": "f-001", "exploitability_score": 0.9, "reasoning": "new"}]
        task.finalize(results, prior)
        assert prior["f-001"]["reasoning"] == "new"
        assert prior["f-001"]["retried"] is True
        assert "low_confidence" not in prior["f-001"]

    def test_finalize_still_ambiguous_flags(self):
        task = RetryTask()
        prior = {"f-001": {"exploitability_score": 0.5, "reasoning": "old"}}
        results = [{"finding_id": "f-001", "exploitability_score": 0.45, "reasoning": "still unsure"}]
        task.finalize(results, prior)
        assert prior["f-001"]["reasoning"] == "old"  # Original kept
        assert prior["f-001"]["retried"] is True
        assert prior["f-001"]["low_confidence"] is True

    def test_finalize_skips_errors(self):
        task = RetryTask()
        prior = {"f-001": {"exploitability_score": 0.5}}
        results = [{"finding_id": "f-001", "error": "timeout"}]
        task.finalize(results, prior)
        assert "retried" not in prior["f-001"]

    def test_inherits_analysis_prompt(self):
        task = RetryTask()
        finding = _make_finding("f-001")
        prompt = task.build_prompt(finding)
        assert "sqli" in prompt  # Inherited from AnalysisTask

    def test_dispatch_integration(self):
        """RetryTask through dispatch_task with mock dispatch_fn."""
        findings = [_make_finding("f-001"), _make_finding("f-002")]
        prior = {
            "f-001": {"exploitability_score": 0.5},
            "f-002": {"exploitability_score": 0.9},
        }

        def mock_fn(prompt, schema, system_prompt, temperature, model):
            return _make_dispatch_result(exploitable=True, score=0.95)

        results = dispatch_task(
            task=RetryTask(),
            items=findings,
            dispatch_fn=mock_fn,
            role_resolution={},
            prior_results=prior,
            cost_tracker=CostTracker(0),
            max_parallel=2,
        )

        # Only f-001 should be retried (f-002 score too high)
        assert len(results) == 1
        # f-001 should be replaced with decisive result
        assert prior["f-001"]["retried"] is True
        assert prior["f-001"]["exploitability_score"] == 0.95


class TestFormatElapsed:
    def test_seconds(self):
        assert _format_elapsed(45) == "45s"

    def test_minutes(self):
        assert _format_elapsed(100) == "1m 40s"

    def test_hours(self):
        assert _format_elapsed(3700) == "1h 1m"


class TestClassifyError:
    """Test error classification for structured reporting."""

    def test_content_filter(self):
        assert _classify_error("Response blocked by content filter") == "blocked"

    def test_safety_block(self):
        assert _classify_error("Gemini blocked response (finish_reason=safety)") == "blocked"

    def test_refusal(self):
        assert _classify_error("Model refused request: I cannot help with exploits") == "blocked"

    def test_auth_error(self):
        assert _classify_error("401 Unauthorized: invalid API key") == "auth"

    def test_quota_error(self):
        assert _classify_error("insufficient_quota: billing limit reached") == "auth"

    def test_timeout(self):
        assert _classify_error("Request timed out after 120s") == "timeout"

    def test_generic_error(self):
        assert _classify_error("JSON parse failed: unexpected token") == "error"

    def test_empty_string(self):
        assert _classify_error("") == "error"


class TestJudgeTask:
    def test_gets_judge_models(self):
        task = JudgeTask()
        m1 = MagicMock()
        resolution = {"judge_models": [m1]}
        assert task.get_models(resolution) == [m1]

    def test_selects_same_as_consensus(self):
        task = JudgeTask()
        findings = [_make_finding("f-001"), _make_finding("f-002"), _make_finding("f-003")]
        prior = {
            "f-001": {"is_exploitable": True},
            "f-002": {"error": "failed"},
            "f-003": {"is_exploitable": True, "cross_family_agreed": True},
        }
        selected = task.select_items(findings, prior)
        assert len(selected) == 1
        assert selected[0]["finding_id"] == "f-001"

    def test_finalize_single_judge_preserves_primary(self):
        task = JudgeTask()
        judge_results = [
            {"finding_id": "f-001", "is_exploitable": True, "analysed_by": "gpt-5",
             "reasoning": "looks exploitable"}
        ]
        prior = {"f-001": {"is_exploitable": False, "finding_id": "f-001"}}
        task.finalize(judge_results, prior)
        assert prior["f-001"]["is_exploitable"] is False
        assert prior["f-001"]["judge"] == "disputed"

    def test_finalize_single_judge_agreed(self):
        task = JudgeTask()
        judge_results = [
            {"finding_id": "f-001", "is_exploitable": True, "analysed_by": "gpt-5",
             "reasoning": "confirmed"}
        ]
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize(judge_results, prior)
        assert prior["f-001"]["is_exploitable"] is True
        assert prior["f-001"]["judge"] == "agreed"

    def test_finalize_multi_judge_majority(self):
        task = JudgeTask()
        judge_results = [
            {"finding_id": "f-001", "is_exploitable": False, "analysed_by": "gpt-5",
             "reasoning": "no"},
            {"finding_id": "f-001", "is_exploitable": False, "analysed_by": "mistral",
             "reasoning": "no"},
        ]
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize(judge_results, prior)
        assert prior["f-001"]["is_exploitable"] is False
        assert prior["f-001"]["judge"] == "disputed"

    def test_judge_analyses_in_output(self):
        task = JudgeTask()
        judge_results = [
            {"finding_id": "f-001", "is_exploitable": True, "analysed_by": "gpt-5",
             "reasoning": "judge reasoning text"}
        ]
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize(judge_results, prior)
        analyses = prior["f-001"]["judge_analyses"]
        assert len(analyses) == 1
        assert analyses[0]["reasoning"] == "judge reasoning text"
        assert analyses[0]["model"] == "gpt-5"

    def test_budget_cutoff(self):
        assert JudgeTask.budget_cutoff == 0.75

    def test_builds_prompt_includes_primary_reasoning(self):
        results_by_id = {
            "f-001": {
                "is_exploitable": True,
                "ruling": "validated",
                "reasoning": "SQL injection via user input",
            }
        }
        task = JudgeTask(results_by_id=results_by_id)
        finding = _make_finding("f-001")
        prompt = task.build_prompt(finding)
        assert "SQL injection via user input" in prompt
        assert "is_exploitable=True" in prompt


class TestAggregationTask:
    def test_gets_aggregate_models(self):
        task = AggregationTask()
        m1 = MagicMock()
        resolution = {"aggregate_models": [m1]}
        assert task.get_models(resolution) == [m1]

    def test_builds_prompt_from_payload(self):
        task = AggregationTask()
        payload = {
            "models": ["claude-opus-4-6", "gpt-5"],
            "correlation_summary": {"agreed": 1, "disputed": 0},
            "findings": [{
                "finding_id": "f-001",
                "selected_verdict": {"is_exploitable": True},
                "analyses": [
                    {"model": "claude-opus-4-6", "reasoning": "reachable sink"},
                    {"model": "gpt-5", "reasoning": "user input reaches sink"},
                ],
            }],
        }
        prompt = task.build_prompt(payload)
        assert "f-001" in prompt
        assert "claude-opus-4-6" in prompt
        assert task.get_schema(payload)["required"][0] == "summary"

    def test_item_id_is_stable(self):
        task = AggregationTask()
        assert task.get_item_id({}) == "aggregate"

    def test_schema_constrains_verdict_and_confidence(self):
        task = AggregationTask()
        schema = task.get_schema({})
        finding_props = schema["properties"]["highest_confidence_findings"]["items"]["properties"]
        assert finding_props["verdict"]["enum"] == ["exploitable", "not_exploitable", "uncertain"]
        assert finding_props["confidence"]["enum"] == ["high", "medium", "low"]


class TestDropHallucinatedFindingIds:
    def test_drops_unknown_ids(self):
        from packages.llm_analysis.orchestrator import _drop_hallucinated_finding_ids
        aggregation = {
            "highest_confidence_findings": [
                {"finding_id": "real-1", "verdict": "exploitable",
                 "confidence": "high", "reason": "ok"},
                {"finding_id": "ghost", "verdict": "exploitable",
                 "confidence": "high", "reason": "made up"},
            ],
            "disputed_findings": [
                {"finding_id": "real-2", "disagreement": "x", "resolution_needed": "y"},
                {"finding_id": "phantom", "disagreement": "x", "resolution_needed": "y"},
            ],
        }
        results_by_id = {"real-1": {}, "real-2": {}}
        _drop_hallucinated_finding_ids(aggregation, results_by_id)
        assert [f["finding_id"] for f in aggregation["highest_confidence_findings"]] == ["real-1"]
        assert [f["finding_id"] for f in aggregation["disputed_findings"]] == ["real-2"]

    def test_keeps_all_when_all_real(self):
        from packages.llm_analysis.orchestrator import _drop_hallucinated_finding_ids
        aggregation = {
            "highest_confidence_findings": [
                {"finding_id": "a", "verdict": "exploitable",
                 "confidence": "high", "reason": "ok"},
            ],
        }
        _drop_hallucinated_finding_ids(aggregation, {"a": {}})
        assert len(aggregation["highest_confidence_findings"]) == 1

    def test_handles_missing_lists(self):
        from packages.llm_analysis.orchestrator import _drop_hallucinated_finding_ids
        aggregation = {"summary": "ok"}
        _drop_hallucinated_finding_ids(aggregation, {})
        assert aggregation == {"summary": "ok"}

    def test_handles_non_dict_items(self):
        from packages.llm_analysis.orchestrator import _drop_hallucinated_finding_ids
        aggregation = {
            "highest_confidence_findings": [
                "not-a-dict",
                {"finding_id": "real", "verdict": "exploitable",
                 "confidence": "high", "reason": "ok"},
            ],
        }
        _drop_hallucinated_finding_ids(aggregation, {"real": {}})
        assert len(aggregation["highest_confidence_findings"]) == 1
        assert aggregation["highest_confidence_findings"][0]["finding_id"] == "real"


class TestJudgeEdgeCases:
    def test_finalize_no_judge_results_for_finding(self):
        """Findings without judge results should be untouched."""
        task = JudgeTask()
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize([], prior)
        assert "judge" not in prior["f-001"]
        assert prior["f-001"]["is_exploitable"] is True

    def test_finalize_skips_error_results(self):
        task = JudgeTask()
        judge_results = [
            {"finding_id": "f-001", "error": "model failed"}
        ]
        prior = {"f-001": {"is_exploitable": True, "finding_id": "f-001"}}
        task.finalize(judge_results, prior)
        assert "judge" not in prior["f-001"]

    def test_finalize_skips_error_prior(self):
        task = JudgeTask()
        judge_results = [
            {"finding_id": "f-001", "is_exploitable": True, "analysed_by": "gpt-5",
             "reasoning": "yes"}
        ]
        prior = {"f-001": {"error": "analysis failed"}}
        task.finalize(judge_results, prior)
        assert "judge" not in prior["f-001"]

    def test_select_skips_false_positives(self):
        task = JudgeTask()
        findings = [_make_finding("f-001")]
        prior = {"f-001": {"is_exploitable": False, "is_true_positive": False}}
        assert task.select_items(findings, prior) == []

    def test_select_includes_true_positive_default(self):
        """is_true_positive defaults to True when missing."""
        task = JudgeTask()
        findings = [_make_finding("f-001")]
        prior = {"f-001": {"is_exploitable": True}}
        assert len(task.select_items(findings, prior)) == 1


class TestProviderOf:
    def test_claude_maps_to_anthropic(self):
        from core.security.llm_family import provider_of
        assert provider_of("claude-opus-4-6") == "anthropic"

    def test_gemini_maps_to_gemini(self):
        from core.security.llm_family import provider_of
        assert provider_of("gemini-2.5-pro") == "gemini"

    def test_gpt_maps_to_openai(self):
        from core.security.llm_family import provider_of
        assert provider_of("gpt-5.4") == "openai"

    def test_unknown_returns_empty(self):
        from core.security.llm_family import provider_of
        assert provider_of("some-random-model") == ""

    def test_ollama_prefix(self):
        from core.security.llm_family import provider_of
        assert provider_of("ollama/llama-3") == "ollama"


class TestConfigRoleValidation:
    def test_judge_without_analysis_raises(self):
        from core.llm.config import _validate_model_roles, ConfigError
        m = MagicMock()
        m.role = "judge"
        m.model_name = "gpt-5"
        with pytest.raises(ConfigError, match="Judge.*without.*analysis"):
            _validate_model_roles([m])

    def test_judge_with_analysis_ok(self):
        from core.llm.config import _validate_model_roles
        analysis = MagicMock(); analysis.role = "analysis"; analysis.model_name = "gemini"
        judge = MagicMock(); judge.role = "judge"; judge.model_name = "gpt-5"
        _validate_model_roles([analysis, judge])

    def test_aggregate_without_analysis_raises(self):
        from core.llm.config import _validate_model_roles, ConfigError
        m = MagicMock()
        m.role = "aggregate"
        m.model_name = "claude-opus-4-6"
        with pytest.raises(ConfigError, match="Aggregate.*without.*analysis"):
            _validate_model_roles([m])

    def test_multiple_aggregate_models_raises(self):
        from core.llm.config import _validate_model_roles, ConfigError
        analysis = MagicMock(); analysis.role = "analysis"; analysis.model_name = "gpt-5"
        a1 = MagicMock(); a1.role = "aggregate"; a1.model_name = "claude-opus-4-6"
        a2 = MagicMock(); a2.role = "aggregate"; a2.model_name = "gpt-5.4"
        with pytest.raises(ConfigError, match="Multiple models with role 'aggregate'"):
            _validate_model_roles([analysis, a1, a2])

    def test_resolve_roles_includes_judge(self):
        from core.llm.config import resolve_model_roles
        analysis = MagicMock(); analysis.role = "analysis"; analysis.model_name = "gemini"
        judge = MagicMock(); judge.role = "judge"; judge.model_name = "gpt-5"
        result = resolve_model_roles(analysis, [judge])
        assert result["judge_models"] == [judge]
        assert result["analysis_model"] == analysis

    def test_resolve_roles_includes_aggregate(self):
        from core.llm.config import resolve_model_roles
        analysis = MagicMock(); analysis.role = "analysis"; analysis.model_name = "gemini"
        aggregate = MagicMock(); aggregate.role = "aggregate"; aggregate.model_name = "claude-opus-4-6"
        result = resolve_model_roles(analysis, [aggregate])
        assert result["aggregate_models"] == [aggregate]

    def test_multiple_analysis_models_allowed(self):
        from core.llm.config import _validate_model_roles
        m1 = MagicMock(); m1.role = "analysis"; m1.model_name = "gemini"
        m2 = MagicMock(); m2.role = "analysis"; m2.model_name = "gpt-5"
        _validate_model_roles([m1, m2])

    def test_resolve_roles_returns_analysis_models_list(self):
        from core.llm.config import resolve_model_roles
        m1 = MagicMock(); m1.role = "analysis"; m1.model_name = "gemini"
        m2 = MagicMock(); m2.role = "analysis"; m2.model_name = "gpt-5"
        result = resolve_model_roles(m1, [m2])
        assert len(result["analysis_models"]) == 2
        assert result["analysis_model"] == m1


class TestBuildLLMConfigFromFlags:
    def test_no_flags_no_autodetect_returns_none(self):
        from packages.llm_analysis.orchestrator import build_llm_config_from_flags
        assert build_llm_config_from_flags(auto_detect=False) is None

    def test_unknown_model_no_key_returns_none(self):
        from packages.llm_analysis.orchestrator import build_llm_config_from_flags
        result = build_llm_config_from_flags(models=["no-such-model"], auto_detect=False)
        assert result is None

    def test_role_flags_without_primary_returns_none(self):
        from packages.llm_analysis.orchestrator import build_llm_config_from_flags
        result = build_llm_config_from_flags(
            consensus="gpt-5", auto_detect=False,
        )
        assert result is None

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"})
    def test_single_model_flag(self):
        from packages.llm_analysis.orchestrator import build_llm_config_from_flags
        result = build_llm_config_from_flags(
            models=["gemini-2.5-pro"], auto_detect=False,
        )
        assert result is not None
        assert result.primary_model.model_name == "gemini-2.5-pro"

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key", "ANTHROPIC_API_KEY": "test-key-2"})
    def test_model_with_role_flags(self):
        from packages.llm_analysis.orchestrator import build_llm_config_from_flags
        result = build_llm_config_from_flags(
            models=["gemini-2.5-pro"],
            consensus="claude-sonnet-4-6",
            auto_detect=False,
        )
        assert result is not None
        consensus_models = [m for m in result.fallback_models if m.role == "consensus"]
        assert len(consensus_models) == 1
        assert consensus_models[0].model_name == "claude-sonnet-4-6"

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-key", "ANTHROPIC_API_KEY": "test-key-2"})
    def test_model_with_aggregate_flag(self):
        from packages.llm_analysis.orchestrator import build_llm_config_from_flags
        result = build_llm_config_from_flags(
            models=["gpt-5", "claude-opus-4-6"],
            aggregate="claude-opus-4-6",
            auto_detect=False,
        )
        assert result is not None
        aggregate_models = [m for m in result.fallback_models if m.role == "aggregate"]
        assert len(aggregate_models) == 1
        assert aggregate_models[0].model_name == "claude-opus-4-6"

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key", "OPENAI_API_KEY": "test-key-2"})
    def test_multi_model_flags(self):
        from packages.llm_analysis.orchestrator import build_llm_config_from_flags
        result = build_llm_config_from_flags(
            models=["gemini-2.5-pro", "gpt-5"],
            auto_detect=False,
        )
        assert result is not None
        assert result.primary_model.model_name == "gemini-2.5-pro"
        analysis_models = [m for m in result.fallback_models if m.role == "analysis"]
        assert len(analysis_models) == 1
        assert analysis_models[0].model_name == "gpt-5"

    @patch.dict("os.environ", {"GEMINI_API_KEY": "k1", "OPENAI_API_KEY": "k2", "ANTHROPIC_API_KEY": "k3"})
    def test_three_models_skips_consensus(self, capsys):
        from packages.llm_analysis.orchestrator import build_llm_config_from_flags
        result = build_llm_config_from_flags(
            models=["gemini-2.5-pro", "gpt-5", "claude-opus-4-6"],
            consensus="mistral-large-latest",
            auto_detect=False,
        )
        assert result is not None
        consensus_models = [m for m in result.fallback_models if m.role == "consensus"]
        assert len(consensus_models) == 0
        captured = capsys.readouterr()
        assert "skipped" in captured.out.lower()


# -----------------------------------------------------------------------
# SCA integration tests
# -----------------------------------------------------------------------

def _make_sca_finding(
    finding_id,
    *,
    reachability="likely_called",
    in_kev=False,
    fixed_version="9.0.3",
):
    """Create a minimal SCA finding for task selection tests."""
    return {
        "finding_id": finding_id,
        "rule_id": "sca:vulnerable_dependency",
        "file_path": "requirements.txt",
        "start_line": 5,
        "end_line": 5,
        "level": "warning",
        "message": "Vulnerable dependency",
        "code": 'pytest>=7.0.0',
        "surrounding_context": "",
        "sca": {
            "ecosystem": "PyPI",
            "name": "pytest",
            "version": "7.0.0",
            "fixed_version": fixed_version,
            "reachability": reachability,
            "in_kev": in_kev,
            "declared_in": "requirements.txt",
            "advisory": {
                "id": "GHSA-6w46-j5rx-g56g",
                "aliases": ["CVE-2025-71176"],
                "summary": "pytest has vulnerable tmpdir handling",
            },
        },
    }


class TestExploitTaskSCA:
    """ExploitTask selection of SCA findings for reachability PoC."""

    def test_selects_sca_with_likely_called(self):
        task = ExploitTask()
        findings = [_make_sca_finding("sca-001", reachability="likely_called")]
        selected = task.select_items(findings, {})
        assert len(selected) == 1

    def test_selects_sca_with_imported(self):
        task = ExploitTask()
        findings = [_make_sca_finding("sca-001", reachability="imported")]
        selected = task.select_items(findings, {})
        assert len(selected) == 1

    def test_selects_sca_kev_with_non_reachable(self):
        task = ExploitTask()
        findings = [_make_sca_finding("sca-001", reachability="not_evaluated", in_kev=True)]
        selected = task.select_items(findings, {})
        assert len(selected) == 1

    def test_skips_sca_kev_with_not_reachable(self):
        task = ExploitTask()
        findings = [_make_sca_finding("sca-001", reachability="not_reachable", in_kev=True)]
        selected = task.select_items(findings, {})
        assert len(selected) == 0

    def test_skips_sca_without_reachability_or_kev(self):
        task = ExploitTask()
        findings = [_make_sca_finding("sca-001", reachability="not_evaluated", in_kev=False)]
        selected = task.select_items(findings, {})
        assert len(selected) == 0

    def test_skips_sca_with_existing_exploit(self):
        task = ExploitTask()
        findings = [_make_sca_finding("sca-001")]
        prior = {"sca-001": {"exploit_code": "# already"}}
        selected = task.select_items(findings, prior)
        assert len(selected) == 0

    def test_mixes_source_and_sca_findings(self):
        task = ExploitTask()
        findings = [
            _make_finding("src-001"),
            _make_sca_finding("sca-001", reachability="likely_called"),
        ]
        prior = {"src-001": {"is_exploitable": True}}
        selected = task.select_items(findings, prior)
        assert len(selected) == 2


class TestPatchTaskSCA:
    """PatchTask selection of SCA findings for manifest patches."""

    def test_selects_sca_with_fix_version(self):
        task = PatchTask()
        findings = [_make_sca_finding("sca-001", fixed_version="9.0.3")]
        selected = task.select_items(findings, {})
        assert len(selected) == 1

    def test_skips_sca_without_fix_version(self):
        task = PatchTask()
        findings = [_make_sca_finding("sca-001", fixed_version="")]
        selected = task.select_items(findings, {})
        assert len(selected) == 0

    def test_skips_sca_with_existing_patch(self):
        task = PatchTask()
        findings = [_make_sca_finding("sca-001")]
        prior = {"sca-001": {"patch_code": "# already"}}
        selected = task.select_items(findings, prior)
        assert len(selected) == 0

    def test_sca_hygiene_not_selected(self):
        task = PatchTask()
        finding = _make_sca_finding("sca-001")
        finding["rule_id"] = "sca:hygiene:lockfile_missing"
        selected = task.select_items([finding], {})
        assert len(selected) == 0


class TestScaExploitPrompt:
    """SCA-specific exploit prompt builder."""

    def test_builds_sca_prompt(self):
        from packages.llm_analysis.prompts.exploit import (
            build_exploit_prompt_bundle_from_finding,
        )
        finding = _make_sca_finding("sca-001")
        bundle = build_exploit_prompt_bundle_from_finding(finding)
        user_msg = next(m.content for m in bundle.messages if m.role == "user")
        assert "CVE-2025-71176" in user_msg
        assert "pytest" in user_msg

    def test_routes_source_findings_normally(self):
        from packages.llm_analysis.prompts.exploit import (
            build_exploit_prompt_bundle_from_finding,
        )
        finding = _make_finding("src-001")
        bundle = build_exploit_prompt_bundle_from_finding(finding)
        user_msg = next(m.content for m in bundle.messages if m.role == "user")
        assert "sqli" in user_msg


class TestScaPatchPrompt:
    """SCA-specific patch prompt builder."""

    def test_builds_sca_patch_prompt(self):
        from packages.llm_analysis.prompts.patch import (
            build_patch_prompt_bundle_from_finding,
        )
        finding = _make_sca_finding("sca-001")
        bundle = build_patch_prompt_bundle_from_finding(finding)
        user_msg = next(m.content for m in bundle.messages if m.role == "user")
        assert "9.0.3" in user_msg
        assert "pytest" in user_msg

    def test_routes_source_findings_normally(self):
        from packages.llm_analysis.prompts.patch import (
            build_patch_prompt_bundle_from_finding,
        )
        finding = _make_finding("src-001")
        bundle = build_patch_prompt_bundle_from_finding(finding)
        user_msg = next(m.content for m in bundle.messages if m.role == "user")
        assert "sqli" in user_msg or "db.py" in user_msg
