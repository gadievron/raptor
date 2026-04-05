"""Tests for the generic dispatch framework (dispatch.py + tasks.py)."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.llm_analysis.dispatch import (
    DispatchTask, DispatchResult, dispatch_task, _format_elapsed,
    _classify_error,
)
from packages.llm_analysis.tasks import (
    AnalysisTask, ExploitTask, PatchTask, ConsensusTask, GroupAnalysisTask,
    RetryTask,
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

    def test_finalize_one_consensus_either_exploitable_wins(self):
        task = ConsensusTask()
        # Consensus says exploitable, primary says not
        consensus_results = [
            {"finding_id": "f-001", "is_exploitable": True, "analysed_by": "gemini",
             "reasoning": "yes"}
        ]
        prior = {"f-001": {"is_exploitable": False, "finding_id": "f-001"}}
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
        prompt = task.build_prompt(group)
        assert "injectable" in prompt
        assert "parameterised" in prompt
        assert "root cause" in prompt.lower()

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
