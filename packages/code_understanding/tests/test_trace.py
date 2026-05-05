"""Tests for trace() orchestrator.

Uses mock dispatch_fn — real LLM dispatch is PR2b's responsibility.
"""

from dataclasses import dataclass

import pytest

from packages.code_understanding import trace


@dataclass
class FakeModel:
    model_name: str


# ---------------------------------------------------------------------------
# Basic dispatch
# ---------------------------------------------------------------------------


class TestTraceDispatch:
    def test_calls_dispatch_for_each_model(self):
        seen = []

        def dispatch(model, traces):
            seen.append(model.model_name)
            return [{"trace_id": t["trace_id"], "verdict": "reachable"}
                    for t in traces]

        trace(
            traces=[{"trace_id": "EP-001"}],
            repo_path="/code",
            models=[FakeModel("a"), FakeModel("b")],
            dispatch_fn=dispatch,
        )

        assert sorted(seen) == ["a", "b"]

    def test_empty_traces_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            trace(
                traces=[],
                repo_path="/code",
                models=[FakeModel("a")],
                dispatch_fn=lambda m, t: [],
            )

    def test_non_callable_dispatch_raises(self):
        with pytest.raises(TypeError, match="callable"):
            trace(
                traces=[{"trace_id": "EP-001"}],
                repo_path="/code",
                models=[FakeModel("a")],
                dispatch_fn=None,  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# Verdict merging (prefer-positive default)
# ---------------------------------------------------------------------------


class TestTraceMerge:
    def test_reachable_wins_over_not_reachable(self):
        verdicts = {
            "claude": [{"trace_id": "EP-001", "verdict": "not_reachable"}],
            "gemini": [{"trace_id": "EP-001", "verdict": "reachable"}],
        }

        def dispatch(model, traces):
            return verdicts[model.model_name]

        result = trace(
            traces=[{"trace_id": "EP-001"}],
            repo_path="/code",
            models=[FakeModel("claude"), FakeModel("gemini")],
            dispatch_fn=dispatch,
        )

        assert result.items[0]["verdict"] == "reachable"

    def test_disagreement_marked_as_disputed(self):
        verdicts = {
            "claude": [{"trace_id": "EP-001", "verdict": "reachable"}],
            "gemini": [{"trace_id": "EP-001", "verdict": "not_reachable"}],
        }

        def dispatch(model, traces):
            return verdicts[model.model_name]

        result = trace(
            traces=[{"trace_id": "EP-001"}],
            repo_path="/code",
            models=[FakeModel("claude"), FakeModel("gemini")],
            dispatch_fn=dispatch,
        )

        assert result.correlation["confidence_signals"]["EP-001"] == "disputed"

    def test_unanimous_reachable_is_high(self):
        def dispatch(model, traces):
            return [{"trace_id": t["trace_id"], "verdict": "reachable"}
                    for t in traces]

        result = trace(
            traces=[{"trace_id": "EP-001"}, {"trace_id": "EP-002"}],
            repo_path="/code",
            models=[FakeModel("a"), FakeModel("b"), FakeModel("c")],
            dispatch_fn=dispatch,
        )

        for trace_id in ("EP-001", "EP-002"):
            assert result.correlation["confidence_signals"][trace_id] == "high"

    def test_all_uncertain_is_high_inconclusive(self):
        def dispatch(model, traces):
            return [{"trace_id": t["trace_id"], "verdict": "uncertain"}
                    for t in traces]

        result = trace(
            traces=[{"trace_id": "EP-001"}],
            repo_path="/code",
            models=[FakeModel("a"), FakeModel("b")],
            dispatch_fn=dispatch,
        )

        assert result.correlation["confidence_signals"]["EP-001"] == "high-inconclusive"


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


class TestTraceFailures:
    def test_failed_model_doesnt_kill_run(self):
        def dispatch(model, traces):
            if model.model_name == "broken":
                raise RuntimeError("nope")
            return [{"trace_id": t["trace_id"], "verdict": "reachable"}
                    for t in traces]

        result = trace(
            traces=[{"trace_id": "EP-001"}],
            repo_path="/code",
            models=[FakeModel("good"), FakeModel("broken")],
            dispatch_fn=dispatch,
        )

        assert result.failed_models == ["broken"]
        assert result.items[0]["verdict"] == "reachable"

    def test_dispatch_partially_returning_errors(self):
        def dispatch(model, traces):
            return [{"error": "model timed out"} for _ in traces]

        result = trace(
            traces=[{"trace_id": "EP-001"}, {"trace_id": "EP-002"}],
            repo_path="/code",
            models=[FakeModel("a")],
            dispatch_fn=dispatch,
        )

        # All of model a's verdicts were errors → failed
        assert result.failed_models == ["a"]
        # Nothing made it through to merged items
        assert result.items == []


# ---------------------------------------------------------------------------
# Aggregator integration
# ---------------------------------------------------------------------------


class TestTraceAggregator:
    def test_aggregator_sees_disputed_traces(self):
        captured = {}

        class DisputedCapturing:
            cutoff_ratio = 1.0

            def aggregate(self, items, correlation):
                disputed = [
                    tid for tid, sig in correlation["confidence_signals"].items()
                    if sig == "disputed"
                ]
                captured["disputed"] = disputed
                return {"disputed_count": len(disputed)}

        verdicts = {
            "claude": [
                {"trace_id": "EP-001", "verdict": "reachable"},
                {"trace_id": "EP-002", "verdict": "reachable"},  # unanimous
            ],
            "gemini": [
                {"trace_id": "EP-001", "verdict": "not_reachable"},  # disputed
                {"trace_id": "EP-002", "verdict": "reachable"},
            ],
        }

        def dispatch(model, traces):
            return verdicts[model.model_name]

        result = trace(
            traces=[{"trace_id": "EP-001"}, {"trace_id": "EP-002"}],
            repo_path="/code",
            models=[FakeModel("claude"), FakeModel("gemini")],
            dispatch_fn=dispatch,
            aggregator=DisputedCapturing(),
        )

        assert captured["disputed"] == ["EP-001"]
        assert result.aggregation == {"disputed_count": 1}
