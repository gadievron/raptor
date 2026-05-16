"""Tests for run_multi_model() — the substrate dispatch loop.

Uses test-only fake adapters and reviewers; no real LLM calls.
"""

import threading
from dataclasses import dataclass
from typing import Any, Dict

import pytest

from core.llm.multi_model import (
    MultiModelResult,
    run_multi_model,
)


# ---------------------------------------------------------------------------
# Test fixtures: minimal fake handles, adapters, reviewers, gates
# ---------------------------------------------------------------------------


@dataclass
class FakeModel:
    """Satisfies ModelHandle protocol."""
    model_name: str


class IdentityAdapter:
    """Trivial adapter: items are dicts with 'id' field. Merge concatenates
    and dedupes by id (later models override earlier on conflict).
    Correlate returns count of contributing models per id."""

    def item_id(self, item: Dict[str, Any]) -> str:
        if not item.get("id"):
            raise ValueError(f"item missing id: {item}")
        return item["id"]

    def merge(self, per_model_results):
        by_id: Dict[str, Dict] = {}
        for model_name, results in per_model_results.items():
            for r in results:
                by_id[self.item_id(r)] = {**r, "from_model": model_name}
        return list(by_id.values())

    def correlate(self, merged_items, per_model_results):
        per_id_count: Dict[str, int] = {}
        for results in per_model_results.values():
            for r in results:
                per_id_count[self.item_id(r)] = per_id_count.get(self.item_id(r), 0) + 1
        return {"contributors": per_id_count}


class AnnotatingReviewer:
    name = "annotator"
    cutoff_ratio = 1.0

    def __init__(self, label: str = "reviewed"):
        self._label = label

    def review(self, items):
        return [{**item, "annotated_by": self._label} for item in items]


class HighSeverityOnlyReviewer:
    """ConditionalReviewer: only inspects items where severity == 'high'."""
    name = "high_only"
    cutoff_ratio = 1.0

    def should_review(self, item):
        return item.get("severity") == "high"

    def review(self, items):
        return [{**item, "high_reviewed": True} for item in items]


class StaticAggregator:
    cutoff_ratio = 1.0

    def __init__(self, payload):
        self._payload = payload

    def aggregate(self, merged_items, correlation):
        return self._payload


class FixedCostGate:
    """Returns a fixed budget_ratio."""
    def __init__(self, ratio: float):
        self._ratio = ratio

    def budget_ratio(self) -> float:
        return self._ratio


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_empty_models_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            run_multi_model(
                task=lambda m: [], models=[], adapter=IdentityAdapter(),
            )

    def test_duplicate_model_name_raises(self):
        with pytest.raises(ValueError, match="duplicate model_name"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("a"), FakeModel("a")],
                adapter=IdentityAdapter(),
            )

    def test_multiple_duplicates_listed(self):
        with pytest.raises(ValueError, match=r"\['a', 'b'\]"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("a"), FakeModel("b"), FakeModel("a"), FakeModel("b")],
                adapter=IdentityAdapter(),
            )

    def test_unique_model_names_ok(self):
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("a"), FakeModel("b")],
            adapter=IdentityAdapter(),
        )
        assert isinstance(result, MultiModelResult)

    def test_non_callable_task_raises(self):
        with pytest.raises(TypeError, match="callable"):
            run_multi_model(
                task="not a function",  # type: ignore[arg-type]
                models=[FakeModel("a")],
                adapter=IdentityAdapter(),
            )

    def test_invalid_adapter_raises(self):
        class NotAnAdapter:
            pass

        with pytest.raises(TypeError, match="ItemAdapter"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("a")],
                adapter=NotAnAdapter(),  # type: ignore[arg-type]
            )

    def test_none_adapter_raises(self):
        with pytest.raises(TypeError, match="ItemAdapter"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("a")],
                adapter=None,  # type: ignore[arg-type]
            )

    def test_invalid_model_handle_raises(self):
        class NotAHandle:
            pass  # missing model_name

        with pytest.raises(TypeError, match=r"models\[1\] does not implement"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("a"), NotAHandle()],  # type: ignore[list-item]
                adapter=IdentityAdapter(),
            )

    def test_model_handle_with_non_string_name_raises(self):
        @dataclass
        class BadModel:
            model_name: int = 42  # type: ignore[assignment]

        with pytest.raises(TypeError, match="str-typed model_name"):
            run_multi_model(
                task=lambda m: [],
                models=[BadModel()],  # type: ignore[list-item]
                adapter=IdentityAdapter(),
            )

    def test_models_as_generator_works(self):
        # If we didn't materialize, the generator would be exhausted by
        # validation and dispatch would see nothing.
        def gen():
            yield FakeModel("a")
            yield FakeModel("b")

        result = run_multi_model(
            task=lambda m: [{"id": m.model_name}],
            models=gen(),  # type: ignore[arg-type]
            adapter=IdentityAdapter(),
        )
        assert {item["id"] for item in result.items} == {"a", "b"}

    def test_reviewers_none_treated_as_empty(self):
        # Defensive: consumer code might pass None where () was expected.
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=None,  # type: ignore[arg-type]
        )
        assert len(result.items) == 1

    def test_non_dict_task_results_treated_as_failure(self):
        def task(m):
            return ["string", "instead", "of", "dicts"]

        result = run_multi_model(
            task=task,
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
        )
        assert result.failed_models == ["m"]
        assert result.items == []

    def test_partial_non_dict_results_treated_as_failure(self):
        # Even one non-dict item disqualifies the model — strict contract.
        def task(m):
            return [{"id": "ok"}, "oops"]

        result = run_multi_model(
            task=task,
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
        )
        assert result.failed_models == ["m"]

    def test_empty_model_name_raises(self):
        with pytest.raises(ValueError, match="model_name must be non-empty"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("")],
                adapter=IdentityAdapter(),
            )

    def test_adapter_returning_non_string_id_raises(self):
        class IntIdAdapter(IdentityAdapter):
            def item_id(self, item):
                return 42  # type: ignore[return-value]

        with pytest.raises(TypeError, match="expected non-empty str"):
            run_multi_model(
                task=lambda m: [{"id": "x"}],
                models=[FakeModel("m")],
                adapter=IntIdAdapter(),
            )

    def test_adapter_returning_empty_id_raises(self):
        class EmptyIdAdapter(IdentityAdapter):
            def item_id(self, item):
                return ""

        with pytest.raises(TypeError, match="expected non-empty str"):
            run_multi_model(
                task=lambda m: [{"id": "x"}],
                models=[FakeModel("m")],
                adapter=EmptyIdAdapter(),
            )


# ---------------------------------------------------------------------------
# Dispatch and merge
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_runs_task_for_each_model(self):
        seen = []
        lock = threading.Lock()

        def task(model):
            with lock:
                seen.append(model.model_name)
            return [{"id": model.model_name}]

        result = run_multi_model(
            task=task,
            models=[FakeModel("m1"), FakeModel("m2"), FakeModel("m3")],
            adapter=IdentityAdapter(),
        )
        assert sorted(seen) == ["m1", "m2", "m3"]
        assert sorted(item["id"] for item in result.items) == ["m1", "m2", "m3"]

    def test_per_model_raw_keyed_by_name(self):
        result = run_multi_model(
            task=lambda m: [{"id": f"i-{m.model_name}"}],
            models=[FakeModel("a"), FakeModel("b")],
            adapter=IdentityAdapter(),
        )
        assert set(result.per_model_raw.keys()) == {"a", "b"}

    def test_failed_models_when_task_raises(self):
        def task(model):
            if model.model_name == "broken":
                raise RuntimeError("boom")
            return [{"id": "ok"}]

        result = run_multi_model(
            task=task,
            models=[FakeModel("good"), FakeModel("broken")],
            adapter=IdentityAdapter(),
        )
        assert result.failed_models == ["broken"]
        assert result.per_model_raw["broken"] == []
        assert any(item["id"] == "ok" for item in result.items)

    def test_failed_when_only_errors_returned(self):
        def task(model):
            return [{"error": "all bad"}, {"error": "still bad"}]

        result = run_multi_model(
            task=task,
            models=[FakeModel("only-errors")],
            adapter=IdentityAdapter(),
        )
        assert "only-errors" in result.failed_models

    def test_empty_result_not_failure(self):
        result = run_multi_model(
            task=lambda m: [],
            models=[FakeModel("nothing")],
            adapter=IdentityAdapter(),
        )
        assert result.failed_models == []
        assert result.items == []

    def test_non_list_return_treated_as_failure(self):
        def task(model):
            return "not a list"  # type: ignore[return-value]

        result = run_multi_model(
            task=task,
            models=[FakeModel("weird")],
            adapter=IdentityAdapter(),
        )
        assert result.failed_models == ["weird"]


# ---------------------------------------------------------------------------
# Error filtering before adapter
# ---------------------------------------------------------------------------


class TestErrorFiltering:
    def test_error_entries_not_in_merged(self):
        def task(model):
            return [{"id": "good"}, {"error": "filter me"}]

        result = run_multi_model(
            task=task,
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
        )
        ids = [item["id"] for item in result.items]
        assert ids == ["good"]

    def test_error_entries_kept_in_per_model_raw(self):
        def task(model):
            return [{"id": "good"}, {"error": "kept here"}]

        result = run_multi_model(
            task=task,
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
        )
        # Raw output preserves the error for debugging
        raw = result.per_model_raw["m"]
        assert any("error" in r for r in raw)


# ---------------------------------------------------------------------------
# Reviewers
# ---------------------------------------------------------------------------


class TestReviewers:
    def test_reviewer_annotates_items(self):
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[AnnotatingReviewer()],
        )
        assert result.items[0]["annotated_by"] == "reviewed"

    def test_reviewers_run_in_registration_order(self):
        r1 = AnnotatingReviewer(label="first")
        r2 = AnnotatingReviewer(label="second")
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[r1, r2],
        )
        # Second reviewer overwrites first because both set annotated_by
        assert result.items[0]["annotated_by"] == "second"

    def test_conditional_reviewer_filters(self):
        def task(m):
            return [
                {"id": "low-1", "severity": "low"},
                {"id": "high-1", "severity": "high"},
                {"id": "low-2", "severity": "low"},
            ]
        result = run_multi_model(
            task=task,
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[HighSeverityOnlyReviewer()],
        )
        by_id = {item["id"]: item for item in result.items}
        assert by_id["high-1"].get("high_reviewed") is True
        assert "high_reviewed" not in by_id["low-1"]
        assert "high_reviewed" not in by_id["low-2"]

    def test_conditional_reviewer_no_applicable_items(self):
        # If no items match should_review, reviewer is a no-op
        def task(m):
            return [{"id": "low", "severity": "low"}]
        result = run_multi_model(
            task=task,
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[HighSeverityOnlyReviewer()],
        )
        assert "high_reviewed" not in result.items[0]

    def test_reviewer_omitting_item_keeps_prior(self):
        class PartialReviewer:
            name = "partial"
            cutoff_ratio = 1.0

            def review(self, items):
                # Only return the first item, omit the rest
                return [{**items[0], "saw_me": True}] if items else []

        def task(m):
            return [{"id": "a"}, {"id": "b"}]

        result = run_multi_model(
            task=task,
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[PartialReviewer()],
        )
        by_id = {item["id"]: item for item in result.items}
        assert by_id["a"].get("saw_me") is True
        assert "saw_me" not in by_id["b"]
        # Original order preserved
        assert [item["id"] for item in result.items] == ["a", "b"]

    def test_reviewer_unknown_id_ignored(self):
        class GhostReviewer:
            name = "ghost"
            cutoff_ratio = 1.0

            def review(self, items):
                # Try to inject a finding that wasn't in the input
                return [{"id": "ghost-id", "ghost": True}]

        result = run_multi_model(
            task=lambda m: [{"id": "real"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[GhostReviewer()],
        )
        ids = [item["id"] for item in result.items]
        assert ids == ["real"]
        assert "ghost-id" not in ids


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


class TestAggregator:
    def test_aggregator_runs(self):
        agg = StaticAggregator({"summary": "all good"})
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            aggregator=agg,
        )
        assert result.aggregation == {"summary": "all good"}

    def test_no_aggregator_means_none(self):
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
        )
        assert result.aggregation is None

    def test_aggregator_returning_none_normalized_to_empty_dict(self):
        agg = StaticAggregator(None)
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            aggregator=agg,
        )
        assert result.aggregation == {}


# ---------------------------------------------------------------------------
# Cost gating
# ---------------------------------------------------------------------------


class TestCostGating:
    def test_no_gate_means_all_phases_run(self):
        agg = StaticAggregator({"ran": True})
        rev = AnnotatingReviewer()
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[rev],
            aggregator=agg,
            cost_gate=None,
        )
        assert result.aggregation == {"ran": True}
        assert result.items[0].get("annotated_by") == "reviewed"

    def test_reviewer_skipped_when_over_budget(self):
        rev = AnnotatingReviewer()
        rev.cutoff_ratio = 0.8  # type: ignore[misc]
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[rev],
            cost_gate=FixedCostGate(0.9),
        )
        # Reviewer skipped — annotation absent
        assert "annotated_by" not in result.items[0]

    def test_reviewer_runs_when_under_budget(self):
        rev = AnnotatingReviewer()
        rev.cutoff_ratio = 0.8  # type: ignore[misc]
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[rev],
            cost_gate=FixedCostGate(0.5),
        )
        assert result.items[0]["annotated_by"] == "reviewed"

    def test_aggregator_skipped_when_over_budget(self):
        agg = StaticAggregator({"ran": True})
        agg.cutoff_ratio = 0.8  # type: ignore[misc]
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            aggregator=agg,
            cost_gate=FixedCostGate(0.95),
        )
        assert result.aggregation is None  # not even attempted

    def test_cutoff_at_1_disables_gating(self):
        # cutoff_ratio >= 1.0 means "never skip" even with high spend
        rev = AnnotatingReviewer()
        rev.cutoff_ratio = 1.0  # type: ignore[misc]
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[rev],
            cost_gate=FixedCostGate(0.99),
        )
        assert result.items[0]["annotated_by"] == "reviewed"


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------


class TestProtocolValidation:
    """All protocol-typed args must validate at entry."""

    def test_invalid_reviewer_raises(self):
        class NotAReviewer:
            pass  # missing name, cutoff_ratio, review

        with pytest.raises(TypeError, match=r"reviewers\[0\] does not implement"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("m")],
                adapter=IdentityAdapter(),
                reviewers=[NotAReviewer()],  # type: ignore[list-item]
            )

    def test_invalid_aggregator_raises(self):
        class NotAnAggregator:
            pass

        with pytest.raises(TypeError, match="Aggregator"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("m")],
                adapter=IdentityAdapter(),
                aggregator=NotAnAggregator(),  # type: ignore[arg-type]
            )

    def test_invalid_cost_gate_raises(self):
        class NotAGate:
            pass

        with pytest.raises(TypeError, match="CostGate"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("m")],
                adapter=IdentityAdapter(),
                cost_gate=NotAGate(),  # type: ignore[arg-type]
            )


class TestReviewerErrorHandling:
    """Reviewer exceptions and bad return types don't kill the run."""

    def test_reviewer_exception_caught(self):
        class BrokenReviewer:
            name = "broken"
            cutoff_ratio = 1.0

            def review(self, items):
                raise RuntimeError("model timed out")

        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[BrokenReviewer()],
        )
        # Run completed; reviewer contributed no annotations
        assert len(result.items) == 1
        assert "broken_annotated" not in result.items[0]

    def test_reviewer_returns_dict_caught(self):
        class WrongReturnReviewer:
            name = "wrongtype"
            cutoff_ratio = 1.0

            def review(self, items):
                # Returns a dict instead of a list — protocol violation
                return {"oops": True}

        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[WrongReturnReviewer()],
        )
        # Run completed; original items unchanged
        assert len(result.items) == 1

    def test_one_broken_reviewer_doesnt_kill_others(self):
        class BrokenReviewer:
            name = "broken"
            cutoff_ratio = 1.0

            def review(self, items):
                raise ValueError("nope")

        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[BrokenReviewer(), AnnotatingReviewer()],
        )
        # Second reviewer's annotations still applied
        assert result.items[0]["annotated_by"] == "reviewed"

    def test_conditional_reviewer_should_review_exception_caught(self):
        class BrokenConditional:
            name = "bad_filter"
            cutoff_ratio = 1.0

            def should_review(self, item):
                raise RuntimeError("filter explosion")

            def review(self, items):
                return items

        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[BrokenConditional()],
        )
        assert len(result.items) == 1


class TestCostGateErrorHandling:
    """Buggy cost gate doesn't kill the run."""

    def test_gate_exception_disables_gating(self):
        class BrokenGate:
            def budget_ratio(self):
                raise RuntimeError("gate is dead")

        rev = AnnotatingReviewer()
        rev.cutoff_ratio = 0.1  # type: ignore[misc] - would normally skip
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[rev],
            cost_gate=BrokenGate(),
        )
        # Gate failed → treat as no-gate → reviewer ran
        assert result.items[0]["annotated_by"] == "reviewed"

    def test_gate_failure_does_not_pollute_external_object(self):
        # Regression: previously the substrate stamped a sentinel on the
        # gate, leaking state across runs. Verify no attribute is added.
        class BrokenGate:
            def budget_ratio(self):
                raise RuntimeError("dead")

        gate = BrokenGate()
        run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[AnnotatingReviewer()],
            cost_gate=gate,
        )
        # Gate object attributes unchanged after run
        attrs = {k for k in dir(gate) if not k.startswith("__")}
        assert attrs == {"budget_ratio"}, f"unexpected attrs: {attrs}"

    def test_gate_returning_non_numeric_disables_gating(self):
        # Same defensive pattern as YY (select_primary). budget_ratio is
        # documented as float; runtime_checkable doesn't enforce. A buggy
        # gate returning "0.5" would crash `ratio >= cutoff_ratio`
        # outside the try/except. Validate the return type instead.
        class StringRatioGate:
            def budget_ratio(self):
                return "0.5"  # type: ignore[return-value]

        rev = AnnotatingReviewer()
        rev.cutoff_ratio = 0.1  # type: ignore[misc]
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[rev],
            cost_gate=StringRatioGate(),
        )
        # Gate's bad return → gating disabled → reviewer ran
        assert result.items[0]["annotated_by"] == "reviewed"

    def test_gate_returning_bool_disables_gating(self):
        # bool is technically int — but almost certainly a schema error
        class BoolRatioGate:
            def budget_ratio(self):
                return True  # type: ignore[return-value]

        rev = AnnotatingReviewer()
        rev.cutoff_ratio = 0.1  # type: ignore[misc]
        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[rev],
            cost_gate=BoolRatioGate(),
        )
        assert result.items[0]["annotated_by"] == "reviewed"

    def test_gate_recovers_in_subsequent_run(self):
        # If the gate is fixed between runs, the new run gets fresh state.
        # (Verifies the disabled flag is per-run, not stamped on the gate.)
        @dataclass
        class FlakyGate:
            should_fail: bool = True

            def budget_ratio(self):
                if self.should_fail:
                    raise RuntimeError("first run dies")
                return 0.0  # plenty of budget

        gate = FlakyGate(should_fail=True)
        rev = AnnotatingReviewer()
        rev.cutoff_ratio = 0.1  # type: ignore[misc]

        # Run 1: gate broken, gating disabled, reviewer runs
        run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[rev],
            cost_gate=gate,
        )
        # Fix the gate
        gate.should_fail = False
        # Run 2: gate works, returns 0.0, reviewer runs (under cutoff)
        result2 = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[rev],
            cost_gate=gate,
        )
        # Reviewer ran in run 2 — state didn't leak from run 1
        assert result2.items[0]["annotated_by"] == "reviewed"


class TestConditionalReviewerScope:
    """ConditionalReviewer can only modify items it was applicable to."""

    def test_cannot_modify_items_outside_applicable_set(self):
        class SneakyReviewer:
            name = "sneaky"
            cutoff_ratio = 1.0

            def should_review(self, item):
                return item.get("severity") == "high"

            def review(self, items):
                # items contains only the high-severity item; substrate
                # passed [{id: "high-1", severity: "high"}]. The reviewer
                # tries to also modify "low-1" which it shouldn't have access to.
                annotated = [{**i, "sneaky": True} for i in items]
                return annotated + [{"id": "low-1", "sneaky": True}]

        result = run_multi_model(
            task=lambda m: [
                {"id": "high-1", "severity": "high"},
                {"id": "low-1", "severity": "low"},
            ],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            reviewers=[SneakyReviewer()],
        )
        by_id = {i["id"]: i for i in result.items}
        # The high-severity item was annotated normally
        assert by_id["high-1"].get("sneaky") is True
        # The low-severity item was NOT modified, even though the
        # reviewer's return tried to do it.
        assert "sneaky" not in by_id["low-1"]


class TestAggregatorReturnValidation:
    def test_non_dict_aggregator_return_treated_as_empty(self):
        class WrongTypeAggregator:
            cutoff_ratio = 1.0

            def aggregate(self, items, correlation):
                return ["this", "is", "wrong"]  # type: ignore[return-value]

        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            aggregator=WrongTypeAggregator(),
        )
        assert result.aggregation == {}


class TestCutoffRatioValidation:
    def test_string_cutoff_ratio_raises(self):
        class BadReviewer:
            name = "bad"
            cutoff_ratio = "0.8"  # string, not float
            def review(self, items): return items

        with pytest.raises(TypeError, match="cutoff_ratio must be"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("m")],
                adapter=IdentityAdapter(),
                reviewers=[BadReviewer()],
            )

    def test_bool_cutoff_ratio_raises(self):
        # bool is technically a subclass of int but it's almost certainly
        # a programming error if it shows up here.
        class BadAggregator:
            cutoff_ratio = True
            def aggregate(self, items, correlation): return {}

        with pytest.raises(TypeError, match="cutoff_ratio must be"):
            run_multi_model(
                task=lambda m: [],
                models=[FakeModel("m")],
                adapter=IdentityAdapter(),
                aggregator=BadAggregator(),
            )


class TestDeterminism:
    """Substrate must give adapters a stable iteration order regardless
    of which model finishes first."""

    def test_per_model_raw_sorted_alphabetically(self):
        # Slow models finish later, but per_model_raw should be sorted by name
        import time

        def task(m):
            # Reverse alphabetical = first-completed isn't last alphabetically
            if m.model_name == "alpha":
                time.sleep(0.05)
            return [{"id": f"i-{m.model_name}"}]

        result = run_multi_model(
            task=task,
            models=[FakeModel("alpha"), FakeModel("beta"), FakeModel("gamma")],
            adapter=IdentityAdapter(),
        )
        assert list(result.per_model_raw.keys()) == ["alpha", "beta", "gamma"]

    def test_failed_models_sorted(self):
        def task(m):
            if m.model_name in ("zeta", "alpha"):
                raise RuntimeError("nope")
            return []

        result = run_multi_model(
            task=task,
            models=[FakeModel("zeta"), FakeModel("alpha"), FakeModel("middle")],
            adapter=IdentityAdapter(),
        )
        assert result.failed_models == ["alpha", "zeta"]


class TestAggregatorErrorHandling:
    """Aggregator exceptions must be caught and produce {} per the contract."""

    def test_aggregator_exception_caught(self):
        class BrokenAggregator:
            cutoff_ratio = 1.0

            def aggregate(self, items, correlation):
                raise RuntimeError("model timed out")

        result = run_multi_model(
            task=lambda m: [{"id": "x"}],
            models=[FakeModel("m")],
            adapter=IdentityAdapter(),
            aggregator=BrokenAggregator(),
        )
        # Documented tri-state: errored → {}
        assert result.aggregation == {}
        # Substrate didn't crash; rest of result is intact
        assert len(result.items) == 1


class TestAdapterUniqueIdsCheck:
    """If adapter.merge() returns duplicate ids, substrate raises."""

    def test_duplicate_ids_from_merge_raises(self):
        class BuggyAdapter(IdentityAdapter):
            def merge(self, per_model_results):
                # Intentionally return two items with the same id
                return [{"id": "dup"}, {"id": "dup", "different": True}]

        with pytest.raises(ValueError, match="duplicate item_id"):
            run_multi_model(
                task=lambda m: [{"id": "anything"}],
                models=[FakeModel("m")],
                adapter=BuggyAdapter(),
            )


class TestAdapterReturnTypeValidation:
    """Substrate validates adapter.merge() and .correlate() return types."""

    def test_merge_returning_dict_raises(self):
        class BadAdapter(IdentityAdapter):
            def merge(self, per_model_results):
                return {"oops": "should be list"}  # type: ignore[return-value]

        with pytest.raises(TypeError, match="merge.*must return a list"):
            run_multi_model(
                task=lambda m: [{"id": "x"}],
                models=[FakeModel("m")],
                adapter=BadAdapter(),
            )

    def test_merge_returning_none_raises(self):
        class BadAdapter(IdentityAdapter):
            def merge(self, per_model_results):
                return None  # type: ignore[return-value]

        with pytest.raises(TypeError, match="merge.*must return a list"):
            run_multi_model(
                task=lambda m: [{"id": "x"}],
                models=[FakeModel("m")],
                adapter=BadAdapter(),
            )

    def test_correlate_returning_list_raises(self):
        class BadAdapter(IdentityAdapter):
            def correlate(self, merged_items, per_model_results):
                return ["not", "a", "dict"]  # type: ignore[return-value]

        with pytest.raises(TypeError, match="correlate.*must return a dict"):
            run_multi_model(
                task=lambda m: [{"id": "x"}],
                models=[FakeModel("m")],
                adapter=BadAdapter(),
            )


class TestEndToEnd:
    def test_full_pipeline(self):
        """All phases: dispatch → merge → correlate → review → aggregate."""

        def task(model):
            return [
                {"id": "f1", "severity": "high", "value": model.model_name},
                {"id": "f2", "severity": "low", "value": model.model_name},
            ]

        result = run_multi_model(
            task=task,
            models=[FakeModel("alpha"), FakeModel("beta")],
            adapter=IdentityAdapter(),
            reviewers=[AnnotatingReviewer(), HighSeverityOnlyReviewer()],
            aggregator=StaticAggregator({"summary": "ok"}),
        )

        assert result.failed_models == []
        assert result.aggregation == {"summary": "ok"}
        assert result.correlation["contributors"] == {"f1": 2, "f2": 2}
        by_id = {item["id"]: item for item in result.items}
        assert by_id["f1"]["annotated_by"] == "reviewed"
        assert by_id["f1"]["high_reviewed"] is True
        assert by_id["f2"]["annotated_by"] == "reviewed"
        assert "high_reviewed" not in by_id["f2"]

    def test_n_equals_one(self):
        # Single-model run must work gracefully (substrate name is
        # multi-model but consumers will pass through it for N=1 too).
        result = run_multi_model(
            task=lambda m: [{"id": "single"}],
            models=[FakeModel("only")],
            adapter=IdentityAdapter(),
        )
        assert result.items == [{"id": "single", "from_model": "only"}]
        assert result.failed_models == []
