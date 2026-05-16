"""Tests for hunt() orchestrator.

Uses mock dispatch_fn — real LLM dispatch is PR2b's responsibility.
"""

from dataclasses import dataclass

import pytest

from packages.code_understanding import hunt


@dataclass
class FakeModel:
    model_name: str


# ---------------------------------------------------------------------------
# Basic dispatch
# ---------------------------------------------------------------------------


class TestHuntDispatch:
    def test_calls_dispatch_for_each_model(self):
        seen = []

        def dispatch(model, pattern, repo_path):
            seen.append((model.model_name, pattern, repo_path))
            return [{"file": "x.c", "line": 1, "function": ""}]

        hunt(
            pattern="strcpy_misuse",
            repo_path="/code",
            models=[FakeModel("a"), FakeModel("b"), FakeModel("c")],
            dispatch_fn=dispatch,
        )

        assert sorted(seen) == [
            ("a", "strcpy_misuse", "/code"),
            ("b", "strcpy_misuse", "/code"),
            ("c", "strcpy_misuse", "/code"),
        ]

    def test_returns_unioned_variants(self):
        per_model_finds = {
            "a": [
                {"file": "src/x.c", "line": 5, "function": "f"},
                {"file": "src/x.c", "line": 9, "function": "g"},
            ],
            "b": [
                {"file": "src/x.c", "line": 5, "function": "f"},
                {"file": "src/y.c", "line": 1, "function": ""},
            ],
        }

        def dispatch(model, pattern, repo_path):
            return per_model_finds[model.model_name]

        result = hunt(
            pattern="any",
            repo_path="/code",
            models=[FakeModel("a"), FakeModel("b")],
            dispatch_fn=dispatch,
        )

        # 3 distinct variants
        ids = sorted(adapter_id(it) for it in result.items)
        assert ids == ["src/x.c:5:f", "src/x.c:9:g", "src/y.c:1"]


def adapter_id(item):
    """Helper to derive id consistently with VariantAdapter."""
    fn = item.get("function", "")
    if fn:
        return f"{item['file']}:{item['line']}:{fn}"
    return f"{item['file']}:{item['line']}"


# ---------------------------------------------------------------------------
# Recall signals
# ---------------------------------------------------------------------------


class TestHuntRecallSignals:
    def test_all_models_recall_when_all_find(self):
        def dispatch(model, pattern, repo_path):
            return [{"file": "src/x.c", "line": 5, "function": "f"}]

        result = hunt(
            pattern="any",
            repo_path="/code",
            models=[FakeModel("a"), FakeModel("b"), FakeModel("c")],
            dispatch_fn=dispatch,
        )

        recall = result.correlation["recall_signals"]
        assert recall["src/x.c:5:f"] == "all_models"

    def test_minority_recall_when_only_one_finds(self):
        def dispatch(model, pattern, repo_path):
            if model.model_name == "a":
                return [{"file": "src/x.c", "line": 5, "function": "f"}]
            return []

        result = hunt(
            pattern="any",
            repo_path="/code",
            models=[FakeModel("a"), FakeModel("b"), FakeModel("c")],
            dispatch_fn=dispatch,
        )

        recall = result.correlation["recall_signals"]
        assert recall["src/x.c:5:f"] == "minority"


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


class TestHuntFailures:
    def test_failed_model_doesnt_kill_run(self):
        def dispatch(model, pattern, repo_path):
            if model.model_name == "broken":
                raise RuntimeError("model fell over")
            return [{"file": "src/x.c", "line": 1, "function": ""}]

        result = hunt(
            pattern="any",
            repo_path="/code",
            models=[FakeModel("good"), FakeModel("broken")],
            dispatch_fn=dispatch,
        )

        assert result.failed_models == ["broken"]
        # Survivor's finds are still in the merged result
        assert any(
            adapter_id(it) == "src/x.c:1" for it in result.items
        )

    def test_dispatch_returning_errors_filtered(self):
        def dispatch(model, pattern, repo_path):
            if model.model_name == "errored":
                return [{"error": "model timed out"}]
            return [{"file": "src/x.c", "line": 1, "function": ""}]

        result = hunt(
            pattern="any",
            repo_path="/code",
            models=[FakeModel("good"), FakeModel("errored")],
            dispatch_fn=dispatch,
        )

        # Substrate filters errors before merge; "errored" is in failed_models
        # because every result it returned was an error
        assert result.failed_models == ["errored"]
        # Real find still surfaces
        ids = [adapter_id(it) for it in result.items]
        assert "src/x.c:1" in ids


class TestHuntInputValidation:
    def test_empty_pattern_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            hunt(
                pattern="",
                repo_path="/code",
                models=[FakeModel("a")],
                dispatch_fn=lambda m, p, r: [],
            )

    def test_whitespace_only_pattern_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            hunt(
                pattern="   ",
                repo_path="/code",
                models=[FakeModel("a")],
                dispatch_fn=lambda m, p, r: [],
            )

    def test_non_callable_dispatch_raises(self):
        with pytest.raises(TypeError, match="callable"):
            hunt(
                pattern="any",
                repo_path="/code",
                models=[FakeModel("a")],
                dispatch_fn="not a function",  # type: ignore[arg-type]
            )

    def test_pattern_stripped_before_dispatch(self):
        # Whitespace-padded patterns are common copy-paste errors.
        # The validation pre-check used `pattern.strip()`; the dispatch
        # call should see the stripped value, not the original.
        seen = []

        def dispatch(model, pattern, repo_path):
            seen.append(pattern)
            return []

        hunt(
            pattern="  strcpy_misuse  ",
            repo_path="/code",
            models=[FakeModel("a")],
            dispatch_fn=dispatch,
        )

        assert seen == ["strcpy_misuse"]


# ---------------------------------------------------------------------------
# Aggregator integration
# ---------------------------------------------------------------------------


class TestHuntAggregator:
    def test_aggregator_runs_with_recall_signals(self):
        captured = {}

        class CapturingAggregator:
            cutoff_ratio = 1.0

            def aggregate(self, items, correlation):
                captured["correlation"] = correlation
                captured["item_count"] = len(items)
                return {"summary": f"{len(items)} variants found"}

        per_model_finds = {
            "a": [{"file": "src/x.c", "line": 5, "function": "f"}],
            "b": [{"file": "src/x.c", "line": 5, "function": "f"}],
        }

        def dispatch(model, pattern, repo_path):
            return per_model_finds[model.model_name]

        result = hunt(
            pattern="any",
            repo_path="/code",
            models=[FakeModel("a"), FakeModel("b")],
            dispatch_fn=dispatch,
            aggregator=CapturingAggregator(),
        )

        assert result.aggregation == {"summary": "1 variants found"}
        assert "recall_signals" in captured["correlation"]
        assert captured["item_count"] == 1
