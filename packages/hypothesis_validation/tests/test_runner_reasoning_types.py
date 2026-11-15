"""Evaluation reasoning remains text when model fields have JSON type drift."""
from packages.hypothesis_validation.adapters.base import ToolEvidence
from packages.hypothesis_validation.hypothesis import Hypothesis
from packages.hypothesis_validation.runner import validate
from packages.hypothesis_validation.tests.test_runner import FakeAdapter, FakeLLM


def test_runner_rejects_nontext_reasoning_without_changing_verdict(tmp_path):
    for raw in (["bad"], {"bad": "value"}, 7, True, None, "", "owned explanation"):
        evidence = ToolEvidence(
            tool="owned", rule="owned rule", success=True,
            matches=[{"file": "owned.c", "line": 1}], summary="owned tool summary",
        )
        adapter = FakeAdapter("owned", evidence=evidence)
        client = FakeLLM([
            {"tool": "owned", "rule": "owned rule"},
            {"verdict": "confirmed", "reasoning": raw},
        ])
        result = validate(Hypothesis(claim="owned claim", target=tmp_path), [adapter], client)
        assert len(adapter.run_calls) == 1
        assert len(client.calls) == 2
        assert result.verdict == "confirmed"
        assert isinstance(result.reasoning, str), raw
        assert result.reasoning == (raw if isinstance(raw, str) and raw else evidence.summary)
        assert result.to_dict()["reasoning"] == result.reasoning
