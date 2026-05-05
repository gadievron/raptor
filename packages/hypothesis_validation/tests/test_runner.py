"""Tests for the HypothesisRunner.

These tests pin down the architectural invariant: verdicts derive from
mechanical tool evidence, not LLM opinion. When the LLM disagrees with
the mechanical truth, the mechanical truth wins.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.hypothesis_validation.adapters.base import (
    ToolAdapter,
    ToolCapability,
    ToolEvidence,
)
from packages.hypothesis_validation.hypothesis import Hypothesis
from packages.hypothesis_validation.runner import (
    _build_evaluate_prompt,
    _build_generate_prompt,
    _build_system_prompt,
    _extract_data,
    validate,
)


# Test doubles ----------------------------------------------------------------

class FakeAdapter(ToolAdapter):
    """A controllable adapter for tests."""

    def __init__(self, name: str, *, available: bool = True,
                 evidence: ToolEvidence = None):
        self._name = name
        self._available = available
        self._evidence = evidence or ToolEvidence(
            tool=name, rule="", success=True, matches=[],
        )
        self.run_calls = []

    @property
    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return self._available

    def describe(self) -> ToolCapability:
        return ToolCapability(
            name=self._name,
            good_for=[f"{self._name} use case"],
            syntax_example=f"{self._name}-rule-example",
        )

    def run(self, rule, target, *, timeout=300, env=None) -> ToolEvidence:
        self.run_calls.append({"rule": rule, "target": target})
        # Return an evidence object that records the rule the runner gave us
        return ToolEvidence(
            tool=self._evidence.tool,
            rule=rule,
            success=self._evidence.success,
            matches=list(self._evidence.matches),
            summary=self._evidence.summary,
            error=self._evidence.error,
        )


class FakeLLM:
    """Minimal LLM client double — returns scripted responses in order."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate_structured(self, prompt, schema, system_prompt=None,
                            task_type=None, **kwargs):
        self.calls.append({
            "prompt": prompt, "schema": schema,
            "system_prompt": system_prompt, "task_type": task_type,
        })
        if not self.responses:
            raise RuntimeError("FakeLLM ran out of scripted responses")
        return self.responses.pop(0)


# Helpers ---------------------------------------------------------------------

class TestPromptBuilders:
    def test_system_prompt_lists_each_adapter(self):
        a = FakeAdapter("aaa")
        b = FakeAdapter("bbb")
        text = _build_system_prompt([a, b])
        assert "## aaa" in text
        assert "## bbb" in text
        assert "aaa-rule-example" in text

    def test_generate_prompt_includes_claim_and_target(self):
        h = Hypothesis(claim="my claim", target=Path("/src/x"))
        text = _build_generate_prompt(h)
        assert "my claim" in text
        assert "/src/x" in text

    def test_generate_prompt_omits_optional_fields_when_empty(self):
        h = Hypothesis(claim="c", target=Path("/x"))
        text = _build_generate_prompt(h)
        assert "Target function:" not in text
        assert "CWE class:" not in text
        assert "Context:" not in text

    def test_generate_prompt_includes_function_when_set(self):
        h = Hypothesis(claim="c", target=Path("/x"), target_function="foo")
        text = _build_generate_prompt(h)
        assert "Target function: foo" in text

    def test_generate_prompt_includes_cwe_when_set(self):
        h = Hypothesis(claim="c", target=Path("/x"), cwe="CWE-129")
        text = _build_generate_prompt(h)
        assert "CWE class: CWE-129" in text

    def test_evaluate_prompt_includes_matches(self):
        h = Hypothesis(claim="c", target=Path("/x"))
        ev = ToolEvidence(
            tool="t", rule="r", success=True,
            matches=[{"file": "a.c", "line": 1, "message": "m1"}],
            summary="1 match",
        )
        text = _build_evaluate_prompt(h, ev)
        assert "a.c:1" in text
        assert "m1" in text

    def test_evaluate_prompt_truncates_matches(self):
        h = Hypothesis(claim="c", target=Path("/x"))
        matches = [{"file": "f.c", "line": i, "message": "m"} for i in range(20)]
        ev = ToolEvidence(tool="t", rule="r", success=True,
                          matches=matches, summary="20 matches")
        text = _build_evaluate_prompt(h, ev)
        # Only first 5 matches shown explicitly
        assert "and 15 more" in text


class TestExtractData:
    def test_dict_passthrough(self):
        assert _extract_data({"x": 1}) == {"x": 1}

    def test_none(self):
        assert _extract_data(None) is None

    def test_object_with_result(self):
        obj = MagicMock()
        obj.result = {"x": 1}
        assert _extract_data(obj) == {"x": 1}

    def test_object_with_data(self):
        obj = MagicMock(spec=["data"])
        obj.data = {"x": 2}
        assert _extract_data(obj) == {"x": 2}

    def test_object_without_known_attrs(self):
        # A plain object with no result/data and no dict mapping
        class X:
            pass
        assert _extract_data(X()) is None


# validate() ------------------------------------------------------------------

class TestValidateConfirmation:
    def test_confirmed_when_tool_finds_matches(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="r", success=True,
            matches=[{"file": "a.c", "line": 1}],
            summary="1 match",
        ))
        llm = FakeLLM([
            {"tool": "cocci", "rule": "@r@\n@@\nx;\n",
             "expected_evidence": "x", "reasoning": "..."},
            {"verdict": "confirmed",
             "reasoning": "match consistent with claim",
             "matches_support_claim": True},
        ])
        result = validate(h, [adapter], llm)
        assert result.confirmed
        assert len(result.evidence) == 1
        assert result.evidence[0].matches == [{"file": "a.c", "line": 1}]
        assert "consistent" in result.reasoning


class TestValidateRefutation:
    def test_refuted_when_tool_runs_clean_with_no_matches(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="r", success=True, matches=[],
            summary="no matches",
        ))
        llm = FakeLLM([
            {"tool": "cocci", "rule": "@r@\n@@\nx;\n",
             "expected_evidence": "x", "reasoning": "..."},
            # LLM returns refuted, which is allowed when no matches
            {"verdict": "refuted",
             "reasoning": "no matches found",
             "matches_support_claim": False},
        ])
        result = validate(h, [adapter], llm)
        assert result.refuted

    def test_llm_confirmed_downgraded_when_no_matches(self):
        """Architectural invariant: LLM cannot claim confirmed without matches."""
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="r", success=True, matches=[],
            summary="no matches",
        ))
        llm = FakeLLM([
            {"tool": "cocci", "rule": "@r@\n@@\nx;\n",
             "expected_evidence": "x", "reasoning": "..."},
            # LLM tries to claim confirmed despite no matches — must be downgraded
            {"verdict": "confirmed",
             "reasoning": "I think it's vulnerable",
             "matches_support_claim": True},
        ])
        result = validate(h, [adapter], llm)
        assert not result.confirmed
        # Tool ran cleanly with no matches → refuted, never confirmed
        assert result.refuted


class TestValidateInconclusive:
    def test_inconclusive_when_no_adapters_available(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", available=False)
        llm = FakeLLM([])  # never called
        result = validate(h, [adapter], llm)
        assert result.inconclusive
        assert "No applicable tools" in result.reasoning
        assert llm.calls == []

    def test_inconclusive_when_tool_errors(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="r", success=False, error="parse error",
        ))
        llm = FakeLLM([
            {"tool": "cocci", "rule": "bad rule",
             "expected_evidence": "x", "reasoning": "..."},
            # No second LLM call expected — runner short-circuits on tool failure
        ])
        result = validate(h, [adapter], llm)
        assert result.inconclusive
        assert "parse error" in result.reasoning
        # Only one LLM call: the rule generation, not evaluation
        assert len(llm.calls) == 1

    def test_inconclusive_when_llm_picks_unknown_tool(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci")
        llm = FakeLLM([
            {"tool": "fictional_tool", "rule": "r",
             "expected_evidence": "x", "reasoning": "..."},
        ])
        result = validate(h, [adapter], llm)
        assert result.inconclusive
        assert "fictional_tool" in result.reasoning

    def test_inconclusive_when_llm_returns_empty_rule(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci")
        llm = FakeLLM([
            {"tool": "cocci", "rule": "",
             "expected_evidence": "x", "reasoning": "..."},
        ])
        result = validate(h, [adapter], llm)
        assert result.inconclusive
        assert len(result.evidence) == 1
        assert not result.evidence[0].success

    def test_inconclusive_when_llm_returns_none(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci")
        # LLM raises during selection
        llm = FakeLLM([])
        result = validate(h, [adapter], llm)
        assert result.inconclusive
        assert "did not return" in result.reasoning

    def test_llm_refuted_with_matches_downgraded_to_inconclusive(self):
        """If LLM says refuted but matches are present, those matches need a human look."""
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="r", success=True,
            matches=[{"file": "a.c", "line": 1}],
            summary="1 match",
        ))
        llm = FakeLLM([
            {"tool": "cocci", "rule": "@r@\n@@\nx;\n",
             "expected_evidence": "x", "reasoning": "..."},
            {"verdict": "refuted",
             "reasoning": "the match is unrelated",
             "matches_support_claim": False},
        ])
        result = validate(h, [adapter], llm)
        assert result.inconclusive  # not refuted, despite LLM's claim


class TestValidateAdapterFiltering:
    def test_unavailable_adapters_filtered_before_llm(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        a = FakeAdapter("cocci", available=False)
        b = FakeAdapter("semgrep", available=True, evidence=ToolEvidence(
            tool="semgrep", rule="r", success=True, matches=[],
            summary="no findings",
        ))
        llm = FakeLLM([
            {"tool": "semgrep", "rule": "rules: []",
             "expected_evidence": "x", "reasoning": "..."},
            {"verdict": "refuted", "reasoning": "no match",
             "matches_support_claim": False},
        ])
        result = validate(h, [a, b], llm)
        # System prompt should NOT contain the unavailable adapter
        sys_prompt = llm.calls[0]["system_prompt"]
        assert "## semgrep" in sys_prompt
        assert "## cocci" not in sys_prompt
        assert b.run_calls  # semgrep was invoked
        assert not a.run_calls  # cocci was filtered
        assert result.refuted


class TestValidateAuditTrail:
    def test_evidence_records_rule_and_summary(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="r", success=True,
            matches=[{"file": "a.c", "line": 1}],
            summary="1 match in 1 file",
        ))
        llm = FakeLLM([
            {"tool": "cocci", "rule": "AUDITABLE_RULE_TEXT",
             "expected_evidence": "x", "reasoning": "..."},
            {"verdict": "confirmed", "reasoning": "match consistent",
             "matches_support_claim": True},
        ])
        result = validate(h, [adapter], llm)
        assert result.evidence[0].rule == "AUDITABLE_RULE_TEXT"
        assert result.evidence[0].summary == "1 match in 1 file"
        assert result.evidence[0].tool == "cocci"
        assert result.iterations == 1

    def test_to_dict_serializable(self):
        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="r", success=True,
            matches=[{"file": "a.c", "line": 1}],
            summary="1 match",
        ))
        llm = FakeLLM([
            {"tool": "cocci", "rule": "r",
             "expected_evidence": "x", "reasoning": "..."},
            {"verdict": "confirmed", "reasoning": "ok",
             "matches_support_claim": True},
        ])
        result = validate(h, [adapter], llm)
        d = result.to_dict()
        assert d["verdict"] == "confirmed"
        assert d["evidence"][0]["tool"] == "cocci"


class TestValidateProvenance:
    """Every Evidence produced by the runner is stamped with the hash
    of the hypothesis it was produced for, so downstream callers can
    refuse to combine evidence across hypotheses."""

    def test_evidence_carries_hypothesis_hash(self):
        from packages.hypothesis_validation.provenance import hash_hypothesis

        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="r", success=True,
            matches=[{"file": "a.c", "line": 1}],
            summary="1 match",
        ))
        llm = FakeLLM([
            {"tool": "cocci", "rule": "@r@\n@@\nx;\n",
             "expected_evidence": "x", "reasoning": "..."},
            {"verdict": "confirmed", "reasoning": "ok",
             "matches_support_claim": True},
        ])
        result = validate(h, [adapter], llm)
        assert result.evidence[0].refers_to == hash_hypothesis(h)

    def test_distinct_hypotheses_produce_distinct_refers_to(self):
        from packages.hypothesis_validation.provenance import hash_hypothesis

        h1 = Hypothesis(claim="a", target=Path("/src"))
        h2 = Hypothesis(claim="b", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="r", success=True,
            matches=[{"file": "a.c", "line": 1}],
            summary="1 match",
        ))
        llm_script = [
            {"tool": "cocci", "rule": "@r@\n@@\nx;\n",
             "expected_evidence": "x", "reasoning": "..."},
            {"verdict": "confirmed", "reasoning": "ok",
             "matches_support_claim": True},
        ]
        r1 = validate(h1, [adapter], FakeLLM(list(llm_script)))
        r2 = validate(h2, [adapter], FakeLLM(list(llm_script)))
        assert r1.evidence[0].refers_to != r2.evidence[0].refers_to
        assert r1.evidence[0].refers_to == hash_hypothesis(h1)
        assert r2.evidence[0].refers_to == hash_hypothesis(h2)

    def test_empty_rule_evidence_also_stamped(self):
        # The empty-rule branch in validate() builds its own Evidence;
        # provenance must still attach so the audit trail is complete.
        from packages.hypothesis_validation.provenance import hash_hypothesis

        h = Hypothesis(claim="c", target=Path("/src"))
        adapter = FakeAdapter("cocci", evidence=ToolEvidence(
            tool="cocci", rule="", success=True, matches=[], summary="",
        ))
        llm = FakeLLM([
            {"tool": "cocci", "rule": "   ",  # whitespace-only → empty
             "expected_evidence": "x", "reasoning": "..."},
        ])
        result = validate(h, [adapter], llm)
        assert result.inconclusive
        assert result.evidence[0].refers_to == hash_hypothesis(h)
