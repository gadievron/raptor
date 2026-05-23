"""End-to-end runner ↔ SourceIntelAdapter integration — closes gap #7.

The 19 existing tests at ``test_adapter_source_intel.py`` exercise the
adapter in isolation. ``packages/llm_analysis/dataflow_validation.py``
is the only production caller of ``hypothesis_validation.runner.validate``
and it only wires ``CodeQLAdapter``. Until now, the path
``runner.validate()`` → ``SourceIntelAdapter.run()`` had never run
under test.

These tests drive the full path with mocked LLM + mocked
``packages.source_intel.analyze.analyze`` so they don't require
coccinelle on the host. The wiring chain proven here is:

  validate()
    → _ask_llm_to_select_tool()          (LLM picks "source_intel")
    → SourceIntelAdapter.run(rule, target)
        → _load_result(target)
            → analyze(target)            (mocked to return a fixture)
        → _collect_axis(...)             (real adapter logic)
        → ToolEvidence(success=True, matches=...)
    → _evaluate(hypothesis, evidence)    (LLM produces verdict)
    → ValidationResult
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from packages.hypothesis_validation.adapters.source_intel import (
    SourceIntelAdapter,
)
from packages.hypothesis_validation.hypothesis import Hypothesis
from packages.hypothesis_validation.runner import validate
from packages.source_intel.analyze import (
    AttributeEvidence,
    KIND_NORETURN,
    SourceIntelResult,
)


class _FakeLLM:
    """Stateful LLM mock — first call selects a tool, second evaluates."""

    def __init__(self, *, tool: str, rule: dict, verdict: str, reasoning: str):
        self._tool = tool
        self._rule = json.dumps(rule)
        self._verdict = verdict
        self._reasoning = reasoning
        self.call_count = 0
        self.calls: list[dict] = []

    def generate_structured(self, *, prompt, schema, **kwargs):
        self.call_count += 1
        self.calls.append({"prompt_head": prompt[:200], "schema": schema})
        if self.call_count == 1:
            # Tool selection: return what looks like StructuredResponse.result.
            return {"tool": self._tool, "rule": self._rule}
        return {"verdict": self._verdict, "reasoning": self._reasoning}


@pytest.fixture
def fixture_target(tmp_path: Path) -> Path:
    """Tmp target with one C file. SourceIntel.analyze is mocked, so the
    file's content doesn't drive the test — just gives the adapter a
    real existing Path to work with."""
    fp = tmp_path / "axis1.c"
    fp.write_text(
        "__attribute__((noreturn))\n"
        "void panic(const char *msg);\n"
    )
    return tmp_path


@pytest.fixture
def stub_analyze_result(fixture_target):
    """Return a SourceIntelResult carrying one NORETURN attribute on `panic`."""
    return SourceIntelResult(
        target=str(fixture_target),
        attributes=(
            AttributeEvidence(
                kind=KIND_NORETURN,
                function_name="panic",
                location=(str(fixture_target / "axis1.c"), 2),
                match_source="literal",
                raw_match="noreturn",
            ),
        ),
    )


def _hypothesis(target: Path) -> Hypothesis:
    return Hypothesis(
        claim="`panic` is annotated NORETURN so the deref guarded by it cannot fire",
        target=target,
        target_function="panic",
        cwe="CWE-476",
        suggested_tools=["source_intel"],
    )


# =====================================================================
# Confirmed path
# =====================================================================

def test_runner_drives_source_intel_adapter_end_to_end(fixture_target, stub_analyze_result):
    """Full runner → adapter → analyze → evaluate path with a match.

    Coccinelle is faked-available via mocking SourceIntelAdapter.is_available
    so the test doesn't need spatch on the host. The internal
    `_load_result` → `analyze()` call is mocked to deliver the stub.
    """
    fake_llm = _FakeLLM(
        tool="source_intel",
        rule={"function": "panic", "axes": ["attrs"]},
        verdict="confirmed",
        reasoning="NORETURN on panic supports the claim",
    )
    adapter = SourceIntelAdapter()

    with mock.patch.object(SourceIntelAdapter, "is_available", return_value=True), \
         mock.patch(
             "packages.source_intel.analyze.analyze",
             return_value=stub_analyze_result,
         ):
        result = validate(
            hypothesis=_hypothesis(fixture_target),
            adapters=[adapter],
            llm_client=fake_llm,
        )

    # 2 LLM calls fired (select + evaluate).
    assert fake_llm.call_count == 2
    # Runner reached a real verdict — the full wiring chain is exercised.
    assert result.verdict == "confirmed"
    assert result.iterations == 1
    # Evidence carries the source_intel tool name + at least one match.
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.tool == "source_intel"
    assert ev.matches  # the stub's NORETURN attribute came through
    # Match shape covers function + axis info — proves adapter._collect_axis
    # ran for real against the stub result.
    m = ev.matches[0]
    assert m.get("function") == "panic"
    assert m.get("kind") == "noreturn"


# =====================================================================
# Refuted path — adapter ran cleanly, found nothing
# =====================================================================

def test_runner_refutes_when_adapter_finds_no_matches(fixture_target):
    """Empty SourceIntelResult → adapter returns success=True with zero
    matches → runner's verdict-from-tool downgrades any LLM-claimed
    confirmation to refuted (architectural invariant)."""
    fake_llm = _FakeLLM(
        tool="source_intel",
        rule={"function": "panic", "axes": ["attrs"]},
        # LLM claims confirmed; runner must downgrade because matches is empty.
        verdict="confirmed",
        reasoning="(LLM opinion, no mechanical evidence)",
    )
    empty = SourceIntelResult(target=str(fixture_target))
    adapter = SourceIntelAdapter()

    with mock.patch.object(SourceIntelAdapter, "is_available", return_value=True), \
         mock.patch(
             "packages.source_intel.analyze.analyze",
             return_value=empty,
         ):
        result = validate(
            hypothesis=_hypothesis(fixture_target),
            adapters=[adapter],
            llm_client=fake_llm,
        )

    # Mechanical truth wins over LLM opinion.
    assert result.verdict == "refuted"


# =====================================================================
# Adapter-error path — runner produces inconclusive
# =====================================================================

def test_runner_inconclusive_when_rule_is_invalid_json(fixture_target):
    """LLM produces a rule the adapter can't parse → adapter returns
    success=False → runner verdict is inconclusive without even
    invoking the LLM evaluator (no point — tool didn't run)."""

    class BadRuleLLM:
        def __init__(self):
            self.call_count = 0

        def generate_structured(self, *, prompt, schema, **kwargs):
            self.call_count += 1
            if self.call_count == 1:
                return {"tool": "source_intel", "rule": "{not json"}
            # Evaluator may or may not be called — depends on adapter
            # contract. Either way return something parseable.
            return {"verdict": "refuted", "reasoning": "evaluator"}

    fake_llm = BadRuleLLM()
    adapter = SourceIntelAdapter()

    with mock.patch.object(SourceIntelAdapter, "is_available", return_value=True), \
         mock.patch(
             "packages.source_intel.analyze.analyze",
         ) as analyze_mock:
        result = validate(
            hypothesis=_hypothesis(fixture_target),
            adapters=[adapter],
            llm_client=fake_llm,
        )
        # analyze() must never have been reached — adapter rejected the rule.
        analyze_mock.assert_not_called()

    assert result.verdict == "inconclusive"


# =====================================================================
# Adapter not available — runner returns inconclusive cleanly
# =====================================================================

def test_runner_inconclusive_when_no_adapter_available(fixture_target):
    """When SourceIntelAdapter.is_available() returns False (no
    coccinelle on host), the runner filters it out → no available
    adapters → inconclusive without any LLM calls."""
    fake_llm = _FakeLLM(
        tool="source_intel",
        rule={"function": "panic", "axes": ["attrs"]},
        verdict="confirmed",
        reasoning="(would not be reached)",
    )
    adapter = SourceIntelAdapter()

    with mock.patch.object(SourceIntelAdapter, "is_available", return_value=False):
        result = validate(
            hypothesis=_hypothesis(fixture_target),
            adapters=[adapter],
            llm_client=fake_llm,
        )

    assert result.verdict == "inconclusive"
    # LLM never consulted — no available adapter to ask about.
    assert fake_llm.call_count == 0
