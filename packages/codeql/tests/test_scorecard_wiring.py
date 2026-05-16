"""Integration tests for codeql's scorecard prefilter wiring.

Drives :class:`AutonomousCodeQLAnalyzer.analyze_vulnerability` and
:class:`DataflowValidator.validate_dataflow_path` with a stubbed
LLM client and verifies:

* The cheap prefilter is consulted on every call.
* When the scorecard says SHORT_CIRCUIT and cheap claims FP, the
  full ANALYSE path is skipped.
* When the scorecard says LEARNING, both cheap and full run, and
  the outcome is recorded back to the cell so trust accumulates.
* Decision classes are keyed as ``codeql:<rule_id>``.
"""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace
from typing import List, Tuple

import pytest

from core.llm.config import LLMConfig, ModelConfig
from core.llm.scorecard import EventType, ModelScorecard, Policy
from core.llm.task_types import TaskType
from packages.codeql.autonomous_analyzer import (
    AutonomousCodeQLAnalyzer,
    CodeQLFinding,
)


# ---------------------------------------------------------------------------
# Stub LLM and scorecard glue
# ---------------------------------------------------------------------------


class StubProvider:
    """Lives in ``client.providers`` so ``LLMClient`` doesn't need to
    construct a real one. Every test test-case attaches a function to
    ``self.responder`` that returns a structured response."""
    def __init__(self):
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.call_count = 0
        self.total_duration = 0.0
        self.responder = lambda prompt, schema, system_prompt: ({}, "")

    def generate_structured(self, prompt, schema, system_prompt=None):
        self.call_count += 1
        return self.responder(prompt, schema, system_prompt)


def _build_llm(tmp_path) -> "object":
    """Build an LLMClient that:
      * has a primary model (so config validation passes)
      * has a fast-tier model under specialized_models[VERDICT_BINARY]
      * routes both through the same StubProvider so a single
        responder can choose what to return based on schema shape
      * uses tmp_path for the scorecard sidecar
    """
    from core.llm.client import LLMClient
    primary = ModelConfig(
        provider="anthropic", model_name="opus-stub",
        max_context=200000, api_key="x",
    )
    cfg = LLMConfig.__new__(LLMConfig)
    cfg.primary_model = primary
    cfg.fallback_models = []
    cfg.enable_fallback = False
    cfg.max_retries = 1
    cfg.retry_delay = 0
    cfg.retry_delay_remote = 0
    cfg.enable_caching = False
    cfg.cache_dir = tmp_path / "cache"
    cfg.cache_ttl_seconds = None
    cfg.cache_max_entries = None
    cfg.enable_cost_tracking = False
    cfg.max_cost_per_scan = 100.0
    # Specialised fast-tier model — same provider+name on the stub
    # so we don't need a second provider entry. The cheap-vs-full
    # distinction in this test is by SCHEMA shape, not by which
    # provider the call hits.
    cfg.specialized_models = {
        TaskType.VERDICT_BINARY: ModelConfig(
            provider="anthropic", model_name="haiku-stub",
            max_context=200000, api_key="x",
        ),
    }
    cfg.scorecard_path = tmp_path / "scorecard.json"
    cfg.scorecard_enabled = True
    cfg.scorecard_retain_samples = True
    # Deterministic short-circuit assertions: the dataclass default
    # for shadow_rate is 0.05, which would flake the
    # ``short_circuit_skips_full`` test ~5% of the time when the random
    # roll lands under threshold.
    cfg.scorecard_shadow_rate = 0.0

    client = LLMClient.__new__(LLMClient)
    client.config = cfg
    client.providers = {}
    client.total_cost = 0.0
    client.request_count = 0
    client.task_type_costs = {}
    client.short_circuits = 0
    client._stats_lock = threading.RLock()
    client._key_locks = {}
    client._key_locks_guard = threading.Lock()
    client._scorecard = None

    # Single shared provider for both opus-stub and haiku-stub —
    # the stub doesn't care about the model identity, only the
    # responder set per-test. The provider key matches what
    # _get_provider would compute.
    prov = StubProvider()
    client.providers["anthropic:opus-stub"] = prov
    client.providers["anthropic:haiku-stub"] = prov
    return client, prov


def _finding(rule_id: str = "py/sql-injection") -> CodeQLFinding:
    return CodeQLFinding(
        rule_id=rule_id,
        rule_name=rule_id,
        message="possible SQL injection",
        level="error",
        file_path="app.py",
        start_line=10,
        end_line=12,
        snippet="x = request.GET['id']",
        cwe="CWE-89",
    )


# Schema shape detector — used by responders to know whether a call
# is the cheap prefilter or the full analysis. Cheap schema has
# ``verdict``; full schema has ``is_true_positive``.
def _is_cheap_call(schema):
    return "verdict" in schema and "is_true_positive" not in schema


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def llm(tmp_path):
    """Yield a fresh (client, provider) pair per test."""
    client, prov = _build_llm(tmp_path)
    yield client, prov


def _make_analyzer(llm_client):
    return AutonomousCodeQLAnalyzer(
        llm_client=llm_client,
        exploit_validator=SimpleNamespace(),
        multi_turn_analyzer=None,
        enable_visualization=False,
    )


def test_learning_mode_runs_both_cheap_and_full(llm):
    """Cold start → policy LEARNING → both calls happen and outcome
    is recorded so trust starts to accumulate."""
    client, prov = llm
    analyzer = _make_analyzer(client)
    cheap_calls, full_calls = [], []

    def responder(prompt, schema, system_prompt):
        if _is_cheap_call(schema):
            cheap_calls.append(prompt)
            return ({"verdict": "clear_fp",
                     "reasoning": "no taint"}, "raw")
        full_calls.append(prompt)
        return ({
            "is_true_positive": False, "is_exploitable": False,
            "exploitability_score": 0.0,
            "severity_assessment": "low", "reasoning": "agree, no real bug",
            "attack_scenario": "", "prerequisites": [],
            "impact": "none", "cvss_estimate": 0.0,
            "mitigation": "n/a",
        }, "raw")
    prov.responder = responder

    result = analyzer.analyze_vulnerability(_finding(), "x = 1")
    assert len(cheap_calls) == 1
    assert len(full_calls) == 1
    assert result.is_true_positive is False

    # Outcome recorded: cheap said FP, full said FP → "correct"
    sc = ModelScorecard(client.config.scorecard_path)
    stat = sc.get_stat("codeql:py/sql-injection", "haiku-stub")
    assert stat is not None
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].correct == 1
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect == 0


def test_disagreement_records_incorrect_with_sample(llm):
    """Cheap claimed FP, full found a real bug → cell records
    ``incorrect`` and the disagreement reasoning is captured."""
    client, prov = llm
    analyzer = _make_analyzer(client)

    def responder(prompt, schema, system_prompt):
        if _is_cheap_call(schema):
            return ({"verdict": "clear_fp",
                     "reasoning": "looks hardcoded"}, "raw")
        return ({
            "is_true_positive": True, "is_exploitable": True,
            "exploitability_score": 0.8,
            "severity_assessment": "high",
            "reasoning": "request.GET tainted via helper",
            "attack_scenario": "", "prerequisites": [],
            "impact": "RCE", "cvss_estimate": 8.0,
            "mitigation": "parametrize",
        }, "raw")
    prov.responder = responder

    result = analyzer.analyze_vulnerability(_finding(), "x = request.GET['id']")
    assert result.is_true_positive is True

    sc = ModelScorecard(client.config.scorecard_path)
    stat = sc.get_stat("codeql:py/sql-injection", "haiku-stub")
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect == 1
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].correct == 0
    assert len(stat.disagreement_samples) == 1
    sample = stat.disagreement_samples[0]
    assert "hardcoded" in sample["this_reasoning"]
    assert "request.GET" in sample["other_reasoning"]


def test_short_circuit_skips_full_when_scorecard_trusts_cell(llm):
    """Pre-seed the scorecard with a trustworthy track record,
    then run analyze: cheap claims FP, full call should NOT happen,
    result should reflect the cheap reasoning."""
    client, prov = llm
    sc = ModelScorecard(client.config.scorecard_path)
    # Build trust on the cell before the analyzer runs.
    for _ in range(150):
        sc.record_event(
            "codeql:py/sql-injection", "haiku-stub",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    # Reset the lazy-built scorecard property so the next access
    # uses the seeded sidecar.
    client._scorecard = None

    analyzer = _make_analyzer(client)
    cheap_calls, full_calls = [], []

    def responder(prompt, schema, system_prompt):
        if _is_cheap_call(schema):
            cheap_calls.append(prompt)
            return ({"verdict": "clear_fp",
                     "reasoning": "value is constant 'admin'"}, "raw")
        full_calls.append(prompt)
        # Won't be invoked under this test; assert below.
        return ({}, "raw")
    prov.responder = responder

    result = analyzer.analyze_vulnerability(_finding(), "x = 'admin'")

    # Critical: full call was avoided.
    assert len(cheap_calls) == 1
    assert len(full_calls) == 0, (
        f"expected no full ANALYSE call, got {len(full_calls)}"
    )
    # And the result reflects the cheap reasoning.
    assert result.is_true_positive is False
    assert "constant 'admin'" in result.reasoning
    # Substrate counter bumped so /codeql can surface the saving.
    assert client.short_circuits == 1


def test_short_circuits_counter_starts_at_zero_when_full_runs(llm):
    """No short-circuit → counter stays at zero. Guards against
    consumers accidentally bumping on the fall-through path."""
    client, prov = llm
    analyzer = _make_analyzer(client)

    def responder(prompt, schema, system_prompt):
        if _is_cheap_call(schema):
            return ({"verdict": "needs_analysis",
                     "reasoning": "uncertain"}, "raw")
        return ({
            "is_true_positive": True, "is_exploitable": True,
            "exploitability_score": 0.5, "severity_assessment": "medium",
            "reasoning": "tainted", "attack_scenario": "",
            "prerequisites": [], "impact": "?", "cvss_estimate": 5.0,
            "mitigation": "fix",
        }, "raw")
    prov.responder = responder

    analyzer.analyze_vulnerability(_finding(), "code")

    assert client.short_circuits == 0


def test_cheap_says_needs_analysis_does_not_record_event(llm):
    """When cheap doesn't claim FP, no scorecard event is recorded —
    the gate's Wilson math is computed only over confident-FP
    outcomes."""
    client, prov = llm
    analyzer = _make_analyzer(client)

    def responder(prompt, schema, system_prompt):
        if _is_cheap_call(schema):
            return ({"verdict": "needs_analysis",
                     "reasoning": "uncertain"}, "raw")
        return ({
            "is_true_positive": True, "is_exploitable": True,
            "exploitability_score": 0.5, "severity_assessment": "medium",
            "reasoning": "tainted", "attack_scenario": "",
            "prerequisites": [], "impact": "?", "cvss_estimate": 5.0,
            "mitigation": "fix",
        }, "raw")
    prov.responder = responder

    analyzer.analyze_vulnerability(_finding(), "code")

    sc = ModelScorecard(client.config.scorecard_path)
    # The cell may have been touched by ensure_cell during the
    # decision lookup; what matters is no event recorded.
    stat = sc.get_stat("codeql:py/sql-injection", "haiku-stub")
    if stat is not None:
        ev = stat.events[EventType.CHEAP_SHORT_CIRCUIT]
        assert ev.correct == 0
        assert ev.incorrect == 0


def test_cheap_call_failure_falls_through_silently(llm):
    """If the cheap call raises (provider down, parse error, etc.)
    we fall through to full analysis as if no prefilter ran. The
    error must NOT propagate out of analyze_vulnerability."""
    client, prov = llm
    analyzer = _make_analyzer(client)

    def responder(prompt, schema, system_prompt):
        if _is_cheap_call(schema):
            raise RuntimeError("simulated cheap call failure")
        return ({
            "is_true_positive": True, "is_exploitable": True,
            "exploitability_score": 0.5, "severity_assessment": "medium",
            "reasoning": "ok", "attack_scenario": "",
            "prerequisites": [], "impact": "x", "cvss_estimate": 5.0,
            "mitigation": "y",
        }, "raw")
    prov.responder = responder

    # Should not raise.
    result = analyzer.analyze_vulnerability(_finding(), "code")
    assert result.is_true_positive is True


def test_decision_class_is_codeql_prefixed(llm):
    """The keying convention ``codeql:<rule_id>`` is locked in.
    A consumer that produced a different shape would silently
    fragment the scorecard."""
    client, prov = llm
    analyzer = _make_analyzer(client)
    prov.responder = lambda p, s, sp: (
        ({"verdict": "clear_fp", "reasoning": "x"}, "raw")
        if _is_cheap_call(s)
        else ({
            "is_true_positive": False, "is_exploitable": False,
            "exploitability_score": 0.0, "severity_assessment": "low",
            "reasoning": "x", "attack_scenario": "",
            "prerequisites": [], "impact": "x", "cvss_estimate": 0.0,
            "mitigation": "x",
        }, "raw")
    )

    analyzer.analyze_vulnerability(_finding("cpp/uncontrolled-format-string"), "code")

    sc = ModelScorecard(client.config.scorecard_path)
    stats = sc.get_stats()
    assert any(s.decision_class == "codeql:cpp/uncontrolled-format-string"
               for s in stats), (
        f"expected codeql-prefixed decision_class, got "
        f"{[s.decision_class for s in stats]}"
    )
