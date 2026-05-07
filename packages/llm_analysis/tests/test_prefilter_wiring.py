"""Tests for /agentic's fast-tier scorecard prefilter wiring.

Drives :func:`packages.llm_analysis.prefilter.prefilter_for_finding`
and the dispatch hook that consumes its result. Mirrors the
codeql-side test in ``packages/codeql/tests/test_scorecard_wiring.py``
so the two consumers stay in lock-step on substrate semantics.
"""

from __future__ import annotations

import threading
from typing import Any, Dict

import pytest

from core.llm.config import LLMConfig, ModelConfig
from core.llm.scorecard import EventType, ModelScorecard
from core.llm.task_types import TaskType
from packages.llm_analysis.prefilter import (
    FP_PREFILTER_SCHEMA,
    agentic_fp_analysis,
    prefilter_for_finding,
)


# ---------------------------------------------------------------------------
# Stub LLM and fixture (parallels test_scorecard_wiring.py:_build_llm)
# ---------------------------------------------------------------------------


class _StubProvider:
    """Lives in ``client.providers`` so ``LLMClient`` doesn't need to
    construct a real one. Each test attaches a function to
    ``self.responder`` that returns a structured response."""

    def __init__(self):
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.call_count = 0
        self.total_duration = 0.0
        self.responder = lambda prompt, schema, system_prompt: ({}, "")

    def generate_structured(self, prompt, schema, system_prompt=None,
                            **_kwargs):
        self.call_count += 1
        return self.responder(prompt, schema, system_prompt)

    def get_stats(self):
        return {
            "total_cost": self.total_cost,
            "total_tokens": self.total_tokens,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "call_count": self.call_count,
            "total_duration": self.total_duration,
        }


def _build_llm(tmp_path):
    """Mirrors the codeql test's _build_llm. Builds a minimally-
    configured LLMClient with a single shared stub provider."""
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
    cfg.specialized_models = {
        TaskType.VERDICT_BINARY: ModelConfig(
            provider="anthropic", model_name="haiku-stub",
            max_context=200000, api_key="x",
        ),
    }
    cfg.scorecard_path = tmp_path / "scorecard.json"
    cfg.scorecard_enabled = True
    cfg.scorecard_retain_samples = True
    # Same flake-prevention as the codeql fixture: dataclass default
    # for shadow_rate is 0.05; force 0.0 for deterministic
    # short-circuit assertions.
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

    prov = _StubProvider()
    client.providers["anthropic:opus-stub"] = prov
    client.providers["anthropic:haiku-stub"] = prov
    return client, prov


def _finding(rule_id: str = "py/sql-injection") -> Dict[str, Any]:
    """A minimal /agentic-shaped finding dict."""
    return {
        "finding_id": "f1",
        "rule_id": rule_id,
        "rule_name": rule_id,
        "message": "possible SQL injection",
        "level": "error",
        "file_path": "app.py",
        "start_line": 10,
        "end_line": 12,
        "vulnerable_code": "x = request.GET['id']",
        "cwe": "CWE-89",
    }


@pytest.fixture
def llm(tmp_path):
    yield _build_llm(tmp_path)


# ---------------------------------------------------------------------------
# Helper-shape tests
# ---------------------------------------------------------------------------


def test_agentic_fp_analysis_has_all_required_fields():
    """The short-circuit result dict must populate every key the
    downstream merge loop / report renderer expects, with values that
    read clearly as 'false positive' rather than 'missing data'."""
    result = agentic_fp_analysis("hardcoded literal, not attacker-controlled")

    assert result["is_true_positive"] is False
    assert result["is_exploitable"] is False
    assert result["exploitability_score"] == 0.0
    assert result["ruling"] == "false_positive"
    assert "hardcoded literal" in result["reasoning"]
    assert "Fast-tier prefilter" in result["reasoning"]
    # Required fields the renderer reads:
    for k in ("severity_assessment", "confidence", "attack_scenario",
              "prerequisites", "impact", "remediation"):
        assert k in result, f"missing required field {k!r}"


def test_agentic_fp_analysis_truncates_overlong_reasoning():
    """The cheap model's reasoning is operator-visible in the report;
    cap it so a chatty model can't bloat the JSON."""
    result = agentic_fp_analysis("x" * 5000)
    assert len(result["reasoning"]) < 1000
    assert len(result["false_positive_reason"]) < 1000


# ---------------------------------------------------------------------------
# prefilter_for_finding behaviour
# ---------------------------------------------------------------------------


def test_learning_mode_returns_none_no_short_circuit(llm):
    """Cold start: scorecard cell has no track record → policy is
    LEARNING → ``prefilter_for_finding`` returns ``None`` and the full
    ANALYSE call must run. No short-circuit even though the cheap
    model said clear_fp."""
    client, prov = llm

    def responder(prompt, schema, system_prompt):
        return ({"verdict": "clear_fp", "reasoning": "no taint"}, "raw")
    prov.responder = responder

    result = prefilter_for_finding(client, _finding())

    assert result is None
    assert client.short_circuits == 0


def test_short_circuit_on_trusted_cell(llm):
    """Pre-seed scorecard with a trustworthy track record →
    SHORT_CIRCUIT → cheap says clear_fp → returns FP analysis dict and
    bumps client.short_circuits."""
    client, prov = llm
    sc = ModelScorecard(client.config.scorecard_path)
    for _ in range(150):
        sc.record_event(
            "agentic:py/sql-injection", "haiku-stub",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    client._scorecard = None  # force lazy reload from sidecar

    def responder(prompt, schema, system_prompt):
        return ({"verdict": "clear_fp",
                 "reasoning": "value is constant 'admin'"}, "raw")
    prov.responder = responder

    result = prefilter_for_finding(client, _finding())

    assert result is not None
    assert result["is_true_positive"] is False
    assert result["ruling"] == "false_positive"
    assert "constant 'admin'" in result["reasoning"]
    assert client.short_circuits == 1


def test_cheap_says_needs_analysis_no_short_circuit_even_when_trusted(llm):
    """Trusted cell + cheap says ``needs_analysis`` → fall through.
    The gate's asymmetry: we never short-circuit on a non-confident
    cheap verdict regardless of trust."""
    client, prov = llm
    sc = ModelScorecard(client.config.scorecard_path)
    for _ in range(150):
        sc.record_event(
            "agentic:py/sql-injection", "haiku-stub",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    client._scorecard = None

    def responder(prompt, schema, system_prompt):
        return ({"verdict": "needs_analysis",
                 "reasoning": "uncertain"}, "raw")
    prov.responder = responder

    result = prefilter_for_finding(client, _finding())

    assert result is None
    assert client.short_circuits == 0


def test_cheap_call_failure_falls_through_silently(llm):
    """A cheap-tier LLM exception (rate limit, schema error, anything)
    must not abort the analysis. Returns ``None`` so the orchestrator
    runs the full ANALYSE path as it would today."""
    client, prov = llm

    def responder(prompt, schema, system_prompt):
        raise RuntimeError("cheap tier exploded")
    prov.responder = responder

    result = prefilter_for_finding(client, _finding())

    assert result is None
    assert client.short_circuits == 0


def test_cheap_unexpected_verdict_falls_through(llm):
    """Defensive: unrecognised verdict strings ('maybe', '???', etc.)
    fall through. No short-circuit, no scorecard event recorded."""
    client, prov = llm
    sc = ModelScorecard(client.config.scorecard_path)
    for _ in range(150):
        sc.record_event(
            "agentic:py/sql-injection", "haiku-stub",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    client._scorecard = None

    def responder(prompt, schema, system_prompt):
        return ({"verdict": "maybe", "reasoning": "?"}, "raw")
    prov.responder = responder

    result = prefilter_for_finding(client, _finding())

    assert result is None
    assert client.short_circuits == 0


def test_decision_class_is_agentic_prefixed(llm):
    """Trust accumulates under ``agentic:<rule_id>``, not the bare
    rule_id and not codeql-style ``codeql:<rule_id>``. Keeps /agentic
    cells distinct from /codeql cells in the same scorecard sidecar."""
    client, prov = llm
    sc = ModelScorecard(client.config.scorecard_path)
    # Pre-seed under the WRONG key — bare rule_id and codeql prefix.
    for prefix in ("py/sql-injection", "codeql:py/sql-injection"):
        for _ in range(150):
            sc.record_event(
                prefix, "haiku-stub",
                EventType.CHEAP_SHORT_CIRCUIT, "correct",
            )
    client._scorecard = None

    def responder(prompt, schema, system_prompt):
        return ({"verdict": "clear_fp", "reasoning": "x"}, "raw")
    prov.responder = responder

    # Wrong-key trust must NOT cause a short-circuit on the correct
    # ``agentic:`` cell.
    result = prefilter_for_finding(client, _finding())
    assert result is None
    assert client.short_circuits == 0


def test_disagreement_lookup_key_matches_decision_class(llm):
    """A short-circuit recording (via the dispatcher's outcome record
    path, not the prefilter) lands under ``agentic:<rule_id>``. We
    verify by writing one event under that exact key and confirming
    ``ModelScorecard.get_stat`` reads it back."""
    client, _prov = llm
    sc = ModelScorecard(client.config.scorecard_path)
    sc.record_event(
        "agentic:py/sql-injection", "haiku-stub",
        EventType.CHEAP_SHORT_CIRCUIT, "correct",
    )
    stat = sc.get_stat("agentic:py/sql-injection", "haiku-stub")
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].correct == 1


# ---------------------------------------------------------------------------
# Schema sanity
# ---------------------------------------------------------------------------


def test_fp_prefilter_schema_matches_codeql():
    """We deliberately match codeql's schema shape so cheap-tier
    responses are interchangeable across consumers. If this drifts,
    it's a deliberate design choice that should be reviewed."""
    from packages.codeql.autonomous_analyzer import (
        FP_PREFILTER_SCHEMA as codeql_schema,
    )
    assert FP_PREFILTER_SCHEMA == codeql_schema
