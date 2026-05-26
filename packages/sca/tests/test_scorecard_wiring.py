"""Integration tests for SCA's upgrade-impact scorecard prefilter.

Drives :func:`packages.sca.llm.upgrade_impact_review.assess_upgrade_impact`
with a stubbed LLM client and verifies:

* Cheap prefilter is consulted on every call.
* When the scorecard says SHORT_CIRCUIT and cheap claims clear_safe,
  the full review is skipped — the returned verdict reflects the
  cheap reasoning.
* In learning mode (cold-start cell) both cheap and full run, and
  the outcome is recorded.
* decision_class is keyed as ``sca:major_bump:<ecosystem>``.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from core.llm.config import LLMConfig, ModelConfig
from core.llm.scorecard import EventType, ModelScorecard
from core.llm.task_types import TaskType


# ---------------------------------------------------------------------------
# Stub provider — chooses cheap vs full response from schema shape
# ---------------------------------------------------------------------------


class StubProvider:
    """Stand-in provider keyed on schema shape:
      * cheap schema has ``verdict`` literal ``clear_safe`` /
        ``needs_analysis``;
      * full schema has ``breaking_changes`` field.
    """
    def __init__(self):
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.call_count = 0
        self.total_duration = 0.0
        self.cheap_calls = 0
        self.full_calls = 0
        self.cheap_responder = None
        self.full_responder = None

    def generate_structured(self, prompt, schema, system_prompt=None):
        is_cheap = self._is_cheap_schema(schema)
        if is_cheap:
            self.cheap_calls += 1
            return self.cheap_responder()
        self.full_calls += 1
        return self.full_responder()

    @staticmethod
    def _is_cheap_schema(schema) -> bool:
        """Detect cheap-tier schema shape. The Pydantic-derived JSON
        schema for ``UpgradeImpactPrefilter`` has a single
        enum-property ``verdict`` whose values are
        ``clear_safe`` / ``needs_analysis``."""
        try:
            props = schema.get("properties", {})
            verdict = props.get("verdict", {})
            enum = verdict.get("enum") or []
            return "clear_safe" in enum
        except Exception:
            return False


# ---------------------------------------------------------------------------
# LLMClient assembly
# ---------------------------------------------------------------------------


def _build_llm(scorecard_path: Path):
    """Build an LLMClient with a single StubProvider serving both
    primary and fast-tier model_name keys. Scorecard sidecar lives
    at the supplied path so each test gets its own."""
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
    cfg.cache_dir = scorecard_path.parent / "cache"
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
    cfg.scorecard_path = scorecard_path
    cfg.scorecard_enabled = True
    cfg.scorecard_retain_samples = True
    cfg.scorecard_shadow_rate = 0.0    # deterministic for this test

    client = LLMClient.__new__(LLMClient)
    client.config = cfg
    client.providers = {}
    client.total_cost = 0.0
    client.request_count = 0
    client.task_type_costs = {}
    client._stats_lock = threading.RLock()
    client._key_locks = {}
    client._key_locks_guard = threading.Lock()
    client._key_locks_cap = 4096
    client._scorecard = None
    client._cache_write_failures = 0

    prov = StubProvider()
    client.providers["anthropic:opus-stub"] = prov
    client.providers["anthropic:haiku-stub"] = prov
    return client, prov


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dep(ecosystem: str = "PyPI", name: str = "requests", version: str = "2.28.0"):
    from packages.sca.models import Dependency, Confidence, PinStyle
    return Dependency(
        ecosystem=ecosystem, name=name, version=version,
        declared_in=Path("requirements.txt"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="test fixture"),
    )


def _cheap_safe_response():
    return (
        {"verdict": "clear_safe",
         "reasoning": "patch bump; changelog only mentions bug fixes"},
        '{"verdict":"clear_safe","reasoning":"..."}',
    )


def _cheap_needs_analysis_response():
    return (
        {"verdict": "needs_analysis",
         "reasoning": "major version bump; changelog mentions breaking"},
        '{"verdict":"needs_analysis","reasoning":"..."}',
    )


def _full_safe_response():
    return (
        {"verdict": "safe", "confidence": "high",
         "breaking_changes": [],
         "summary": "all call sites unaffected"},
        '{"verdict":"safe",...}',
    )


def _full_major_response():
    return (
        {"verdict": "major_migration", "confidence": "high",
         "breaking_changes": [
             {"site": "src/app.py:10",
              "what_breaks": "removed_api removed in 3.0",
              "suggested_fix": "use new_api()"}
         ],
         "summary": "API removed"},
        '{"verdict":"major_migration",...}',
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def llm(tmp_path):
    client, prov = _build_llm(tmp_path / "scorecard.json")
    yield client, prov


def _patch_grep_to_return_call_sites(monkeypatch):
    """SCA's full path early-returns 'safe' when grep finds no call
    sites. To exercise the cheap-vs-full split honestly we need at
    least one call site so the full path is reachable."""
    from packages.sca.llm import upgrade_impact_review
    monkeypatch.setattr(
        upgrade_impact_review, "_grep_call_sites",
        lambda target, dep: ["src/app.py:10:    requests.get(url)"],
    )


def test_learning_mode_runs_both_cheap_and_full(llm, tmp_path, monkeypatch):
    """Cold scorecard cell → both cheap and full run; outcome
    recorded so trust starts to accumulate. cheap=safe, full=safe →
    correct event."""
    client, prov = llm
    _patch_grep_to_return_call_sites(monkeypatch)
    prov.cheap_responder = _cheap_safe_response
    prov.full_responder = _full_safe_response

    from packages.sca.llm.upgrade_impact_review import assess_upgrade_impact
    result = assess_upgrade_impact(
        client, _dep(), "2.28.5", target=tmp_path, changelog="bugfix only",
    )

    assert prov.cheap_calls == 1
    assert prov.full_calls == 1
    assert result.verdict == "safe"

    sc = ModelScorecard(client.config.scorecard_path)
    stat = sc.get_stat("sca:major_bump:PyPI", "haiku-stub")
    assert stat is not None
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].correct == 1


def test_disagreement_records_incorrect(llm, tmp_path, monkeypatch):
    """Cheap claimed clear_safe but full found a major_migration —
    cell records ``incorrect`` and disagreement reasoning is captured."""
    client, prov = llm
    _patch_grep_to_return_call_sites(monkeypatch)
    prov.cheap_responder = _cheap_safe_response
    prov.full_responder = _full_major_response

    from packages.sca.llm.upgrade_impact_review import assess_upgrade_impact
    result = assess_upgrade_impact(
        client, _dep(), "3.0.0", target=tmp_path, changelog="...",
    )

    # Full ran and returned major_migration — that's the result.
    assert result.verdict == "major_migration"

    sc = ModelScorecard(client.config.scorecard_path)
    stat = sc.get_stat("sca:major_bump:PyPI", "haiku-stub")
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect == 1
    assert len(stat.disagreement_samples) == 1
    sample = stat.disagreement_samples[0]
    assert "patch bump" in sample["this_reasoning"]


def test_short_circuit_skips_full_when_cell_trusted(llm, tmp_path, monkeypatch):
    """Pre-seed scorecard with a trustworthy track record. Cheap
    claims clear_safe → full ANALYSE skipped, result reflects
    cheap reasoning."""
    client, prov = llm
    sc = ModelScorecard(client.config.scorecard_path)
    for _ in range(150):
        sc.record_event(
            "sca:major_bump:PyPI", "haiku-stub",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    client._scorecard = None        # force reload
    _patch_grep_to_return_call_sites(monkeypatch)
    prov.cheap_responder = _cheap_safe_response
    prov.full_responder = _full_major_response   # would NOT match if run

    from packages.sca.llm.upgrade_impact_review import assess_upgrade_impact
    result = assess_upgrade_impact(
        client, _dep(), "2.28.5", target=tmp_path, changelog="...",
    )

    assert prov.cheap_calls == 1
    assert prov.full_calls == 0, (
        f"expected full ANALYSE skipped, got {prov.full_calls}"
    )
    assert result.verdict == "safe"
    assert result.confidence == "medium"
    # The summary mentions the cheap reasoning so operators know
    # how the verdict was reached.
    assert "Fast-tier prefilter" in result.summary


def test_decision_class_is_ecosystem_keyed(llm, tmp_path, monkeypatch):
    """``decision_class = sca:major_bump:<ecosystem>``. Different
    ecosystems get separate cells — learning curves don't pool
    across PyPI / npm / Maven."""
    client, prov = llm
    _patch_grep_to_return_call_sites(monkeypatch)
    prov.cheap_responder = _cheap_safe_response
    prov.full_responder = _full_safe_response

    from packages.sca.llm.upgrade_impact_review import assess_upgrade_impact
    assess_upgrade_impact(
        client, _dep(ecosystem="PyPI"), "2.28.5",
        target=tmp_path, changelog="x",
    )
    assess_upgrade_impact(
        client, _dep(ecosystem="npm", name="lodash", version="4.0.0"),
        "4.0.5", target=tmp_path, changelog="x",
    )

    sc = ModelScorecard(client.config.scorecard_path)
    classes = {s.decision_class for s in sc.get_stats()}
    assert classes == {"sca:major_bump:PyPI", "sca:major_bump:npm"}


def test_cheap_says_needs_analysis_does_not_record(llm, tmp_path, monkeypatch):
    """cheap returns needs_analysis → no scorecard event is
    recorded. The gate's Wilson math only over confident-safe
    outcomes."""
    client, prov = llm
    _patch_grep_to_return_call_sites(monkeypatch)
    prov.cheap_responder = _cheap_needs_analysis_response
    prov.full_responder = _full_safe_response

    from packages.sca.llm.upgrade_impact_review import assess_upgrade_impact
    assess_upgrade_impact(
        client, _dep(), "3.0.0", target=tmp_path, changelog="breaking",
    )

    sc = ModelScorecard(client.config.scorecard_path)
    stat = sc.get_stat("sca:major_bump:PyPI", "haiku-stub")
    if stat is not None:
        ev = stat.events[EventType.CHEAP_SHORT_CIRCUIT]
        assert ev.correct == 0 and ev.incorrect == 0


def test_cheap_call_failure_falls_through(llm, tmp_path, monkeypatch):
    """If the cheap call fails, fall through to full as if no
    prefilter ran — the consumer must not raise."""
    client, prov = llm
    _patch_grep_to_return_call_sites(monkeypatch)
    def raise_cheap():
        raise RuntimeError("simulated cheap failure")
    prov.cheap_responder = raise_cheap
    prov.full_responder = _full_safe_response

    from packages.sca.llm.upgrade_impact_review import assess_upgrade_impact
    result = assess_upgrade_impact(
        client, _dep(), "2.28.5", target=tmp_path, changelog="x",
    )
    assert result is not None
    assert result.verdict == "safe"


def test_no_call_sites_skips_prefilter_path(llm, tmp_path, monkeypatch):
    """When grep finds no call sites, SCA already returns 'safe'
    early — no LLM calls at all. The prefilter must not break that
    fast-path optimisation."""
    client, prov = llm
    # Don't patch _grep_call_sites — leave it returning [] from
    # an empty target tree.
    prov.cheap_responder = _cheap_safe_response
    prov.full_responder = _full_safe_response

    from packages.sca.llm.upgrade_impact_review import assess_upgrade_impact
    result = assess_upgrade_impact(
        client, _dep(), "2.28.5", target=tmp_path, changelog="x",
    )
    assert result.verdict == "safe"
    assert prov.cheap_calls == 0
    assert prov.full_calls == 0
