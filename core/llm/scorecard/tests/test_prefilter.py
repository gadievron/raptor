"""Tests for the consumer-facing prefilter helpers
(:mod:`core.llm.scorecard.prefilter`).

These verify the small-but-load-bearing glue every consumer uses:
``prefilter_decision`` and ``record_prefilter_outcome``. The
substrate's ``ModelScorecard`` is exercised separately.
"""

from __future__ import annotations

from core.llm.scorecard import (
    EventType,
    ModelScorecard,
    Policy,
    fast_tier_model_name,
    prefilter_decision,
    record_prefilter_outcome,
    run_cheap_fp_check,
)

# ---------------------------------------------------------------------------
# prefilter_decision
# ---------------------------------------------------------------------------


def test_cheap_did_not_claim_fp_never_short_circuits(tmp_path):
    """``cheap_says_fp=False`` → fall through, regardless of how
    trustworthy the cell is. Without this rule, a cheap model that
    said 'needs analysis' would somehow trigger short-circuit just
    because the cell is trusted in general — which would silently
    skip the analysis the cheap model explicitly asked for."""
    sc = ModelScorecard(tmp_path / "sc.json")
    # Build a cell with strong trust track record.
    for _ in range(200):
        sc.record_event(
            "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    decision = prefilter_decision(
        sc, decision_class="x:y", model="m", cheap_says_fp=False,
    )
    assert decision.short_circuit is False


def test_cheap_says_fp_with_trusted_cell_short_circuits(tmp_path):
    sc = ModelScorecard(tmp_path / "sc.json")
    for _ in range(200):
        sc.record_event(
            "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    decision = prefilter_decision(
        sc, decision_class="x:y", model="m", cheap_says_fp=True,
    )
    assert decision.short_circuit is True
    assert decision.policy == Policy.SHORT_CIRCUIT


def test_cheap_says_fp_in_learning_falls_through(tmp_path):
    """In learning mode we always run full analysis even when cheap
    claims FP — the goal is to accumulate ground-truth comparison
    data."""
    sc = ModelScorecard(tmp_path / "sc.json")
    decision = prefilter_decision(
        sc, decision_class="x:y", model="m", cheap_says_fp=True,
    )
    assert decision.short_circuit is False
    assert decision.policy == Policy.LEARNING


def test_no_scorecard_falls_through(tmp_path):
    """When the operator opted out (``LLMConfig.scorecard_enabled=False``)
    the scorecard is None and we never short-circuit."""
    decision = prefilter_decision(
        None, decision_class="x:y", model="m", cheap_says_fp=True,
    )
    assert decision.short_circuit is False


# ---------------------------------------------------------------------------
# record_prefilter_outcome
# ---------------------------------------------------------------------------


def test_records_correct_when_cheap_and_full_agree(tmp_path):
    sc = ModelScorecard(tmp_path / "sc.json")
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=True, full_says_fp=True,
        cheap_reasoning="not exploitable",
        full_reasoning="agree, not exploitable",
    )
    stat = sc.get_stat("x:y", "m")
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].correct == 1
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect == 0


def test_records_incorrect_with_sample_when_cheap_was_wrong(tmp_path):
    """When cheap said FP but full said TP, the cell records an
    incorrect outcome AND the disagreement sample for the operator
    to read later."""
    sc = ModelScorecard(tmp_path / "sc.json")
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=True, full_says_fp=False,
        cheap_reasoning="cheap thought it was hardcoded",
        full_reasoning="full found user-tainted source via helper",
    )
    stat = sc.get_stat("x:y", "m")
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect == 1
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].correct == 0
    assert len(stat.disagreement_samples) == 1
    assert "hardcoded" in stat.disagreement_samples[0]["this_reasoning"]
    assert "user-tainted" in stat.disagreement_samples[0]["other_reasoning"]


def test_no_record_when_cheap_did_not_claim_fp(tmp_path):
    """Records only when cheap claimed FP — those are the only events
    that feed the short-circuit gate. A cheap "needs_analysis" verdict
    paired with a full TP/FP carries no signal for the gate."""
    sc = ModelScorecard(tmp_path / "sc.json")
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=False, full_says_fp=True,
        cheap_reasoning="needs analysis",
    )
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=False, full_says_fp=False,
        cheap_reasoning="needs analysis",
    )
    assert sc.get_stat("x:y", "m") is None


def test_no_record_when_scorecard_is_none(tmp_path):
    """Operator opted out — record_prefilter_outcome is a no-op."""
    record_prefilter_outcome(
        None, decision_class="x:y", model="m",
        cheap_says_fp=True, full_says_fp=False,
    )
    # Just shouldn't raise.


def test_reasoning_text_is_truncated(tmp_path):
    """Long reasoning is capped at 500 chars to bound on-disk
    storage and avoid large code snippets ending up persisted."""
    sc = ModelScorecard(tmp_path / "sc.json")
    long_text = "X" * 5000
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=True, full_says_fp=False,
        cheap_reasoning=long_text,
        full_reasoning=long_text,
    )
    stat = sc.get_stat("x:y", "m")
    assert len(stat.disagreement_samples[0]["this_reasoning"]) == 500
    assert len(stat.disagreement_samples[0]["other_reasoning"]) == 500


# ---------------------------------------------------------------------------
# fast_tier_model_name
# ---------------------------------------------------------------------------


class _Model:
    def __init__(self, name, enabled=True):
        self.model_name = name
        self.enabled = enabled


class _Cfg:
    def __init__(self, specialized=None, primary=None):
        from core.llm.task_types import TaskType
        self.specialized_models = (
            {TaskType.VERDICT_BINARY: specialized} if specialized else {}
        )
        self.primary_model = primary


def test_fast_tier_prefers_enabled_specialized_model():
    cfg = _Cfg(specialized=_Model("fast"), primary=_Model("big"))
    assert fast_tier_model_name(cfg) == "fast"


def test_fast_tier_skips_disabled_specialized_model():
    cfg = _Cfg(specialized=_Model("fast", enabled=False),
               primary=_Model("big"))
    assert fast_tier_model_name(cfg) == "big"


def test_fast_tier_falls_back_to_primary_then_empty():
    assert fast_tier_model_name(_Cfg(primary=_Model("big"))) == "big"
    assert fast_tier_model_name(_Cfg()) == ""


# ---------------------------------------------------------------------------
# run_cheap_fp_check
# ---------------------------------------------------------------------------


class _StubClient:
    """Client-level stub capturing the structured call."""

    def __init__(self, result=None, raise_exc=None):
        self._result = result
        self._raise = raise_exc
        self.calls = []

    def generate_structured(self, *, prompt, schema, system_prompt=None,
                            task_type=None, **kwargs):
        self.calls.append({
            "prompt": prompt, "schema": schema,
            "system_prompt": system_prompt, "task_type": task_type,
        })
        if self._raise is not None:
            raise self._raise
        return (self._result, "raw")  # stub-tuple shape; helper unwraps


_SCHEMA = {"reasoning": "string", "verdict": {"enum": ["clear_fp",
                                                       "needs_analysis"]}}


def test_run_cheap_fp_check_returns_verdict_and_reasoning():
    client = _StubClient(result={"verdict": "Clear_FP",
                                 "reasoning": "hardcoded"})
    out = run_cheap_fp_check(client, system="sys text", schema=_SCHEMA)
    assert out == ("clear_fp", "hardcoded")
    # The call went through the VERDICT_BINARY fast tier with the
    # envelope's role-separated messages.
    from core.llm.task_types import TaskType
    call = client.calls[0]
    assert call["task_type"] == TaskType.VERDICT_BINARY
    assert "sys text" in call["system_prompt"]


def test_run_cheap_fp_check_wraps_untrusted_content_in_envelope():
    from core.security.prompt_envelope import TaintedString, UntrustedBlock
    client = _StubClient(result={"verdict": "needs_analysis",
                                 "reasoning": ""})
    run_cheap_fp_check(
        client, system="s", schema=_SCHEMA,
        untrusted_blocks=[UntrustedBlock(
            content="EVIL CODE", kind="vulnerable-code", origin="a.c:1")],
        slots={"rule_id": TaintedString(value="cpp/x", trust="untrusted")},
    )
    prompt = client.calls[0]["prompt"]
    assert "EVIL CODE" in prompt
    assert "cpp/x" in prompt


def test_run_cheap_fp_check_call_failure_is_no_signal():
    client = _StubClient(raise_exc=RuntimeError("provider down"))
    assert run_cheap_fp_check(client, system="s", schema=_SCHEMA) is None


def test_run_cheap_fp_check_unexpected_verdict_is_no_signal():
    client = _StubClient(result={"verdict": "definitely_exploit_it",
                                 "reasoning": "x"})
    assert run_cheap_fp_check(client, system="s", schema=_SCHEMA) is None


def test_run_cheap_fp_check_custom_verdict_literals():
    """SCA-style consumers use clear_safe/needs_analysis literals."""
    client = _StubClient(result={"verdict": "clear_safe", "reasoning": "ok"})
    out = run_cheap_fp_check(
        client, system="s", schema=_SCHEMA,
        allowed_verdicts=("clear_safe", "needs_analysis"),
    )
    assert out == ("clear_safe", "ok")
    # And clear_fp is now out-of-set for that consumer.
    client2 = _StubClient(result={"verdict": "clear_fp", "reasoning": "x"})
    assert run_cheap_fp_check(
        client2, system="s", schema=_SCHEMA,
        allowed_verdicts=("clear_safe", "needs_analysis"),
    ) is None
