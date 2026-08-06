"""Phase 43.1.5 (2026-05-16): coverage gap closure for `_accum_tokens`.

Per Phase 42.5 coverage report — MED-risk no-test gap on B-19's token
accumulator at `src/cve_env/agent/loop.py:477`.

Function accumulates input/output tokens onto `_StreamState` from the
SDK's `usage` field, which can be:
  * None / falsy → no-op
  * dict (some SDK versions)
  * object with attributes (other SDK versions)

Outcome construction uses ``max(last_cost_usd, run.total_cost_usd,
estimate_from_tokens(state.total_input_tokens, state.total_output_tokens, model))``
so this accumulator is load-bearing when SDK reports cost=0 despite real
LLM rounds (observed on max_turns_reached + end_turn-after-give_up paths).

Tests cover:
- None / falsy usage → no-op
- dict variant (input + output keys present)
- dict missing keys → 0 added (defensive .get(..., 0))
- dict with None values → coerced to 0 (`or 0` predicate)
- object variant (getattr)
- object missing attrs → 0 added (getattr default)
- Multiple calls accumulate (cumulative semantics)

Location: src/cve_env/agent/loop.py:477-491.
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

from types import SimpleNamespace

from cve_env.agent.loop import _accum_tokens, _StreamState

def test_accum_none_usage_is_noop() -> None:
    """usage=None → no-op (falsy short-circuit at line 484)."""
    state = _StreamState()
    _accum_tokens(state, None)
    assert state.total_input_tokens == 0
    assert state.total_output_tokens == 0

def test_accum_empty_dict_is_noop() -> None:
    """Empty dict is falsy in Python → no-op (short-circuit)."""
    state = _StreamState()
    _accum_tokens(state, {})
    assert state.total_input_tokens == 0
    assert state.total_output_tokens == 0

def test_accum_dict_with_both_keys() -> None:
    """Standard dict usage from SDK ResultMessage."""
    state = _StreamState()
    _accum_tokens(state, {"input_tokens": 1500, "output_tokens": 250})
    assert state.total_input_tokens == 1500
    assert state.total_output_tokens == 250

def test_accum_dict_missing_input_tokens_key() -> None:
    """Missing input_tokens → .get(..., 0) returns 0; output added normally."""
    state = _StreamState()
    _accum_tokens(state, {"output_tokens": 500})
    assert state.total_input_tokens == 0
    assert state.total_output_tokens == 500

def test_accum_dict_missing_output_tokens_key() -> None:
    """Missing output_tokens → 0 added; input added normally."""
    state = _StreamState()
    _accum_tokens(state, {"input_tokens": 1000})
    assert state.total_input_tokens == 1000
    assert state.total_output_tokens == 0

def test_accum_dict_none_values_coerced_to_zero() -> None:
    """`(value or 0)` predicate at lines 487-488 maps None → 0 (defensive
    against SDK emitting null fields)."""
    state = _StreamState()
    _accum_tokens(state, {"input_tokens": None, "output_tokens": None})
    assert state.total_input_tokens == 0
    assert state.total_output_tokens == 0

def test_accum_object_with_attrs() -> None:
    """SDK may emit usage as an object (claude_agent_sdk types). Uses
    getattr at lines 490-491."""
    usage = SimpleNamespace(input_tokens=2000, output_tokens=400)
    state = _StreamState()
    _accum_tokens(state, usage)
    assert state.total_input_tokens == 2000
    assert state.total_output_tokens == 400

def test_accum_object_missing_attrs() -> None:
    """getattr(..., 0) default → 0 added for missing attrs."""
    usage = SimpleNamespace()  # no input_tokens, no output_tokens
    state = _StreamState()
    _accum_tokens(state, usage)
    assert state.total_input_tokens == 0
    assert state.total_output_tokens == 0

def test_accum_object_with_none_attr() -> None:
    """Object with attr=None → `or 0` coerces to 0."""
    usage = SimpleNamespace(input_tokens=None, output_tokens=None)
    state = _StreamState()
    _accum_tokens(state, usage)
    assert state.total_input_tokens == 0
    assert state.total_output_tokens == 0

def test_accum_is_cumulative_across_calls() -> None:
    """Successive calls accumulate; not replace. Critical for the
    multi-AssistantMessage / multi-ResultMessage flow."""
    state = _StreamState()
    _accum_tokens(state, {"input_tokens": 100, "output_tokens": 10})
    _accum_tokens(state, {"input_tokens": 200, "output_tokens": 20})
    _accum_tokens(state, {"input_tokens": 50, "output_tokens": 5})
    assert state.total_input_tokens == 350
    assert state.total_output_tokens == 35

def test_accum_mixed_dict_and_object() -> None:
    """Real runs interleave dict-shaped (AssistantMessage.usage) and
    object-shaped (ResultMessage.usage) values. Both branches accumulate
    into the same state."""
    state = _StreamState()
    _accum_tokens(state, {"input_tokens": 100, "output_tokens": 10})
    _accum_tokens(state, SimpleNamespace(input_tokens=300, output_tokens=30))
    assert state.total_input_tokens == 400
    assert state.total_output_tokens == 40

def test_accum_int_coercion_handles_floats() -> None:
    """The int() cast at lines 487-491 handles float inputs (defensive).
    A misbehaving SDK reporting 1500.7 tokens shouldn't crash; should
    truncate to 1500."""
    state = _StreamState()
    _accum_tokens(state, {"input_tokens": 1500.7, "output_tokens": 250.9})
    assert state.total_input_tokens == 1500
    assert state.total_output_tokens == 250
