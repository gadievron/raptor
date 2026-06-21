"""ResultMessage.usage is cumulative — merge it, don't add it (2026-06-14).

Bug (trace br-token-double-count; independent + SDK-source judge): the loop
accumulates tokens into state.total_*_tokens from BOTH AssistantMessage.usage
(per-message, loop.py:1624) AND ResultMessage.usage (loop.py:1973). But
ResultMessage.usage is the session AGGREGATE (SDK types.py:768 "Cumulative API
usage for the session"), so summing both double-counts (~2x, worse on
multi-ResultMessage retry storms). Benign for cost under session auth (the token
estimate never wins _floor_cost's max()), but it inflates token telemetry and
would over-report ~2x under API-key auth. Fix: merge the cumulative RM usage via
max(), not +=, preserving the per-message AssistantMessage accumulation (which
also covers give_up runs that never reach a terminal ResultMessage).
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

import pytest

from cve_env.agent.loop import _accum_tokens, _merge_cumulative_tokens, _StreamState

def test_result_message_usage_does_not_double_count() -> None:
    """AM accumulated 10/2 per-message, then a CUMULATIVE RM reports 100/20
    (the session total, which already includes those AM tokens). The running
    total must become the cumulative 100/20, NOT 110/22 (the double-count)."""
    st = _StreamState()
    _accum_tokens(st, {"input_tokens": 10, "output_tokens": 2})  # AM per-message
    _merge_cumulative_tokens(
        st, {"input_tokens": 100, "output_tokens": 20}
    )  # RM cumulative
    assert st.total_input_tokens == 100, st.total_input_tokens
    assert st.total_output_tokens == 20, st.total_output_tokens

def test_merge_never_lowers_the_running_total() -> None:
    """A cumulative value below the running per-message sum (shouldn't happen,
    but defensive) must not lower the total — max() floor."""
    st = _StreamState()
    _accum_tokens(st, {"input_tokens": 50, "output_tokens": 10})
    _merge_cumulative_tokens(st, {"input_tokens": 5, "output_tokens": 1})
    assert st.total_input_tokens == 50
    assert st.total_output_tokens == 10

def test_merge_handles_object_and_none_usage() -> None:
    """Object-shaped usage (.input_tokens attrs) and None are both handled."""
    import types

    st = _StreamState()
    _merge_cumulative_tokens(st, None)  # no-op
    assert st.total_input_tokens == 0
    _merge_cumulative_tokens(
        st, types.SimpleNamespace(input_tokens=42, output_tokens=7)
    )
    assert st.total_input_tokens == 42
    assert st.total_output_tokens == 7

def test_give_up_run_keeps_per_message_tokens() -> None:
    """A give_up run (AM accumulation, no terminal ResultMessage) keeps its
    per-message token sum — the AM += path is unchanged and still the fallback."""
    st = _StreamState()
    _accum_tokens(st, {"input_tokens": 10, "output_tokens": 2})
    _accum_tokens(st, {"input_tokens": 10, "output_tokens": 2})
    assert st.total_input_tokens == 20
    assert st.total_output_tokens == 4
