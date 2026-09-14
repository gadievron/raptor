"""LLM-review taint-rule derivation and upward propagation tests for
:mod:`core.analysis.summaries`."""
from __future__ import annotations

from core.evidence import EvidenceTier

from core.analysis.summaries import (
    FunctionSummary,
    _sink_name_from_assumption,
    propagate_taint_upward,
    summary_from_review_result,
)


def _review_result_with_flow() -> dict:
    # Realistic review-schema shape: a ``function_reaches_sink``
    # precondition is the structured "THIS function passes
    # ``parameter`` to a dangerous API" claim.
    return {
        "status": "suspicious",
        "preconditions": [
            {
                "assumption": (
                    "parse_header passes buf to memcpy without a "
                    "bounds check"
                ),
                "check_type": "function_reaches_sink",
                "location": {"file": "src/proto.c",
                             "function": "parse_header"},
                "expect_absent": False,
                "parameter": "buf",
                # Propagation needs a CONCRETE index — an indexless
                # precondition defaults to -1 (unknown) and never
                # binds (see test_indexless_precondition_never_binds
                # _to_arg_zero).
                "param_index": 0,
            },
            {
                "assumption": "caller does not null-terminate buf",
                "check_type": "caller_null_terminates",
                "location": {"file": "src/handler.c",
                             "function": "handle_request"},
                "expect_absent": True,
                "parameter": "buf",
            },
        ],
    }


def test_reaches_sink_precondition_becomes_taint_rule():
    summary = summary_from_review_result(
        "parse_header", "src/proto.c", _review_result_with_flow(),
    )
    assert summary is not None
    assert len(summary.taint_rules) == 1
    rule = summary.taint_rules[0]
    assert rule.source_param == "buf"
    assert rule.sink_call == "memcpy"
    assert rule.evidence_tier == EvidenceTier.HEURISTIC
    # Caller-side assumptions (caller_null_terminates etc.) must NOT
    # mint taint rules — they are claims about the caller, not a
    # this-function param flow.
    assert all(r.sink_call == "memcpy" for r in summary.taint_rules)


def test_propagate_taint_upward_functions_on_llm_summaries():
    # The whole point of the derivation: an LLM callee summary now
    # carries taint_rules, so upward propagation produces inherited
    # rules instead of structurally returning [].
    callee = summary_from_review_result(
        "parse_header", "src/proto.c", _review_result_with_flow(),
    )
    assert callee is not None
    caller = FunctionSummary(function="handle_request", file="src/handler.c")
    inherited = propagate_taint_upward(
        callee, caller,
        [{"callee_index": 0, "caller_param": "user_input"}],
    )
    assert len(inherited) == 1
    assert inherited[0].source_param == "user_input"
    assert inherited[0].sink_call == "memcpy"
    assert inherited[0].hop_count == 1
    assert caller.taint_rules == inherited


def test_review_result_without_flow_claim_mints_no_taint_rule():
    # A review with only caller-side preconditions carries no
    # derivable this-function param-flow signal — no rule invented.
    rr = {
        "status": "suspicious",
        "preconditions": [
            {
                "assumption": "caller bounds-checks n before the call",
                "check_type": "caller_bounds_checks",
                "location": {"file": "a.c", "function": "caller"},
                "expect_absent": True,
                "parameter": "n",
            },
        ],
    }
    summary = summary_from_review_result("f", "a.c", rr)
    assert summary is not None
    assert summary.taint_rules == []


def test_sink_name_extraction_preference_order():
    # Known dangerous sink wins over the first call-shaped identifier.
    assert _sink_name_from_assumption(
        "wrapper(buf) forwards buf to system"
    ) == "system"
    # Call-shaped identifier when no known sink is named.
    assert _sink_name_from_assumption(
        "reaches custom_emit(dst, fmt) unchecked"
    ) == "custom_emit"
    # Stable fallback label when the prose names nothing concrete.
    assert _sink_name_from_assumption(
        "passes the value to a dangerous API"
    ) == "unspecified_sink"


def test_indexless_precondition_never_binds_to_arg_zero():
    """A review precondition with NO param_index must default to -1
    (unknown), matching the taint-rule branch. Defaulting to 0 minted
    a concrete index that _param_index_of "recovered" for the named
    param, so an inherited rule bound to whichever caller symbol
    feeds callee arg 0 — a fabricated flow in the reviewer prompt."""
    rr = {
        "preconditions": [
            {
                "parameter": "second",
                "assumption": "flows into memcpy",
                "check_type": "function_reaches_sink",
            },
        ],
    }
    callee = summary_from_review_result("callee_fn", "src/x.c", rr)
    assert callee is not None
    # The precondition record itself carries the unknown marker.
    assert all(p.param_index == -1 for p in callee.preconditions)
    caller = FunctionSummary(function="caller_fn", file="src/y.c")
    inherited = propagate_taint_upward(
        callee, caller,
        [{"callee_index": 0, "caller_param": "first_arg"}],
    )
    # Nothing pins ``second`` to index 0 — no inherited rule.
    assert inherited == []


def test_explicit_param_index_still_binds():
    rr = {
        "preconditions": [
            {
                "parameter": "buf",
                "assumption": "flows into memcpy",
                "check_type": "function_reaches_sink",
                "param_index": 0,
            },
        ],
    }
    callee = summary_from_review_result("callee_fn", "src/x.c", rr)
    assert callee is not None
    caller = FunctionSummary(function="caller_fn", file="src/y.c")
    inherited = propagate_taint_upward(
        callee, caller,
        [{"callee_index": 0, "caller_param": "user_input"}],
    )
    assert len(inherited) == 1
    assert inherited[0].source_param == "user_input"
