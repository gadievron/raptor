"""Tests for reachability evidence surfacing in the analysis prompt (C1).

Pre-C1 the analysis prompt rendered only ``priority="high"`` from the
metadata. The reachability pre-pass enriches every checklist function
with priority/priority_reason/caller_count_*/direct_caller_names — all
invisible to the LLM analysis prompt that decides is_exploitable.

C1 surfaces this data:
  * NOT_CALLED (priority=low) becomes a "Verdict: NOT_CALLED" line.
  * REACHABLE-via-decorator (priority_reason=framework_callable) and
    REACHABLE-via-registration-call (priority_reason=
    registered_via_call) become explicit "Verdict: REACHABLE via X" lines.
  * Caller counts (direct/transitive/uncertain) become a summary line.
  * Direct caller names become a comma-separated list (capped at 10).

No verdict mutation; this is information-only. The matching system-
prompt section ("REACHABILITY ENGAGEMENT") tells the LLM how to
integrate the data into its is_exploitable reasoning.
"""

from __future__ import annotations

from packages.llm_analysis.prompts.analysis import (
    _format_metadata_for_block,
    _format_reachability_block,
)


# ---------------------------------------------------------------------------
# Verdict line surfaces priority + reason
# ---------------------------------------------------------------------------


class TestVerdictLine:
    def test_priority_low_renders_not_called(self):
        out = _format_reachability_block({
            "priority": "low",
            "priority_reason": "reachability:not_called",
        })
        assert "Verdict: NOT_CALLED" in out
        assert "reachability:not_called" in out

    def test_priority_low_default_reason(self):
        out = _format_reachability_block({"priority": "low"})
        assert "Verdict: NOT_CALLED" in out
        assert "no callers in project" in out

    def test_framework_callable_reason_renders_reachable(self):
        out = _format_reachability_block({
            "priority_reason": "reachability:framework_callable",
        })
        assert "Verdict: REACHABLE" in out
        assert "framework decorator dispatch" in out

    def test_registered_via_call_reason_renders_reachable(self):
        out = _format_reachability_block({
            "priority_reason": "reachability:registered_via_call",
        })
        assert "Verdict: REACHABLE" in out
        assert "registration call" in out
        assert "handler passed as argument" in out

    def test_no_priority_no_verdict_line(self):
        # Priority not set + no framework reason → no verdict line.
        # Caller counts may still render below.
        out = _format_reachability_block({})
        assert "Verdict" not in out

    def test_priority_high_does_not_render_verdict_line(self):
        # priority=high is the architectural-role signal already
        # rendered by _format_metadata_for_block — the reachability
        # block doesn't duplicate it as a verdict.
        out = _format_reachability_block({
            "priority": "high",
            "priority_reason": "entry_point",
        })
        assert "Verdict" not in out


# ---------------------------------------------------------------------------
# Caller graph summary
# ---------------------------------------------------------------------------


class TestCallerGraphSummary:
    def test_direct_only(self):
        out = _format_reachability_block({"caller_count_direct": 3})
        assert "Caller graph: 3 direct" in out

    def test_direct_and_transitive_different(self):
        out = _format_reachability_block({
            "caller_count_direct": 3,
            "caller_count_transitive": 12,
        })
        assert "3 direct" in out
        assert "12 transitive" in out

    def test_transitive_equal_to_direct_omits_transitive(self):
        # When transitive == direct, the function has no further-out
        # callers; rendering "3 direct, 3 transitive" is noise.
        out = _format_reachability_block({
            "caller_count_direct": 3,
            "caller_count_transitive": 3,
        })
        assert "3 direct" in out
        assert "transitive" not in out

    def test_uncertain_callers_rendered_with_explanation(self):
        out = _format_reachability_block({
            "caller_count_direct": 0,
            "caller_count_uncertain": 2,
        })
        assert "0 direct" in out
        assert "2 uncertain" in out
        assert "indirection" in out.lower()

    def test_zero_callers_renders(self):
        # Explicit "0 direct" is signal — must render, not be omitted.
        out = _format_reachability_block({"caller_count_direct": 0})
        assert "0 direct" in out

    def test_none_callers_omits_graph_line(self):
        # caller_count_direct=None (enricher didn't run) → no line.
        out = _format_reachability_block({})
        assert "Caller graph" not in out


# ---------------------------------------------------------------------------
# Direct caller names list
# ---------------------------------------------------------------------------


class TestDirectCallerNames:
    def test_renders_list(self):
        out = _format_reachability_block({
            "direct_caller_names": [
                "auth.py:handle_login",
                "api/users.py:create_user",
            ],
        })
        assert "auth.py:handle_login" in out
        assert "api/users.py:create_user" in out
        assert out.count("Direct callers:") == 1

    def test_caps_at_10_names_with_overflow_count(self):
        names = [f"f{i}.py:fn{i}" for i in range(15)]
        out = _format_reachability_block({"direct_caller_names": names})
        # First 10 appear; +5 more is summarised.
        for i in range(10):
            assert f"f{i}.py:fn{i}" in out
        assert "+5 more" in out
        # The 11th through 15th names are NOT in the output verbatim
        # — capped.
        for i in range(10, 15):
            assert f"f{i}.py:fn{i}" not in out

    def test_empty_names_list_omits_line(self):
        out = _format_reachability_block({"direct_caller_names": []})
        assert "Direct callers" not in out

    def test_missing_names_omits_line(self):
        out = _format_reachability_block({})
        assert "Direct callers" not in out


# ---------------------------------------------------------------------------
# Combined rendering (the realistic per-finding scenario)
# ---------------------------------------------------------------------------


class TestCombinedRendering:
    def test_dead_function_full_block(self):
        # A function the substrate marked NOT_CALLED.
        out = _format_reachability_block({
            "priority": "low",
            "priority_reason": "reachability:not_called",
            "caller_count_direct": 0,
            "caller_count_transitive": 0,
            "direct_caller_names": [],
        })
        assert out.startswith("Reachability:")
        assert "Verdict: NOT_CALLED" in out
        assert "0 direct" in out
        # Empty names list → no Direct callers line.
        assert "Direct callers" not in out

    def test_live_function_with_callers(self):
        out = _format_reachability_block({
            "caller_count_direct": 3,
            "caller_count_transitive": 12,
            "direct_caller_names": [
                "auth.py:handle_login",
                "api/users.py:create_user",
                "tests/test_auth.py:test_e2e",
            ],
        })
        assert "Verdict" not in out  # no priority signal set
        assert "3 direct" in out
        assert "12 transitive" in out
        assert "auth.py:handle_login" in out

    def test_framework_callable_with_zero_static_callers(self):
        # Flask-route shape: framework dispatches at runtime,
        # static graph has no callers. The C1 surfacing should
        # make BOTH facts visible to the LLM.
        out = _format_reachability_block({
            "priority_reason": "reachability:framework_callable",
            "caller_count_direct": 0,
            "caller_count_transitive": 0,
        })
        assert "Verdict: REACHABLE" in out
        assert "framework decorator dispatch" in out
        assert "0 direct" in out

    def test_no_signals_returns_empty(self):
        # Metadata with none of the reachability fields → empty
        # string (no "Reachability:" header emitted).
        out = _format_reachability_block({
            "class_name": "MyClass",
            "return_type": "int",
        })
        assert out == ""

    def test_integration_through_format_metadata_for_block(self):
        # End-to-end: the wrapper function appends the reachability
        # block to the existing metadata output, with the existing
        # fields preserved.
        out = _format_metadata_for_block({
            "class_name": "ApiRouter",
            "return_type": "Response",
            "priority": "low",
            "priority_reason": "reachability:not_called",
            "caller_count_direct": 0,
        })
        assert "Class: ApiRouter" in out
        assert "Return type: Response" in out
        assert "Reachability:" in out
        assert "Verdict: NOT_CALLED" in out
        assert "0 direct" in out
