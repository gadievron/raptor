"""Tests for core.analysis.reachability_gates — generic finding gates."""

import sys
from pathlib import Path

# core/inventory/tests/ → repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.analysis.reachability_gates import (
    build_sink_reachable_set,
    compute_demotion_verdict,
    has_safety_self_contradiction,
    is_conduit_candidate,
    is_entry_unreachable,
    query_sink_arg_index,
    query_unguarded_sinks,
)


# ─── build_sink_reachable_set ────────────────────────────────────────────────


class TestBuildSinkReachableSet:
    def test_none_context_map(self):
        assert build_sink_reachable_set(None) is None

    def test_no_call_edges(self):
        assert build_sink_reachable_set({"sinks": [{"function": "f"}]}) is None

    def test_transitive_reach(self):
        cm = {
            "sinks": [{"function": "dangerous_handler"}],
            "call_edges": [
                {"caller": "main", "callee": "parse"},
                {"caller": "parse", "callee": "dangerous_handler"},
            ],
        }
        reachable = build_sink_reachable_set(cm)
        assert "main" in reachable
        assert "parse" in reachable
        assert "dangerous_handler" in reachable

    def test_libc_sinks_auto_seeded(self):
        cm = {
            "sinks": [],
            "call_edges": [
                {"caller": "copy_data", "callee": "memcpy"},
                {"caller": "main", "callee": "copy_data"},
            ],
        }
        reachable = build_sink_reachable_set(cm)
        assert "memcpy" in reachable
        assert "copy_data" in reachable
        assert "main" in reachable

    def test_unreachable_function(self):
        cm = {
            "sinks": [{"function": "sink"}],
            "call_edges": [
                {"caller": "caller_a", "callee": "sink"},
                {"caller": "isolated", "callee": "helper"},
            ],
        }
        reachable = build_sink_reachable_set(cm)
        assert "caller_a" in reachable
        assert "isolated" not in reachable


# ─── is_entry_unreachable ────────────────────────────────────────────────────


class TestIsEntryUnreachable:
    def test_no_context_map(self):
        assert is_entry_unreachable("f", None) is False

    def test_no_call_edges(self):
        assert is_entry_unreachable("f", {"entry_points": []}) is False

    def test_entry_point_not_unreachable(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [{"caller": "main", "callee": "parse"}],
        }
        assert is_entry_unreachable("main", cm) is False

    def test_called_function_not_unreachable(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [{"caller": "main", "callee": "parse"}],
        }
        assert is_entry_unreachable("parse", cm) is False

    def test_orphan_function_is_unreachable(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [{"caller": "main", "callee": "parse"}],
        }
        assert is_entry_unreachable("orphan_fn", cm) is True

    def test_no_entry_points_never_unreachable(self):
        cm = {
            "entry_points": [],
            "call_edges": [{"caller": "a", "callee": "b"}],
        }
        assert is_entry_unreachable("orphan_fn", cm) is False


# ─── is_conduit_candidate ────────────────────────────────────────────────────


class TestIsConduitCandidate:
    def test_mentions_dangerous_call(self):
        assert is_conduit_candidate("passes input to strcpy( dest, src)") is True

    def test_mentions_memcpy_call(self):
        assert is_conduit_candidate("calls memcpy(dst, src, n) without bounds") is True

    def test_conduit_phrase(self):
        assert is_conduit_candidate("forwards data to the downstream handler") is True

    def test_local_logic_bug(self):
        assert is_conduit_candidate(
            "off-by-one in null terminator write at dst[di]"
        ) is False

    def test_word_execution_not_matched(self):
        assert is_conduit_candidate(
            "leads to arbitrary code execution via buffer overflow"
        ) is False

    def test_word_query_not_matched(self):
        assert is_conduit_candidate(
            "decodes URL-encoded query string characters"
        ) is False


# ─── compute_demotion_verdict ────────────────────────────────────────────────


class TestComputeDemotionVerdict:
    def test_entry_unreachable_fires_first(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [{"caller": "main", "callee": "parse"}],
        }
        verdict = compute_demotion_verdict("orphan", "calls strcpy(", cm)
        assert verdict is not None
        assert "entry-unreachability" in verdict

    def test_no_demotion_for_reachable_function(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [
                {"caller": "main", "callee": "parse"},
                {"caller": "parse", "callee": "memcpy"},
            ],
            "sinks": [{"function": "memcpy"}],
        }
        verdict = compute_demotion_verdict("parse", "local logic bug", cm)
        assert verdict is None

    def test_self_contradiction_fires(self):
        cm = {
            "entry_points": [{"name": "banner"}],
            "call_edges": [
                {"caller": "banner", "callee": "memcpy"},
            ],
            "sinks": [{"function": "memcpy"}],
        }
        verdict = compute_demotion_verdict(
            "banner",
            "copies a fixed-size static string into a caller-provided buffer",
            cm,
        )
        assert verdict is not None
        assert "self-contradiction" in verdict

    def test_sink_unreachable_conduit(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [
                {"caller": "main", "callee": "wrapper"},
                {"caller": "handler", "callee": "memcpy"},
            ],
            "sinks": [{"function": "memcpy"}],
        }
        verdict = compute_demotion_verdict(
            "wrapper", "passes input to strcpy( dest, src)", cm,
        )
        assert verdict is not None
        assert "sink-unreachability" in verdict


# ─── has_safety_self_contradiction ──────────────────────────────────────────


class TestHasSafetySelfContradiction:
    def test_fixed_size_static_string(self):
        body = "copies a fixed-size static string kBanner into a caller buffer"
        assert has_safety_self_contradiction(body) is True

    def test_saturating_arithmetic(self):
        body = "implements saturating subtraction, correctly returning zero"
        assert has_safety_self_contradiction(body) is True

    def test_correctly_bounded(self):
        body = "the function correctly bounded the output to MAX_LEN bytes"
        assert has_safety_self_contradiction(body) is True

    def test_cannot_overflow(self):
        body = "the copy size is capped so it cannot overflow the destination"
        assert has_safety_self_contradiction(body) is True

    def test_hypothetical_caller_violation(self):
        body = "if a caller violates this contract and provides a smaller buffer"
        assert has_safety_self_contradiction(body) is True

    def test_hypothetical_caller_provides(self):
        body = "if a caller provides a buffer smaller than N, overflow occurs"
        assert has_safety_self_contradiction(body) is True

    def test_real_bug_no_bounds(self):
        body = "does not check output bounds, allowing overflow"
        assert has_safety_self_contradiction(body) is False

    def test_real_bug_format_string(self):
        body = "attacker-controlled path in format string passed to snprintf"
        assert has_safety_self_contradiction(body) is False

    def test_real_bug_fixed_size_buffer(self):
        body = "strcpy overflows the fixed-size stack buffer"
        assert has_safety_self_contradiction(body) is False

    def test_negation_not_correctly(self):
        body = "the function does not correctly implement bounds checking"
        assert has_safety_self_contradiction(body) is False

    def test_negation_however_before(self):
        body = "However, the function correctly handles input validation"
        assert has_safety_self_contradiction(body) is False

    def test_negation_fails_to(self):
        body = "The function fails to correctly validate the input length"
        assert has_safety_self_contradiction(body) is False

    def test_negation_without_bounded(self):
        body = "without correctly bounded checks on the size parameter"
        assert has_safety_self_contradiction(body) is False

    def test_specific_caller_not_hypothetical(self):
        body = "The caller handle_connection provides untrusted data directly"
        assert has_safety_self_contradiction(body) is False

    def test_correctly_handles_is_not_safety_assertion(self):
        body = "The function correctly handles content-type but path is not normalized before fopen"
        assert has_safety_self_contradiction(body) is False

    def test_properly_validates_is_not_safety_assertion(self):
        body = "The function properly validates using normalize_path but this happens after fopen"
        assert has_safety_self_contradiction(body) is False

    def test_correctly_implements_is_not_safety_assertion(self):
        body = "The function correctly implements response formatting but the path is attacker-controlled"
        assert has_safety_self_contradiction(body) is False


# ─── Joern caller override for entry-unreachability ─────────────────────────


class _FakeJoernServer:
    """Minimal stub for JoernServer that returns controlled query results."""

    def __init__(self, raw_output="", errors=None, alive=True):
        self._raw_output = raw_output
        self._errors = errors or []
        self._alive = alive

    def is_alive(self):
        return self._alive

    def query(self, cpgql, *, timeout=30, validate=False):
        class _Result:
            pass
        r = _Result()
        r.raw_output = self._raw_output
        r.errors = self._errors
        return r


class TestEntryUnreachableJoernOverride:
    """Joern caller query prevents false entry-unreachability demotions."""

    _cm = {
        "entry_points": [{"name": "main"}],
        "call_edges": [{"caller": "main", "callee": "parse"}],
    }

    def test_unreachable_without_joern(self):
        assert is_entry_unreachable("orphan", self._cm) is True

    def test_joern_callers_override_unreachability(self):
        stdout = 'JOERN_CALLER:{"caller":"dispatch","file":"src/dispatch.c","line":42,"code":"orphan(buf)"}'
        server = _FakeJoernServer(raw_output=stdout)
        assert is_entry_unreachable("orphan", self._cm, joern_server=server) is False

    def test_joern_no_callers_stays_unreachable(self):
        server = _FakeJoernServer(raw_output="")
        assert is_entry_unreachable("orphan", self._cm, joern_server=server) is True

    def test_joern_error_stays_unreachable(self):
        server = _FakeJoernServer(raw_output="", errors=["timeout"])
        assert is_entry_unreachable("orphan", self._cm, joern_server=server) is True

    def test_joern_dead_server_stays_unreachable(self):
        server = _FakeJoernServer(alive=False)
        assert is_entry_unreachable("orphan", self._cm, joern_server=server) is True


# ─── query_unguarded_sinks ──────────────────────────────────────────────────


class TestQueryUnguardedSinks:
    def test_none_server(self):
        assert query_unguarded_sinks("fn", None) == []

    def test_dead_server(self):
        server = _FakeJoernServer(alive=False)
        assert query_unguarded_sinks("fn", server) == []

    def test_invalid_function_name(self):
        server = _FakeJoernServer()
        assert query_unguarded_sinks("fn; rm -rf", server) == []


class TestQuerySinkArgIndex:
    def test_none_server(self):
        assert query_sink_arg_index("fn", "memcpy", None) == []

    def test_dead_server(self):
        server = _FakeJoernServer(alive=False)
        assert query_sink_arg_index("fn", "memcpy", server) == []

    def test_invalid_sink_name(self):
        server = _FakeJoernServer()
        assert query_sink_arg_index("fn", "sink; bad", server) == []
