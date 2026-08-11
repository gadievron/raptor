"""Tests for core.audit.refutation — early refutation gates."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from core.audit.refutation import (
    _classify_lifecycle,
    _extract_all_cwes,
    _extract_cwe,
    _get_calls,
    _refute_by_architecture,
    _refute_by_contract,
    _refute_by_known_return_type,
    _refute_by_lifecycle,
    _signal_reachable_set,
    refute_hypothesis,
)


# ---------------------------------------------------------------------------
# Minimal ReviewOutcome stand-in (avoids importing orchestrator)
# ---------------------------------------------------------------------------


@dataclass
class _Outcome:
    file: str = "src/net.c"
    function: str = "handle_packet"
    status: str = "finding"
    body: str = ""
    hypothesis: str = ""
    evidence_tool: str = ""
    review_result: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Minimal OrchestratorConfig stand-in
# ---------------------------------------------------------------------------


@dataclass
class _Config:
    target_path: Path = field(default_factory=lambda: Path("/nonexistent"))
    out_dir: Path = field(default_factory=lambda: Path("/nonexistent"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _checklist_with_calls(calls: list, path: str = "src/main.c") -> dict:
    """Build a minimal checklist with a call graph."""
    return {
        "files": [
            {
                "path": path,
                "items": [],
                "call_graph": {"calls": calls},
            },
        ],
    }


def _domain_model(
    *,
    overview: str = "",
    contracts: list | None = None,
    architecture: dict | None = None,
) -> dict:
    dm: dict = {"overview_summary": overview}
    if contracts is not None:
        dm["contracts"] = contracts
    if architecture is not None:
        dm["architecture"] = architecture
    return dm


# ===================================================================
# Gate 1: Architecture model
# ===================================================================


class TestRefuteByArchitecture:
    """Gate 1: CWE-362 in single-threaded targets."""

    def test_race_in_single_threaded_refuted(self):
        """Race hypothesis in single-threaded target → refuted."""
        outcome = _Outcome(
            hypothesis="data race in newaddress concurrent modification",
        )
        dm = _domain_model(
            architecture={"threading_model": "single_threaded"},
        )
        r = _refute_by_architecture(outcome, dm, None, _Config())
        assert r is not None
        assert r.gate == "architecture"
        assert r.demote_to == "clean"
        assert "single-threaded" in r.reason

    def test_cwe_with_description_refuted(self):
        """CWE-362 with description text still triggers the gate."""
        outcome = _Outcome(
            review_result={
                "cwe": "CWE-362: Concurrent Execution using Shared "
                       "Resource with Improper Synchronization",
            },
            hypothesis="race on refcount",
        )
        dm = _domain_model(
            architecture={"threading_model": "single_threaded"},
        )
        r = _refute_by_architecture(outcome, dm, None, _Config())
        assert r is not None
        assert r.gate == "architecture"

    def test_multi_cwe_with_362_refuted(self):
        """Multi-CWE string containing CWE-362 still triggers."""
        outcome = _Outcome(
            review_result={
                "cwe": "CWE-476: Null Pointer Dereference; "
                       "CWE-362: Race Condition",
            },
            hypothesis="concurrent access",
        )
        dm = _domain_model(
            architecture={"threading_model": "single_threaded"},
        )
        r = _refute_by_architecture(outcome, dm, None, _Config())
        assert r is not None
        assert r.gate == "architecture"
        assert "CWE-362" in r.reason

    def test_non_race_cwe_passes(self):
        """Non-race CWE → not refuted even if single-threaded."""
        outcome = _Outcome(
            hypothesis="buffer overflow in parse_input",
        )
        dm = _domain_model(overview="single-threaded event loop")
        r = _refute_by_architecture(outcome, dm, None, _Config())
        assert r is None

    def test_multi_threaded_passes(self):
        """Race hypothesis in multi-threaded target → not refuted."""
        outcome = _Outcome(
            hypothesis="data race in shared_counter concurrent write",
        )
        dm = _domain_model(
            architecture={"threading_model": "multi_threaded"},
        )
        r = _refute_by_architecture(outcome, dm, None, _Config())
        assert r is None

    def test_signal_handler_exception(self):
        """Function reachable from signal handler → not refuted."""
        outcome = _Outcome(
            function="cleanup",
            hypothesis="data race between main loop and signal handler",
        )
        dm = _domain_model(overview="single-threaded event loop")
        # Build a checklist where cleanup is reachable from sig_handler
        checklist = _checklist_with_calls([
            {"line": 10, "chain": ["signal", "sig_handler"], "caller": "main"},
            {"line": 20, "chain": ["cleanup"], "caller": "sig_handler"},
        ])
        # Also add sig_handler as an item so it has a file mapping
        checklist["files"][0]["items"] = [
            {"name": "sig_handler"},
            {"name": "cleanup"},
        ]
        r = _refute_by_architecture(outcome, dm, checklist, _Config())
        assert r is None

    def test_no_domain_model_passes(self):
        """No domain model → can't determine threading → passes."""
        outcome = _Outcome(
            hypothesis="data race in shared state",
        )
        r = _refute_by_architecture(outcome, None, None, _Config())
        assert r is None

    def test_architecture_block_threading(self):
        """Structured architecture.threading_model field works."""
        outcome = _Outcome(
            hypothesis="race condition on shared counter without lock",
        )
        dm = _domain_model(
            architecture={"threading_model": "single_threaded"},
        )
        r = _refute_by_architecture(outcome, dm, None, _Config())
        assert r is not None
        assert r.demote_to == "clean"


# ===================================================================
# Gate 2: Lifecycle phase
# ===================================================================


class TestRefuteByLifecycle:
    """Gate 2: resource leaks in init-only functions."""

    def _init_checklist(self):
        """Checklist where dbus_init is called only before the event loop."""
        return _checklist_with_calls([
            {"line": 50, "chain": ["dbus_init"], "caller": "main"},
            {"line": 200, "chain": ["do_poll"], "caller": "main"},
            {"line": 300, "chain": ["handle_query"], "caller": "main"},
        ])

    def test_leak_in_init_refuted(self):
        """Resource leak in init-only function → refuted."""
        outcome = _Outcome(
            function="dbus_init",
            hypothesis="dbus_init leaking DBusConnection reference on error",
        )
        r = _refute_by_lifecycle(outcome, self._init_checklist())
        assert r is not None
        assert r.gate == "lifecycle"
        assert r.demote_to == "clean"
        assert "init-only" in r.reason

    def test_leak_keyword_unref(self):
        """Keyword 'unref' triggers the gate."""
        outcome = _Outcome(
            function="dbus_init",
            hypothesis="returns without calling dbus_connection_unref",
        )
        r = _refute_by_lifecycle(outcome, self._init_checklist())
        assert r is not None
        assert r.gate == "lifecycle"

    def test_leak_in_request_passes(self):
        """Resource leak in request-path function → not refuted."""
        outcome = _Outcome(
            function="handle_query",
            hypothesis="handle_query leaks memory on error path",
        )
        r = _refute_by_lifecycle(outcome, self._init_checklist())
        assert r is None

    def test_function_in_both_init_and_request(self):
        """Function called from both init and request → not refuted."""
        checklist = _checklist_with_calls([
            {"line": 50, "chain": ["dbus_init"], "caller": "main"},
            {"line": 200, "chain": ["do_poll"], "caller": "main"},
            {"line": 300, "chain": ["dbus_init"], "caller": "main"},  # after loop
        ])
        outcome = _Outcome(
            function="dbus_init",
            hypothesis="dbus_init leaking connection reference",
        )
        r = _refute_by_lifecycle(outcome, checklist)
        assert r is None  # conservative: both → request

    def test_no_event_loop_detected(self):
        """No event loop call found → unknown lifecycle → not refuted."""
        checklist = _checklist_with_calls([
            {"line": 50, "chain": ["dbus_init"], "caller": "main"},
            {"line": 100, "chain": ["process"], "caller": "main"},
        ])
        outcome = _Outcome(
            function="dbus_init",
            hypothesis="dbus_init leaks on error",
        )
        r = _refute_by_lifecycle(outcome, checklist)
        assert r is None

    def test_dos_in_init_refuted(self):
        """DoS hypothesis in init-only function → refuted."""
        outcome = _Outcome(
            function="setup_cache",
            hypothesis="denial of service via memory exhaustion",
        )
        checklist = _checklist_with_calls([
            {"line": 30, "chain": ["setup_cache"], "caller": "main"},
            {"line": 200, "chain": ["poll"], "caller": "main"},
        ])
        r = _refute_by_lifecycle(outcome, checklist)
        assert r is not None
        assert "DoS" in r.reason

    def test_dos_with_restart_passes(self):
        """DoS hypothesis mentioning restart → not refuted."""
        outcome = _Outcome(
            function="setup_cache",
            hypothesis="denial of service via restart loop exhaustion",
        )
        checklist = _checklist_with_calls([
            {"line": 30, "chain": ["setup_cache"], "caller": "main"},
            {"line": 200, "chain": ["poll"], "caller": "main"},
        ])
        r = _refute_by_lifecycle(outcome, checklist)
        assert r is None

    def test_no_checklist(self):
        """No checklist → not refuted."""
        outcome = _Outcome(
            function="dbus_init",
            hypothesis="dbus_init leaks reference",
        )
        r = _refute_by_lifecycle(outcome, None)
        assert r is None

    def test_non_leak_in_init_passes(self):
        """Non-leak finding in init function → not refuted."""
        outcome = _Outcome(
            function="parse_config",
            hypothesis="buffer overflow in configuration parser",
        )
        checklist = _checklist_with_calls([
            {"line": 30, "chain": ["parse_config"], "caller": "main"},
            {"line": 200, "chain": ["poll"], "caller": "main"},
        ])
        r = _refute_by_lifecycle(outcome, checklist)
        assert r is None


# ===================================================================
# Gate 3: Contract provenance
# ===================================================================


class TestRefuteByContract:
    """Gate 3: hypothesis-vs-contract contradiction."""

    def test_defender_provenance_refuted(self):
        """Contract says 'stashed copy' → refuted."""
        outcome = _Outcome(
            function="swap_to_tcp",
            hypothesis="attacker-controlled header data reaches memcpy",
        )
        dm = _domain_model(contracts=[{
            "function": "swap_to_tcp",
            "input_semantics": "header: locally constructed stashed copy of original query",
        }])
        r = _refute_by_contract(outcome, dm)
        assert r is not None
        assert r.gate == "contract"
        assert r.demote_to == "suspicious"  # fragile match → suspicious

    def test_no_attacker_claim_passes(self):
        """Hypothesis doesn't claim attacker control → not checked."""
        outcome = _Outcome(
            function="swap_to_tcp",
            hypothesis="integer overflow in length calculation",
        )
        dm = _domain_model(contracts=[{
            "function": "swap_to_tcp",
            "input_semantics": "header: stashed copy",
        }])
        r = _refute_by_contract(outcome, dm)
        assert r is None

    def test_no_matching_contract(self):
        """No contract for function → not refuted."""
        outcome = _Outcome(
            function="unknown_func",
            hypothesis="attacker data reaches sink",
        )
        dm = _domain_model(contracts=[{
            "function": "other_func",
            "input_semantics": "stashed data",
        }])
        r = _refute_by_contract(outcome, dm)
        assert r is None

    def test_attacker_source_contract_passes(self):
        """Contract describes attacker input → not refuted."""
        outcome = _Outcome(
            function="receive_query",
            hypothesis="attacker-controlled DNS query header",
        )
        dm = _domain_model(contracts=[{
            "function": "receive_query",
            "input_semantics": "header: raw DNS query from network recvmsg",
        }])
        r = _refute_by_contract(outcome, dm)
        assert r is None

    def test_no_domain_model(self):
        """No domain model → not refuted."""
        outcome = _Outcome(hypothesis="attacker data flows to sink")
        r = _refute_by_contract(outcome, None)
        assert r is None

    def test_daemon_not_in_regex(self):
        """'daemon->' should NOT match — it's state, not provenance."""
        outcome = _Outcome(
            function="handle_request",
            hypothesis="attacker data reaches daemon structure",
        )
        dm = _domain_model(contracts=[{
            "function": "handle_request",
            "input_semantics": "daemon->cache entry pointer, len from config",
        }])
        r = _refute_by_contract(outcome, dm)
        assert r is None  # daemon-> is not defender provenance


# ===================================================================
# Gate 4: Input-bound Tier 0
# ===================================================================


class TestRefuteByKnownReturnType:
    """Gate 4: known-return-type table."""

    def test_ntohs_overflow_refuted(self):
        """ntohs() returns uint16_t → overflow into int impossible."""
        outcome = _Outcome(
            hypothesis=(
                "integer wraparound: ntohs() return value used in "
                "arithmetic that overflows the loop counter"
            ),
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is not None
        assert r.gate == "input_bound_t0"
        assert r.demote_to == "clean"
        assert "uint16_t" in r.reason

    def test_no_overflow_keyword_passes(self):
        """No overflow/wraparound claim → not checked."""
        outcome = _Outcome(
            hypothesis="ntohs() return value used as array index",
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is None

    def test_unknown_function_passes(self):
        """Unknown function → not in table → not refuted."""
        outcome = _Outcome(
            hypothesis="overflow from custom_parse() return value",
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is None

    def test_function_name_far_from_overflow(self):
        """Function mentioned far from overflow keyword → not refuted.

        When CWE is NOT explicit, the proximity heuristic requires
        the function name and an overflow keyword to be within ~200
        chars.  This test places them far apart with no CWE.
        Uses "wraparound" (matches _OVERFLOW_KW) which does not
        trigger CWE-190 inference, so the proximity check is used.
        """
        outcome = _Outcome(
            hypothesis=(
                "wraparound in the allocation counter. "
                + "x" * 200
                + " ntohs is used elsewhere for header parsing."
            ),
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is None

    def test_cwe_190_triggers_without_keywords(self):
        """CWE-190 in review_result triggers even without keywords."""
        outcome = _Outcome(
            hypothesis="ntohs() value causes integer issue",
            review_result={"cwe": "CWE-190"},
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is not None

    def test_buffer_overflow_not_refuted(self):
        """ntohs value used as memcpy length → buffer overflow is real.

        Gate 4 must NOT fire when the hypothesis is about buffer overflow,
        even though the source value is type-bounded.  A uint16_t can
        still overflow a 1024-byte buffer.
        """
        outcome = _Outcome(
            hypothesis=(
                "integer overflow: ntohs() return value used as "
                "memcpy length causes buffer overflow"
            ),
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is None

    def test_heap_overflow_not_refuted(self):
        """Heap overflow claim with bounded source → not refuted."""
        outcome = _Outcome(
            hypothesis=(
                "ntohl() return value used as allocation size, "
                "arithmetic overflow leads to heap overflow"
            ),
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is None

    def test_pure_integer_wraparound_refuted(self):
        """Pure integer wraparound with no buffer claim → refuted."""
        outcome = _Outcome(
            hypothesis=(
                "ntohs() value causes arithmetic overflow when "
                "multiplied in loop counter increment"
            ),
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is not None
        assert r.gate == "input_bound_t0"


# ===================================================================
# Shared helpers
# ===================================================================


class TestExtractCwe:
    """CWE extraction with fallback to hypothesis inference."""

    def test_explicit_cwe(self):
        outcome = _Outcome(review_result={"cwe": "CWE-362"})
        assert _extract_cwe(outcome) == "CWE-362"

    def test_cwe_with_description_normalised(self):
        """CWE string with description is normalised to bare ID."""
        outcome = _Outcome(review_result={
            "cwe": "CWE-362: Concurrent Execution using Shared Resource",
        })
        assert _extract_cwe(outcome) == "CWE-362"

    def test_multi_cwe_returns_first(self):
        """Multi-CWE string returns the first CWE ID."""
        outcome = _Outcome(review_result={
            "cwe": "CWE-476: Null Pointer Dereference; CWE-362: Race Condition",
        })
        assert _extract_cwe(outcome) == "CWE-476"

    def test_cwe_with_parens_normalised(self):
        outcome = _Outcome(review_result={
            "cwe": "CWE-362 (Concurrent Modification), CWE-667 (Locking)",
        })
        assert _extract_cwe(outcome) == "CWE-362"

    def test_inferred_from_hypothesis(self):
        outcome = _Outcome(
            hypothesis="data race in concurrent modification",
        )
        assert _extract_cwe(outcome) == "CWE-362"

    def test_no_cwe(self):
        outcome = _Outcome(hypothesis="something vague")
        # May return None or a CWE depending on keywords
        result = _extract_cwe(outcome)
        # Just ensure it doesn't crash
        assert result is None or result.startswith("CWE-")


class TestExtractAllCwes:
    """Multi-CWE extraction."""

    def test_single_bare(self):
        outcome = _Outcome(review_result={"cwe": "CWE-362"})
        assert _extract_all_cwes(outcome) == frozenset({"CWE-362"})

    def test_multi_cwe_semicolon(self):
        outcome = _Outcome(review_result={
            "cwe": "CWE-476: Null Pointer; CWE-362: Race Condition",
        })
        assert _extract_all_cwes(outcome) == frozenset({"CWE-476", "CWE-362"})

    def test_multi_cwe_comma(self):
        outcome = _Outcome(review_result={
            "cwe": "CWE-835 (Infinite Loop), CWE-362 (Race), CWE-416 (UAF)",
        })
        assert _extract_all_cwes(outcome) == frozenset({
            "CWE-835", "CWE-362", "CWE-416",
        })

    def test_empty(self):
        outcome = _Outcome(review_result={})
        assert _extract_all_cwes(outcome) == frozenset()

    def test_typo_no_match(self):
        """Typos like 'CIE-362' don't match the regex."""
        outcome = _Outcome(review_result={"cwe": "CIE-362"})
        assert _extract_all_cwes(outcome) == frozenset()


class TestSignalReachableSet:
    """Signal handler reachability computation."""

    def test_empty_checklist(self):
        assert _signal_reachable_set(None) == frozenset()
        assert _signal_reachable_set({}) == frozenset()

    def test_no_signal_handlers(self):
        cl = _checklist_with_calls([
            {"line": 10, "chain": ["printf"], "caller": "main"},
        ])
        assert _signal_reachable_set(cl) == frozenset()

    def test_transitive_reachability(self):
        cl = _checklist_with_calls([
            {"line": 10, "chain": ["signal", "my_handler"], "caller": "main"},
            {"line": 20, "chain": ["cleanup"], "caller": "my_handler"},
            {"line": 30, "chain": ["close_fd"], "caller": "cleanup"},
        ])
        cl["files"][0]["items"] = [
            {"name": "my_handler"},
            {"name": "cleanup"},
            {"name": "close_fd"},
        ]
        sig_set = _signal_reachable_set(cl)
        # my_handler, cleanup, close_fd should all be reachable
        assert any("my_handler" in s for s in sig_set)
        assert any("cleanup" in s for s in sig_set)
        assert any("close_fd" in s for s in sig_set)

    def test_sighandler_name_heuristic(self):
        """Functions named *sig_handler* are detected as handlers."""
        cl = _checklist_with_calls([
            {"line": 20, "chain": ["do_work"], "caller": "my_sig_handler"},
        ])
        cl["files"][0]["items"] = [
            {"name": "my_sig_handler"},
            {"name": "do_work"},
        ]
        sig_set = _signal_reachable_set(cl)
        assert any("my_sig_handler" in s for s in sig_set)
        assert any("do_work" in s for s in sig_set)


class TestClassifyLifecycle:
    """Lifecycle phase classification."""

    def test_init_phase(self):
        cl = _checklist_with_calls([
            {"line": 50, "chain": ["setup"], "caller": "main"},
            {"line": 200, "chain": ["poll"], "caller": "main"},
        ])
        assert _classify_lifecycle("setup", "src/main.c", cl) == "init"

    def test_request_phase(self):
        cl = _checklist_with_calls([
            {"line": 200, "chain": ["poll"], "caller": "main"},
            {"line": 300, "chain": ["handle"], "caller": "main"},
        ])
        assert _classify_lifecycle("handle", "src/main.c", cl) == "request"

    def test_both_phases(self):
        cl = _checklist_with_calls([
            {"line": 50, "chain": ["dual"], "caller": "main"},
            {"line": 200, "chain": ["poll"], "caller": "main"},
            {"line": 300, "chain": ["dual"], "caller": "main"},
        ])
        assert _classify_lifecycle("dual", "src/main.c", cl) == "request"

    def test_unknown_function(self):
        cl = _checklist_with_calls([
            {"line": 200, "chain": ["poll"], "caller": "main"},
        ])
        assert _classify_lifecycle("unknown", "src/main.c", cl) == "unknown"

    def test_no_main(self):
        cl = _checklist_with_calls([
            {"line": 10, "chain": ["foo"], "caller": "lib_init"},
        ])
        assert _classify_lifecycle("foo", "src/lib.c", cl) == "unknown"


class TestGetCalls:
    """Call graph extraction from checklist file entries."""

    def test_dict_with_calls_list(self):
        fentry = {"call_graph": {"calls": [{"line": 1}]}}
        assert _get_calls(fentry) == [{"line": 1}]

    def test_missing_call_graph(self):
        assert _get_calls({}) == []
        assert _get_calls({"call_graph": {}}) == []

    def test_non_dict_call_graph(self):
        assert _get_calls({"call_graph": "invalid"}) == []


# ===================================================================
# Integration: refute_hypothesis
# ===================================================================


class TestRefuteHypothesis:
    """End-to-end refutation gate dispatch."""

    def test_tool_confirmed_bypasses_all(self):
        """Finding with real tool evidence → never refuted."""
        outcome = _Outcome(
            hypothesis="data race in shared state",
            evidence_tool="semgrep:race-condition",
        )
        dm = _domain_model(overview="single-threaded event loop")
        r = refute_hypothesis(
            outcome, domain_model=dm, checklist=None,
            config=_Config(),
        )
        assert r is None

    def test_no_hypothesis_bypasses(self):
        """Empty hypothesis → nothing to refute."""
        outcome = _Outcome(hypothesis="")
        r = refute_hypothesis(
            outcome, domain_model=None, checklist=None,
            config=_Config(),
        )
        assert r is None

    def test_architecture_fires_first(self):
        """Architecture gate fires before lifecycle."""
        outcome = _Outcome(
            function="init_net",
            hypothesis="data race in init_net concurrent access",
        )
        dm = _domain_model(
            architecture={"threading_model": "single_threaded"},
        )
        checklist = _checklist_with_calls([
            {"line": 50, "chain": ["init_net"], "caller": "main"},
            {"line": 200, "chain": ["poll"], "caller": "main"},
        ])
        r = refute_hypothesis(
            outcome, domain_model=dm, checklist=checklist,
            config=_Config(),
        )
        assert r is not None
        assert r.gate == "architecture"  # fires first, not lifecycle

    def test_lifecycle_fires_when_arch_doesnt(self):
        """Lifecycle gate fires for resource leak in init."""
        outcome = _Outcome(
            function="db_init",
            hypothesis="db_init leaks connection handle on error",
        )
        dm = _domain_model(overview="multi-threaded server")
        checklist = _checklist_with_calls([
            {"line": 50, "chain": ["db_init"], "caller": "main"},
            {"line": 200, "chain": ["poll"], "caller": "main"},
        ])
        r = refute_hypothesis(
            outcome, domain_model=dm, checklist=checklist,
            config=_Config(),
        )
        assert r is not None
        assert r.gate == "lifecycle"

    def test_no_gate_fires(self):
        """Legitimate finding → no refutation."""
        outcome = _Outcome(
            hypothesis="buffer overflow in parse_dns_reply via memcpy",
        )
        r = refute_hypothesis(
            outcome, domain_model=None, checklist=None,
            config=_Config(),
        )
        assert r is None
