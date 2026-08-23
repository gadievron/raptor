"""Tests for core.audit.refutation — early refutation gates."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from core.audit.refutation import (
    _classify_lifecycle,
    _extract_all_cwes,
    _extract_cwe,
    _extract_cwes_from_text,
    _get_calls,
    _get_function_source_and_callees,
    _refute_by_architecture,
    _refute_by_callee_inheritance,
    _refute_by_contract,
    _refute_by_known_return_type,
    _refute_by_lifecycle,
    _signal_reachable_set,
    refute_hypothesis,
    rescue_self_refuted,
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
    hypotheses: Optional[list] = None
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

    def test_visible_thread_primitive_vetoes_claim(self, tmp_path):
        """The single_threaded claim is an unverified LLM output; when
        the source visibly spawns threads the claim is provably wrong
        and must not demote race findings."""
        import core.audit.refutation as refutation_mod
        (tmp_path / "worker.c").write_text(
            "void start(void) { pthread_create(&t, 0, run, 0); }\n")
        refutation_mod._threading_seen_cache.clear()
        outcome = _Outcome(
            hypothesis="data race in newaddress concurrent modification",
        )
        dm = _domain_model(
            architecture={"threading_model": "single_threaded"},
        )
        try:
            r = _refute_by_architecture(
                outcome, dm, None, _Config(target_path=tmp_path))
        finally:
            refutation_mod._threading_seen_cache.clear()
        assert r is None

    def test_no_primitives_claim_still_suppresses(self, tmp_path):
        import core.audit.refutation as refutation_mod
        (tmp_path / "main.c").write_text("int main(void) { return 0; }\n")
        refutation_mod._threading_seen_cache.clear()
        outcome = _Outcome(
            hypothesis="data race in newaddress concurrent modification",
        )
        dm = _domain_model(
            architecture={"threading_model": "single_threaded"},
        )
        try:
            r = _refute_by_architecture(
                outcome, dm, None, _Config(target_path=tmp_path))
        finally:
            refutation_mod._threading_seen_cache.clear()
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

    def test_getchar_underflow_not_refuted(self):
        """getchar() returns EOF (-1) — a CWE-191 underflow claim on
        its value is real and must NOT be demoted (the table only
        bounds the value above)."""
        outcome = _Outcome(
            hypothesis=(
                "integer underflow: getchar() returns EOF (-1) and "
                "the value is subtracted from an unsigned counter"
            ),
            review_result={"cwe": "CWE-191"},
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is None

    def test_getchar_underflow_keyword_only_not_refuted(self):
        """Underflow keyword without explicit CWE also spares the
        negative-capable functions."""
        outcome = _Outcome(
            hypothesis=(
                "integer underflow when fgetc() result feeds the "
                "size computation"
            ),
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is None

    def test_getchar_overflow_still_refuted(self):
        """CWE-190 on getchar() keeps the original refutation: the
        value is bounded above by 0xFF."""
        outcome = _Outcome(
            hypothesis="integer overflow from getchar() return value",
            review_result={"cwe": "CWE-190"},
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is not None
        assert r.gate == "input_bound_t0"

    def test_ntohs_underflow_still_refuted(self):
        """ntohs() cannot return a negative value (min 0), so the
        CWE-191 refutation stays for it."""
        outcome = _Outcome(
            hypothesis="integer underflow from ntohs() return value",
            review_result={"cwe": "CWE-191"},
        )
        r = _refute_by_known_return_type(outcome, _Config())
        assert r is not None


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

    def test_memoised_per_checklist_identity(self, monkeypatch):
        """The gate runs per outcome; the reachable-set walk must be
        served from the per-checklist cache on repeat calls."""
        import core.audit.refutation as rf

        cl = _checklist_with_calls([
            {"line": 10, "chain": ["signal", "my_handler"],
             "caller": "main"},
        ])
        cl["files"][0]["items"] = [{"name": "my_handler"}]
        counter = {"n": 0}
        orig = rf._get_calls

        def _counting(fentry):
            counter["n"] += 1
            return orig(fentry)

        monkeypatch.setattr(rf, "_get_calls", _counting)
        first = rf._signal_reachable_set(cl)
        walked = counter["n"]
        assert walked > 0
        second = rf._signal_reachable_set(cl)
        assert second == first
        assert counter["n"] == walked  # no rebuild

        # A distinct checklist object is not served the cached value.
        other = _checklist_with_calls([
            {"line": 10, "chain": ["printf"], "caller": "main"},
        ])
        assert rf._signal_reachable_set(other) == frozenset()


class TestClassifyLifecycleMemo:
    def test_caller_map_memoised_per_checklist(self, monkeypatch):
        import core.audit.refutation as rf

        cl = _checklist_with_calls([
            {"line": 50, "chain": ["setup"], "caller": "main"},
            {"line": 200, "chain": ["poll"], "caller": "main"},
        ])
        counter = {"n": 0}
        orig = rf._get_calls

        def _counting(fentry):
            counter["n"] += 1
            return orig(fentry)

        monkeypatch.setattr(rf, "_get_calls", _counting)
        assert rf._classify_lifecycle("setup", "src/main.c", cl) \
            == "init"
        walked = counter["n"]
        assert walked > 0
        assert rf._classify_lifecycle("setup", "src/main.c", cl) \
            == "init"
        assert counter["n"] == walked  # map served from cache


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


# ---------------------------------------------------------------------------
# Gate 5: Anti-self-refutation
# ---------------------------------------------------------------------------


class TestRescueSelfRefuted:
    """Tests for rescue_self_refuted (Gate 5)."""

    def test_rescues_refuted_race_hypothesis(self):
        """Refuted CWE-362 hypothesis without evidence → suspicious."""
        outcome = _Outcome(
            status="clean",
            hypothesis="race condition on credential field",
            hypotheses=[{
                "mechanism": "CWE-362 race between read and write of cred",
                "confidence": "refuted",
                "counter": "analysis shows it fails safely",
            }],
        )
        r = rescue_self_refuted(outcome)
        assert r is not None
        assert r.gate == "anti_self_refutation"
        assert r.demote_to == "suspicious"

    def test_rescues_refuted_uaf_hypothesis(self):
        """Refuted CWE-416 hypothesis without evidence → suspicious."""
        outcome = _Outcome(
            status="clean",
            hypothesis="use-after-free on list head",
            hypotheses=[{
                "mechanism": "CWE-416 use after free: kfree then rcu deref",
                "confidence": "refuted",
                "counter": "existing readers already dereferenced",
            }],
        )
        r = rescue_self_refuted(outcome)
        assert r is not None
        assert r.gate == "anti_self_refutation"

    def test_no_rescue_for_non_race_cwe(self):
        """CWE-190 self-refutation is not rescued."""
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-190 integer overflow in size calc",
                "confidence": "refuted",
                "counter": "value fits in 32-bit",
            }],
        )
        r = rescue_self_refuted(outcome)
        assert r is None

    def test_no_rescue_when_tool_evidence(self):
        """Tool already spoke — don't second-guess."""
        outcome = _Outcome(
            status="clean",
            evidence_tool="joern:taint",
            hypotheses=[{
                "mechanism": "CWE-362 race on shared counter",
                "confidence": "refuted",
                "counter": "no concurrent access found",
            }],
        )
        r = rescue_self_refuted(outcome)
        assert r is None

    def test_no_rescue_when_not_clean(self):
        """Gate only fires on clean outcomes."""
        outcome = _Outcome(
            status="suspicious",
            hypotheses=[{
                "mechanism": "CWE-362 race condition",
                "confidence": "refuted",
                "counter": "appears safe",
            }],
        )
        r = rescue_self_refuted(outcome)
        assert r is None

    def test_no_rescue_without_counter(self):
        """No counter reasoning → nothing to rescue."""
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-416 use after free",
                "confidence": "refuted",
                "counter": "",
            }],
        )
        r = rescue_self_refuted(outcome)
        assert r is None

    def test_rescues_from_review_result_hypotheses(self):
        """Hypotheses in review_result are also checked."""
        outcome = _Outcome(
            status="clean",
            review_result={
                "hypotheses": [{
                    "mechanism": "CWE-415 double free of skb",
                    "confidence": "refuted",
                    "counter": "second free path unreachable",
                }],
            },
        )
        r = rescue_self_refuted(outcome)
        assert r is not None
        assert r.gate == "anti_self_refutation"

    def test_inferred_cwe_from_keywords(self):
        """CWE inferred from keywords when no explicit CWE-NNN."""
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "race condition between reader and writer threads",
                "confidence": "refuted",
                "counter": "lock ordering prevents this",
            }],
        )
        r = rescue_self_refuted(outcome)
        assert r is not None

    def test_skips_non_refuted_hypotheses(self):
        """Only hypotheses with confidence=refuted are candidates."""
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-362 race condition",
                "confidence": "high",
                "counter": "",
            }],
        )
        r = rescue_self_refuted(outcome)
        assert r is None


class TestRaceProtectedSelfRefutation:
    """A race-family self-refutation corroborated by mechanical lock
    protection is accepted, not floored — re-flagging fully serialized
    kernel code manufactures a false positive. Lifetime CWEs keep the
    floor: lock protection says nothing about object lifetime."""

    _LOCKED_C = (
        "void sync_counters(struct gate_state *st)\n"
        "{\n"
        "\tunsigned long flags;\n"
        "\tmutex_lock(&st->gate_mutex);\n"
        "\traw_spin_lock_irqsave(&st->gate_lock, flags);\n"
        "\tst->count = st->count + 1;\n"
        "\tWRITE_ONCE(st->snap, st->count);\n"
        "\traw_spin_unlock_irqrestore(&st->gate_lock, flags);\n"
        "\tmutex_unlock(&st->gate_mutex);\n"
        "}\n"
    )

    def _race_outcome(self):
        return _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-362 race on the shared counter",
                "confidence": "refuted",
                "counter": "serialized by the gate mutex",
            }],
        )

    def test_protected_source_accepts_refutation(self):
        r = rescue_self_refuted(self._race_outcome(), source=self._LOCKED_C)
        assert r is None

    def test_without_source_still_floors(self):
        r = rescue_self_refuted(self._race_outcome())
        assert r is not None
        assert r.demote_to == "suspicious"

    def test_unprotected_source_still_floors(self):
        unlocked = (
            "void sync_counters(void)\n"
            "{\n"
            "\tst->count = st->count + 1;\n"
            "\tst->snap = st->count;\n"
            "}\n"
        )
        r = rescue_self_refuted(self._race_outcome(), source=unlocked)
        assert r is not None

    def test_uaf_refutation_accepted_when_locked_and_nothing_freed(self):
        # Doctrine update (corpus-verified): a lifetime self-refutation
        # on FULLY lock-protected source that frees NOTHING is
        # mechanically corroborated — the claimed hazard has no local
        # mechanism and no concurrent window in scope. Flooring it
        # manufactured a family of kernel false positives (the model
        # concluded clean, the floor shipped suspicious, and no
        # verification channel could ever adjudicate the lifetime
        # claim).
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-416 use after free of the state block",
                "confidence": "refuted",
                "counter": "reference held by caller",
            }],
        )
        r = rescue_self_refuted(outcome, source=self._LOCKED_C)
        assert r is None

    _BARE_FREE_C = (
        "void teardown(struct dev_priv *priv)\n"
        "{\n"
        "\tkfree(priv->buf);\n"
        "\tpriv->buf = NULL;\n"
        "}\n"
    )

    def test_uaf_refutation_still_floored_over_bare_free(self):
        # A bare free with no visible teardown ordering: the witness
        # grades unsafe, so the self-refutation is NOT accepted.
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-416 use after free of the buffer",
                "confidence": "refuted",
                "counter": "no concurrent access believed possible",
            }],
        )
        r = rescue_self_refuted(outcome, source=self._BARE_FREE_C)
        assert r is not None
        assert r.demote_to == "suspicious"

    _ASYNC_CANCEL_FREE_C = (
        "void disconnect(struct outer *dev)\n"
        "{\n"
        "\tstruct dev_priv *priv = dev->private;\n"
        "\ttimer_delete(&priv->timer);\n"
        "\tkfree(dev->private);\n"
        "}\n"
    )

    def test_uaf_refutation_still_floored_over_async_cancel_free(self):
        # The async-cancel-then-free race shape grades UNSAFE — a
        # reviewer talking itself out of the real teardown race stays
        # floored.
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-416 use after free via the timer callback",
                "confidence": "refuted",
                "counter": "timer_delete cancels the pending timer",
            }],
        )
        r = rescue_self_refuted(outcome, source=self._ASYNC_CANCEL_FREE_C)
        assert r is not None

    _SYNC_TEARDOWN_C = (
        "void release(struct ctx *c)\n"
        "{\n"
        "\thrtimer_cancel(&c->tmr);\n"
        "\tkfree_rcu(c, rcu);\n"
        "}\n"
    )

    def test_uaf_refutation_accepted_over_waiting_teardown(self):
        # Waiting cancel + RCU-deferred reclamation corroborate the
        # reviewer's lifetime self-refutation.
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-416 use after free if the callback re-arms",
                "confidence": "refuted",
                "counter": "hrtimer_cancel waits; kfree_rcu defers",
            }],
        )
        r = rescue_self_refuted(outcome, source=self._SYNC_TEARDOWN_C)
        assert r is None


class TestPreEvidenceCorroboratedRefutation:
    """A pre-loop screen receipt from the parsed-int family outranks a
    same-family self-refutation — the integer CWEs are outside the
    gate's CWE allowlist, so this clause is the only path."""

    def _outcome(self, mechanism):
        return _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": mechanism,
                "confidence": "refuted",
                "counter": "values are stored as metadata only",
            }],
        )

    def test_int_family_refutation_floored_with_screen_receipt(self):
        o = self._outcome(
            "huge parsed values overflow int32 storage downstream",
        )
        r = rescue_self_refuted(
            o, pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is not None
        assert r.demote_to == "suspicious"
        assert "smt:check-parsed-int-contract" in r.reason

    def test_low_dismissal_also_floored(self):
        o = self._outcome(
            "huge parsed values overflow int32 storage downstream",
        )
        o.hypotheses[0]["confidence"] = "low"
        r = rescue_self_refuted(
            o, pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is not None

    def test_no_screen_receipt_no_floor(self):
        o = self._outcome(
            "huge parsed values overflow int32 storage downstream",
        )
        assert rescue_self_refuted(o) is None

    def test_unrelated_family_hypothesis_not_floored(self):
        o = self._outcome(
            "path traversal via the parsed filename component",
        )
        r = rescue_self_refuted(
            o, pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is None

    def test_unrelated_pre_evidence_not_consumed(self):
        o = self._outcome(
            "huge parsed values overflow int32 storage downstream",
        )
        r = rescue_self_refuted(
            o, pre_evidence="smt:check-auth-bypass",
        )
        assert r is None


class TestDetectorCorroboratedDismissal:
    """A mechanical detector receipt on this function outranks a
    same-family hypothesis the reviewer raised then dismissed at low
    confidence or refuted."""

    _DETECTORS = [{"detector": "cocci:uninitialized_return"}]

    def _outcome(self, conf="low", mechanism=None):
        return _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": mechanism or (
                    "uninitialized ret read: the switch has no default "
                    "case, so an unexpected value leaves ret unset"
                ),
                "confidence": conf,
                "counter": "only two enum values are ever assigned",
            }],
        )

    def test_low_dismissal_floored(self):
        r = rescue_self_refuted(
            self._outcome("low"), detector_findings=self._DETECTORS,
        )
        assert r is not None
        assert r.gate == "anti_self_refutation"
        assert "detector receipt" in r.reason

    def test_refuted_dismissal_floored(self):
        r = rescue_self_refuted(
            self._outcome("refuted"), detector_findings=self._DETECTORS,
        )
        assert r is not None

    def test_medium_confidence_not_consumed(self):
        r = rescue_self_refuted(
            self._outcome("medium"), detector_findings=self._DETECTORS,
        )
        assert r is None

    def test_unrelated_family_hypothesis_not_floored(self):
        r = rescue_self_refuted(
            self._outcome("low", "refcount imbalance on the pm runtime"),
            detector_findings=self._DETECTORS,
        )
        assert r is None

    def test_unmapped_detector_not_consumed(self):
        r = rescue_self_refuted(
            self._outcome("low"),
            detector_findings=[{"detector": "stale_alias_candidate"}],
        )
        assert r is None

    def test_tool_evidence_blocks(self):
        o = self._outcome("low")
        o.evidence_tool = "joern:flow"
        r = rescue_self_refuted(o, detector_findings=self._DETECTORS)
        assert r is None


class TestDiagnoseRescue:
    """diagnose_rescue mirrors the Gate-5 precondition chain and names
    the first broken link, so a silent non-fire is explainable from a
    durable audit-log row instead of invisible."""

    _RECEIPT = {
        "check_type": "auth_mode_registration",
        "function": "handle_packet",
        "file": "src/net.c",
    }

    def test_none_when_gate_would_fire(self):
        from core.audit.refutation import diagnose_rescue
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-362 race between read and write",
                "confidence": "refuted",
                "counter": "appears safe",
            }],
        )
        assert diagnose_rescue(outcome) is None

    def test_non_clean_status(self):
        from core.audit.refutation import diagnose_rescue
        outcome = _Outcome(status="suspicious")
        d = diagnose_rescue(outcome)
        assert d["blocked_on"] == "status"

    def test_no_refuted_hypothesis_with_receipt(self):
        from core.audit.refutation import diagnose_rescue
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": (
                    "auth mode gates registration views asymmetrically"
                ),
                "confidence": "low",
                "counter": "views enforce their own permissions",
            }],
        )
        d = diagnose_rescue(outcome, negative_space=[self._RECEIPT])
        assert d["blocked_on"] == "no_refuted_hypothesis"
        assert d["receipts"] == ["auth_mode_registration"]
        assert d["confidences"] == ["low"]

    def test_tool_evidence_blocks(self):
        from core.audit.refutation import diagnose_rescue
        outcome = _Outcome(
            status="clean",
            evidence_tool="joern:taint",
            hypotheses=[{
                "mechanism": "CWE-362 race",
                "confidence": "refuted",
                "counter": "safe",
            }],
        )
        d = diagnose_rescue(outcome)
        assert d["blocked_on"] == "tool_evidence"

    def test_missing_counter_blocks(self):
        from core.audit.refutation import diagnose_rescue
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-416 use after free",
                "confidence": "refuted",
                "counter": "",
            }],
        )
        d = diagnose_rescue(outcome)
        assert d["blocked_on"] == "no_counter"

    def test_unmatched_receipt_and_cwe(self):
        from core.audit.refutation import diagnose_rescue
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": "CWE-190 integer overflow in size",
                "confidence": "refuted",
                "counter": "value bounded by caller",
            }],
        )
        d = diagnose_rescue(outcome, negative_space=[self._RECEIPT])
        assert d["blocked_on"] == "no_matching_receipt_or_cwe"

    def test_receipt_on_other_function_not_counted(self):
        from core.audit.refutation import diagnose_rescue
        outcome = _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": (
                    "auth mode gates registration views asymmetrically"
                ),
                "confidence": "low",
                "counter": "some counter",
            }],
        )
        other = dict(self._RECEIPT, function="other_fn")
        d = diagnose_rescue(outcome, negative_space=[other])
        assert d["receipts"] == []


# ---------------------------------------------------------------------------
# Gate 6: Callee-inheritance suppression
# ---------------------------------------------------------------------------


class TestCalleeInheritance:
    """Tests for _refute_by_callee_inheritance (Gate 6)."""

    _THIN_WRAPPER = (
        "int aead_sendmsg_nokey(struct sock *sk, struct msghdr *msg, size_t size)\n"
        "{\n"
        "    if (!aead_check_key(sk))\n"
        "        return -ENOKEY;\n"
        "    return aead_sendmsg(sk, msg, size);\n"
        "}\n"
    )

    def test_suppresses_thin_wrapper_with_callee_pattern(self):
        """Hypothesis says 'calls vulnerable function' + thin wrapper → refute."""
        outcome = _Outcome(
            hypothesis="calls vulnerable function aead_sendmsg",
        )
        r = _refute_by_callee_inheritance(
            outcome, self._THIN_WRAPPER, ["aead_sendmsg"],
        )
        assert r is not None
        assert r.gate == "callee_inheritance"
        assert r.demote_to == "clean"

    def test_suppresses_named_callee_in_hypothesis(self):
        """Hypothesis names a specific callee that is in the callee list."""
        outcome = _Outcome(
            hypothesis="the function aead_sendmsg has a TOCTOU race condition",
        )
        r = _refute_by_callee_inheritance(
            outcome, self._THIN_WRAPPER, ["aead_sendmsg"],
        )
        assert r is not None
        assert r.gate == "callee_inheritance"

    def test_no_suppression_when_body_has_memcpy(self):
        """Wrapper with memcpy is not a thin delegation."""
        source = (
            "void wrap_copy(void *dst, void *src, size_t n)\n"
            "{\n"
            "    memcpy(dst, src, n);\n"
            "}\n"
        )
        outcome = _Outcome(
            hypothesis="calls vulnerable function inner_copy",
        )
        r = _refute_by_callee_inheritance(
            outcome, source, ["inner_copy"],
        )
        assert r is None

    def test_no_suppression_when_body_has_cast(self):
        """Wrapper with pointer cast is not a thin delegation."""
        source = (
            "int wrap(void *p)\n"
            "{\n"
            "    struct foo *f = (struct foo *)p;\n"
            "    return inner(f);\n"
            "}\n"
        )
        outcome = _Outcome(
            hypothesis="calls vulnerable function inner",
        )
        r = _refute_by_callee_inheritance(
            outcome, source, ["inner"],
        )
        assert r is None

    def test_no_suppression_when_body_too_large(self):
        """Function with >10 SLOC is not a thin wrapper."""
        lines = ["int big_func(int x) {"]
        for i in range(12):
            lines.append(f"    x = do_thing_{i}(x);")
        lines.append("    return x;")
        lines.append("}")
        source = "\n".join(lines)
        outcome = _Outcome(
            hypothesis="calls vulnerable function do_thing_0",
        )
        r = _refute_by_callee_inheritance(
            outcome, source, ["do_thing_0"],
        )
        assert r is None

    def test_no_suppression_without_callee_match(self):
        """Named callee not in callee list → no suppression."""
        outcome = _Outcome(
            hypothesis="the function unknown_func has a bug",
        )
        r = _refute_by_callee_inheritance(
            outcome, self._THIN_WRAPPER, ["aead_sendmsg"],
        )
        assert r is None

    def test_no_suppression_without_hypothesis(self):
        """No hypothesis text → no suppression."""
        outcome = _Outcome(hypothesis="")
        r = _refute_by_callee_inheritance(
            outcome, self._THIN_WRAPPER, ["aead_sendmsg"],
        )
        assert r is None

    def test_no_suppression_with_allocation(self):
        """Wrapper that allocates memory is doing real work."""
        source = (
            "void *wrap_alloc(size_t n)\n"
            "{\n"
            "    void *p = kmalloc(n, GFP_KERNEL);\n"
            "    return inner(p);\n"
            "}\n"
        )
        outcome = _Outcome(
            hypothesis="calls vulnerable function inner",
        )
        r = _refute_by_callee_inheritance(
            outcome, source, ["inner"],
        )
        assert r is None

    def test_integrated_via_refute_hypothesis(self):
        """Gate 6 fires through the main refute_hypothesis entry point."""
        checklist = {
            "files": [{
                "path": "src/net.c",
                "items": [{
                    "name": "handle_packet",
                    "source": self._THIN_WRAPPER,
                }],
                "call_graph": {
                    "calls": [{
                        "caller": "handle_packet",
                        "chain": ["aead_sendmsg"],
                        "line": 5,
                    }],
                },
            }],
        }
        outcome = _Outcome(
            hypothesis="calls vulnerable function aead_sendmsg",
            function="handle_packet",
        )
        r = refute_hypothesis(
            outcome,
            domain_model=None,
            checklist=checklist,
            config=_Config(),
        )
        assert r is not None
        assert r.gate == "callee_inheritance"


# ---------------------------------------------------------------------------
# _extract_cwes_from_text
# ---------------------------------------------------------------------------


class TestExtractCwesFromText:
    """Tests for _extract_cwes_from_text helper."""

    def test_explicit_cwe_ids(self):
        assert _extract_cwes_from_text("CWE-362 race condition") == frozenset({"CWE-362"})

    def test_multiple_cwe_ids(self):
        result = _extract_cwes_from_text("CWE-416 and CWE-362 combined")
        assert result == frozenset({"CWE-416", "CWE-362"})

    def test_keyword_inference(self):
        result = _extract_cwes_from_text("race condition between threads")
        assert "CWE-362" in result

    def test_empty_string(self):
        assert _extract_cwes_from_text("") == frozenset()

    def test_no_match(self):
        assert _extract_cwes_from_text("just some random text") == frozenset()


# ---------------------------------------------------------------------------
# _get_function_source_and_callees
# ---------------------------------------------------------------------------


class TestGetFunctionSourceAndCallees:
    """Tests for _get_function_source_and_callees helper."""

    def test_finds_source_and_callees(self):
        checklist = {
            "files": [{
                "path": "src/net.c",
                "items": [{"name": "handle_packet", "source": "int handle_packet() {}"}],
                "call_graph": {
                    "calls": [
                        {"caller": "handle_packet", "chain": ["send_reply"], "line": 10},
                        {"caller": "handle_packet", "chain": ["log_event"], "line": 20},
                    ],
                },
            }],
        }
        outcome = _Outcome(file="src/net.c", function="handle_packet")
        source, callees = _get_function_source_and_callees(outcome, checklist)
        assert source == "int handle_packet() {}"
        assert "send_reply" in callees
        assert "log_event" in callees

    def test_returns_empty_for_missing_function(self):
        checklist = {"files": [{"path": "src/net.c", "items": [], "call_graph": {"calls": []}}]}
        outcome = _Outcome(file="src/net.c", function="nonexistent")
        source, callees = _get_function_source_and_callees(outcome, checklist)
        assert source == ""
        assert callees == []

    def test_returns_empty_for_no_checklist(self):
        outcome = _Outcome()
        source, callees = _get_function_source_and_callees(outcome, None)
        assert source == ""
        assert callees == []


class TestReceiptContradictionRescue:
    """Self-refutations that contradict an active structural receipt on
    the same function are rescued regardless of CWE family."""

    def _refuted_auth_outcome(self):
        return _Outcome(
            file="app/setup/wiring.py",
            function="mount_endpoints",
            status="clean",
            hypotheses=[{
                "mechanism": (
                    "the login-mode chain gates most endpoint "
                    "registration calls, but two endpoints are "
                    "registered outside the chain and mount in "
                    "every mode"
                ),
                "confidence": "refuted",
                "counter": "those views require login at request time",
            }],
        )

    def test_matching_receipt_rescues(self):
        receipts = [{
            "check_type": "auth_mode_registration",
            "function": "mount_endpoints",
        }]
        r = rescue_self_refuted(
            self._refuted_auth_outcome(), negative_space=receipts,
        )
        assert r is not None
        assert r.gate == "anti_self_refutation"
        assert "auth_mode_registration receipt" in r.reason
        assert r.demote_to == "suspicious"

    def test_receipt_on_other_function_ignored(self):
        receipts = [{
            "check_type": "auth_mode_registration",
            "function": "some_other_setup",
        }]
        r = rescue_self_refuted(
            self._refuted_auth_outcome(), negative_space=receipts,
        )
        assert r is None

    def test_unrelated_receipt_family_ignored(self):
        receipts = [{
            "check_type": "shared_writer_race",
            "function": "mount_endpoints",
        }]
        r = rescue_self_refuted(
            self._refuted_auth_outcome(), negative_space=receipts,
        )
        assert r is None

    def test_object_shaped_receipts_supported(self):
        class _NF:
            check_type = "auth_mode_registration"
            function = "mount_endpoints"

        r = rescue_self_refuted(
            self._refuted_auth_outcome(), negative_space=[_NF()],
        )
        assert r is not None

    def test_no_receipts_no_rescue(self):
        r = rescue_self_refuted(self._refuted_auth_outcome())
        assert r is None


class TestReturnDomainFamilyDismissal:
    """A `return_domain` detector receipt (sentinel-vs-domain mismatch
    with a constructive body proof) outranks a raised-then-dismissed
    hypothesis about a failure signal escaping an exact-sentinel
    comparison."""

    _DETECTORS = [{
        "detector": "return_domain",
        "file": "src/net.c",
        "function": "handle_packet",
        "line": 42,
        "description": (
            "check_peer: decision tests `== -1` but the callee "
            "provably also returns {-2}"
        ),
    }]

    def _outcome(self, conf="refuted", mechanism=None):
        return _Outcome(
            status="clean",
            hypotheses=[{
                "mechanism": mechanism or (
                    "check_peer() returns a negative value other "
                    "than -1 on some failure path, bypassing the "
                    "`== -1` check"
                ),
                "confidence": conf,
                "counter": "the callee only ever returns 0 or -1",
            }],
        )

    def test_refuted_dismissal_floored(self):
        r = rescue_self_refuted(
            self._outcome(), detector_findings=self._DETECTORS,
        )
        assert r is not None
        assert r.gate == "anti_self_refutation"
        assert r.demote_to == "suspicious"
        assert "detector receipt" in r.reason

    def test_sentinel_phrasing_floored(self):
        r = rescue_self_refuted(
            self._outcome(
                mechanism=(
                    "the callee's failure signal is not the exact "
                    "sentinel value the function checks"
                ),
            ),
            detector_findings=self._DETECTORS,
        )
        assert r is not None

    def test_fail_closed_phrasing_floored(self):
        r = rescue_self_refuted(
            self._outcome(
                mechanism=(
                    "a failure return from the checker is not "
                    "fail-closed, so the caller proceeds"
                ),
            ),
            detector_findings=self._DETECTORS,
        )
        assert r is not None

    def test_unrelated_hypothesis_not_floored(self):
        r = rescue_self_refuted(
            self._outcome(
                mechanism="heap overflow when copying the banner",
            ),
            detector_findings=self._DETECTORS,
        )
        assert r is None

    def test_confident_dismissal_not_consumed(self):
        r = rescue_self_refuted(
            self._outcome(conf="high"),
            detector_findings=self._DETECTORS,
        )
        assert r is None

    def test_no_receipt_no_rescue(self):
        r = rescue_self_refuted(self._outcome())
        assert r is None
