"""Live-server integration for the joern_verify channels.

The channels' unit tests drive doubles, and a double that echoes
println answers a channel the real server does not — the exact
mechanism that let a println-riding protocol read structurally dead
in production while every unit test stayed green. This file is the
transport ground truth: a REAL Joern server, a REAL CPG built from a
two-function C fixture, and the shipped check functions end to end.

Skipped (marked slow) when Joern or user namespaces are unavailable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from packages.joern import server as server_mod


def _live_ready() -> bool:
    from packages.joern.prereqs import _joern_path
    if _joern_path() is None:
        return False
    try:
        return subprocess.run(
            [sys.executable,
             str(Path(server_mod.__file__).parent / "netns_forwarder.py"),
             "--self-probe"],
            capture_output=True, timeout=30, check=False,
        ).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


_FIXTURE = """\
#include <string.h>

char dst[16];

void guarded_copy(char *buf, int len) {
    if (len < 16) {
        memcpy(dst, buf, len);
    }
}

void unguarded_copy(char *buf, int len) {
    memcpy(dst, buf, len);
}

void join_point_copy(char *buf, int len) {
    if (len < 16) { }
    memcpy(dst, buf, len);
}

void early_return_copy(char *buf, int len) {
    if (len >= 16) return;
    memcpy(dst, buf, len);
}

void literal_copy(char *buf, int len) {
    memcpy(dst, buf, strlen("a perfectly ordinary format string") + len);
}

void veto_probe(char *buf, int len) {
    memcpy(dst, buf, strlen("x:12: error: boom") + len);
}
void cap_evade(char *buf, int len, int flag) {
    if (flag) {
        if (len < 16) {
            memcpy(dst, buf, len + 0);
            memcpy(dst, buf, len + 1);
            memcpy(dst, buf, len + 2);
            memcpy(dst, buf, len + 3);
            memcpy(dst, buf, len + 4);
            memcpy(dst, buf, len + 5);
            memcpy(dst, buf, len + 6);
            memcpy(dst, buf, len + 7);
            memcpy(dst, buf, len + 8);
            memcpy(dst, buf, len + 9);
            memcpy(dst, buf, len + 10);
            memcpy(dst, buf, len + 11);
            memcpy(dst, buf, len + 12);
            memcpy(dst, buf, len + 13);
            memcpy(dst, buf, len + 14);
            memcpy(dst, buf, len + 15);
            memcpy(dst, buf, len + 16);
            memcpy(dst, buf, len + 17);
            memcpy(dst, buf, len + 18);
            memcpy(dst, buf, len + 19);
            memcpy(dst, buf, len + 20);
            memcpy(dst, buf, len + 21);
            memcpy(dst, buf, len + 22);
            memcpy(dst, buf, len + 23);
            memcpy(dst, buf, len + 24);
            memcpy(dst, buf, len + 25);
            memcpy(dst, buf, len + 26);
            memcpy(dst, buf, len + 27);
            memcpy(dst, buf, len + 28);
            memcpy(dst, buf, len + 29);
            memcpy(dst, buf, len + 30);
            memcpy(dst, buf, len + 31);
            memcpy(dst, buf, len + 32);
            memcpy(dst, buf, len + 33);
            memcpy(dst, buf, len + 34);
            memcpy(dst, buf, len + 35);
            memcpy(dst, buf, len + 36);
            memcpy(dst, buf, len + 37);
            memcpy(dst, buf, len + 38);
            memcpy(dst, buf, len + 39);
            memcpy(dst, buf, len + 40);
            memcpy(dst, buf, len + 41);
            memcpy(dst, buf, len + 42);
            memcpy(dst, buf, len + 43);
            memcpy(dst, buf, len + 44);
            memcpy(dst, buf, len + 45);
            memcpy(dst, buf, len + 46);
            memcpy(dst, buf, len + 47);
            memcpy(dst, buf, len + 48);
            memcpy(dst, buf, len + 49);
        }
    } else {
        memcpy(dst, buf, len);
    }
}
"""


@pytest.mark.slow
@pytest.mark.skipif(not _live_ready(),
                    reason="needs a joern install and user namespaces")
class TestLiveVerifyChannels:
    @pytest.fixture(scope="class")
    def live(self, tmp_path_factory):
        from core.audit.joern_backend import (
            _ensure_cpg_loaded,
            joern_tunables,
        )
        from packages.joern.server import JoernServer

        target = tmp_path_factory.mktemp("verify-target")
        (target / "copy.c").write_text(_FIXTURE)
        srv = JoernServer.from_tunables(joern_tunables())
        srv.start()
        try:
            assert _ensure_cpg_loaded(srv, target) is True
        except BaseException:
            srv.stop()
            raise
        yield srv, target
        srv.stop()

    def test_guard_dominance_answers_both_directions(self, live):
        from core.audit.joern_verify import run_guard_dominance_check

        srv, target = live
        refuted = run_guard_dominance_check(
            target_path=target, file_path="copy.c",
            function_name="guarded_copy", identifier="len",
            sink_call="memcpy", server=srv,
        )
        assert refuted.outcome == "refuted", (
            refuted.outcome, refuted.errors, refuted.details,
        )
        confirmed = run_guard_dominance_check(
            target_path=target, file_path="copy.c",
            function_name="unguarded_copy", identifier="len",
            sink_call="memcpy", server=srv,
        )
        assert confirmed.outcome == "confirmed", (
            confirmed.outcome, confirmed.errors, confirmed.details,
        )
        assert confirmed.matches, "unguarded sink sites are the evidence"

    def test_join_point_sink_is_not_refuted(self, live):
        # CDG ground truth: a guard with an EMPTY body followed by
        # the sink at the join point is the canonical missing-check
        # shape. Under dominatedBy the condition dominated the join
        # too and this booked a false REFUTATION with
        # verification-grade authority (live-reproduced); under
        # controlledBy the join-point sink is not control-dependent
        # on the guard and the unguarded site confirms.
        from core.audit.joern_verify import run_guard_dominance_check

        srv, target = live
        res = run_guard_dominance_check(
            target_path=target, file_path="copy.c",
            function_name="join_point_copy", identifier="len",
            sink_call="memcpy", server=srv,
        )
        assert res.outcome == "confirmed", (
            res.outcome, res.errors, res.details,
        )

    def test_early_return_guard_still_refutes(self, live):
        # The other CDG direction: behind an early-return guard the
        # sink IS control-dependent on the condition — the
        # refutation must survive the dominance->control-dependence
        # swap.
        from core.audit.joern_verify import run_guard_dominance_check

        srv, target = live
        res = run_guard_dominance_check(
            target_path=target, file_path="copy.c",
            function_name="early_return_copy", identifier="len",
            sink_call="memcpy", server=srv,
        )
        assert res.outcome == "refuted", (
            res.outcome, res.errors, res.details,
        )

    def test_flow_reachability_confirms_param_to_sink(self, live):
        from core.audit.joern_verify import run_flow_reachability_check

        srv, target = live
        res = run_flow_reachability_check(
            target_path=target, file_path="copy.c",
            function_name="unguarded_copy", source_id="buf",
            sink_call="memcpy", server=srv,
        )
        # The load-bearing assertion is transport, not engine tuning:
        # the protocol answered (facts parsed), and the pre-fix
        # symptom — error("flow query produced no protocol output") —
        # cannot recur.
        assert res.outcome != "error", (res.outcome, res.errors)
        assert res.outcome == "confirmed", (
            res.outcome, res.errors, res.details, res.raw_output[:500],
        )

    def test_missing_function_is_inconclusive_not_error(self, live):
        from core.audit.joern_verify import run_guard_dominance_check

        srv, target = live
        res = run_guard_dominance_check(
            target_path=target, file_path="copy.c",
            function_name="no_such_function", identifier="len",
            sink_call="memcpy", server=srv,
        )
        assert res.outcome == "inconclusive", (res.outcome, res.errors)


    def test_string_literal_facts_round_trip(self, live):
        """Payload content containing quotes must not break the echo
        parse: a top-level buffer binder echoed its populated state
        with raw inner quotes and errored the channel on any function
        whose facts quote a string literal."""
        from core.audit.joern_verify import run_flow_reachability_check

        srv, target = live
        res = run_flow_reachability_check(
            target_path=target, file_path="copy.c",
            function_name="literal_copy", source_id="buf",
            sink_call="memcpy", server=srv,
        )
        assert res.outcome != "error", (res.outcome, res.errors)

    def test_hostile_error_literal_cannot_veto_a_conviction(self, live):
        """A path:N: error: shaped string literal in the sink
        expression must not read as a compiler diagnostic and veto
        the unguarded-sink confirmation."""
        from core.audit.joern_verify import run_guard_dominance_check

        srv, target = live
        res = run_guard_dominance_check(
            target_path=target, file_path="copy.c",
            function_name="veto_probe", identifier="len",
            sink_call="memcpy", server=srv,
        )
        assert res.outcome == "confirmed", (
            res.outcome, res.errors, res.details,
        )


    def test_emission_cap_never_hides_an_unguarded_sink(self, live):
        """50 guarded decoys precede one genuinely unguarded 51st
        sink on a branch no identifier-check dominates (a condition
        node dominates ALL later straight-line code, so the unguarded
        sink must live in the else of an unrelated branch): the
        verdict quantifies over the FULL set, so the cap on evidence
        emission must not convert this confirmation into a
        refutation."""
        from core.audit.joern_verify import run_guard_dominance_check

        srv, target = live
        res = run_guard_dominance_check(
            target_path=target, file_path="copy.c",
            function_name="cap_evade", identifier="len",
            sink_call="memcpy", server=srv,
        )
        assert res.outcome == "confirmed", (
            res.outcome, res.errors, res.details,
        )
