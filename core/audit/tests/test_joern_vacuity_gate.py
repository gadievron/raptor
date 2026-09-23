"""Joern live-lane vacuity gate: silence only refutes when the CPG
actually models the function.

Two-direction coverage: a covered function's silent query still counts
as refutation-grade "looked and found nothing", while an uncovered or
unanswerable coverage probe demotes the step to skipped — the channel
did not look, so it must stay out of the dispatch record (the same
phantom-coverage rule as the health-gated skips).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.audit.joern_backend import (
    _FN_COVERAGE_CACHE_ATTR,
    joern_function_in_cpg,
)
from core.audit.orchestrator import TierCounters, _run_tool_chain


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target: Path):
        self.target_path = target
        self.out_dir = None
        self.codeql_db_path = None
        self.project_sinks = None
        self.tool_chain_early_exit = False


class _QueryResult:
    def __init__(self, raw_output: str):
        self.raw_output = raw_output


class _Server:
    """Duck-typed Joern server: silent taint batches, scripted
    coverage answers.

    Transport-faithful on one load-bearing fact: println output does
    NOT come back through the query-sync transport (a real server
    returns '' for println-shaped probes) — only the FINAL
    EXPRESSION's string echo lands in raw_output. A probe that rides
    println must therefore fail against this double, exactly as it
    fails against joern itself.
    """

    def __init__(self, covers: bool | None):
        self._covers = covers
        self.queries: list[str] = []
        self.no_restart_flags: list[bool] = []

    def run_taint_queries_batch(self, pairs, timeout=0, errors_out=None,
                                **kwargs):
        return []

    def query(self, query: str, timeout: int = 0,
              check_length: bool = False,
              no_restart: bool = False) -> _QueryResult:
        self.no_restart_flags.append(no_restart)
        self.queries.append(query)
        if self._covers is None:
            raise RuntimeError("transport lost")
        if "println" in query:
            return _QueryResult("")
        last = query.strip().rsplit("\n", 1)[-1]
        nonce = last.split('"')[1]  # '"<nonce>:" + cpg....' → '<nonce>:'
        return _QueryResult(
            f'res0: String = "{nonce}{"true" if self._covers else "false"}"'
        )


def _write_tree(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "a.c").write_text("int f(void){}\n")


def _run(tmp_path: Path, server: Any) -> tuple[TierCounters, set]:
    _write_tree(tmp_path)
    tiers = {"joern": TierCounters()}
    skipped: set = set()
    _run_tool_chain(
        [{"type": "joern", "config": {"sinks": ["memcpy"]}}],
        config=_Cfg(tmp_path),
        file_path="src/a.c",
        function_name="f",
        source="int f(void){}",
        hypothesis="attacker data reaches memcpy",
        line_start=1,
        tier_counters=tiers,
        joern_server=server,
        skipped_types=skipped,
    )
    return tiers["joern"], skipped


class TestVacuityGate:
    def test_uncovered_function_skips_instead_of_refuting(self, tmp_path):
        tc, skipped = _run(tmp_path, _Server(covers=False))
        assert tc.refuted == 0
        assert tc.skipped == 1
        assert "joern" in skipped

    def test_unanswerable_probe_skips_instead_of_refuting(self, tmp_path):
        tc, skipped = _run(tmp_path, _Server(covers=None))
        assert tc.refuted == 0
        assert tc.skipped == 1
        assert "joern" in skipped

    def test_covered_function_silence_still_refutes(self, tmp_path):
        tc, skipped = _run(tmp_path, _Server(covers=True))
        assert tc.refuted == 1
        assert tc.skipped == 0
        assert "joern" not in skipped


class TestCoverageProbe:
    def test_answers_and_memoises_when_cache_installed(self):
        srv = _Server(covers=True)
        setattr(srv, _FN_COVERAGE_CACHE_ATTR, {})
        assert joern_function_in_cpg(srv, "f") is True
        assert joern_function_in_cpg(srv, "f") is True
        assert len(srv.queries) == 1

    def test_no_cache_attr_still_answers(self):
        srv = _Server(covers=False)
        assert joern_function_in_cpg(srv, "f") is False
        assert joern_function_in_cpg(srv, "f") is False
        assert len(srv.queries) == 2

    def test_probe_failure_is_none_and_memoised(self):
        # An unanswerable transport does not heal within one CPG load;
        # re-probing would pay a REPL round trip per silent hypothesis.
        srv = _Server(covers=None)
        setattr(srv, _FN_COVERAGE_CACHE_ATTR, {})
        assert joern_function_in_cpg(srv, "f") is None
        assert getattr(srv, _FN_COVERAGE_CACHE_ATTR) == {("f", None): None}
        assert joern_function_in_cpg(srv, "f") is None
        assert len(srv.queries) == 1

    def test_probe_query_never_rides_println(self):
        # println output does not return through query-sync on a real
        # server — the sentinel must be the final expression.
        srv = _Server(covers=True)
        assert joern_function_in_cpg(srv, "f") is True
        assert "println" not in srv.queries[0]

    def test_server_without_query_api_is_none(self):
        class _BatchOnly:
            def run_taint_queries_batch(self, pairs, timeout=0,
                                        errors_out=None, **kwargs):
                return []

        assert joern_function_in_cpg(_BatchOnly(), "f") is None

    def test_invalid_function_name_is_none(self):
        srv = _Server(covers=True)
        assert joern_function_in_cpg(srv, 'f"); bad') is None
        assert not srv.queries


class _Health:
    """Minimal joern_health double recording outcome calls."""

    def __init__(self):
        self.successes = 0
        self.errors: list[str] = []

    def allow_dispatch(self) -> bool:
        return True

    def record_success(self) -> None:
        self.successes += 1

    def record_error(self, detail: str = "", key: str = "") -> None:
        self.errors.append(detail)


class TestHealthAccounting:
    def test_answered_probe_counts_as_healthy_round_trip(self, tmp_path):
        cfg = _Cfg(tmp_path)
        cfg.joern_health = _Health()
        _write_tree(tmp_path)
        _run_tool_chain(
            [{"type": "joern", "config": {"sinks": ["memcpy"]}}],
            config=cfg, file_path="src/a.c", function_name="f",
            source="int f(void){}", hypothesis="taint reaches memcpy",
            line_start=1, tier_counters={"joern": TierCounters()},
            joern_server=_Server(covers=False), skipped_types=set(),
        )
        assert cfg.joern_health.successes == 1
        assert cfg.joern_health.errors == []

    def test_unanswerable_probe_counts_as_channel_error(self, tmp_path):
        cfg = _Cfg(tmp_path)
        cfg.joern_health = _Health()
        _write_tree(tmp_path)
        _run_tool_chain(
            [{"type": "joern", "config": {"sinks": ["memcpy"]}}],
            config=cfg, file_path="src/a.c", function_name="f",
            source="int f(void){}", hypothesis="taint reaches memcpy",
            line_start=1, tier_counters={"joern": TierCounters()},
            joern_server=_Server(covers=None), skipped_types=set(),
        )
        assert cfg.joern_health.successes == 0
        assert cfg.joern_health.errors == ["coverage probe unanswerable"]


class TestEmptySinkMenu:
    def test_no_sinks_skips_without_any_query(self, tmp_path):
        # An empty sink menu makes the live query vacuously silent —
        # it must not book a refutation even for a covered function.
        srv = _Server(covers=True)
        tiers = {"joern": TierCounters()}
        skipped: set = set()
        _write_tree(tmp_path)
        _run_tool_chain(
            [{"type": "joern", "config": {"sinks": []}}],
            config=_Cfg(tmp_path), file_path="src/a.c", function_name="f",
            source="int f(void){}", hypothesis="taint reaches a sink",
            line_start=1, tier_counters=tiers,
            joern_server=srv, skipped_types=skipped,
        )
        assert tiers["joern"].refuted == 0
        assert tiers["joern"].skipped == 1
        assert "joern" in skipped
        assert srv.queries == []


class TestProactiveValidateLeg:
    """The CWE-dispatch verification leg is a second live-query
    consumer: silence must pass the same coverage gate, and a vacuous
    dispatch must not stay in the dispatch record (it is added before
    the query runs)."""

    def _outcome(self):
        from core.audit.orchestrator import ReviewOutcome

        outcome = ReviewOutcome(
            file="src/a.c", function="f", status="suspicious",
            body="looks off",
            hypothesis="attacker data reaches system()", line=3,
        )
        outcome.review_result = {
            "cwe": "CWE-78", "mechanism": "command injection",
        }
        return outcome

    def _run(self, tmp_path, server):
        from core.audit.orchestrator import _proactive_validate

        _write_tree(tmp_path)
        tiers = {"joern": TierCounters(), "smt": TierCounters(),
                 "codeql": TierCounters(), "semgrep": TierCounters()}
        result = _proactive_validate(
            self._outcome(), _Cfg(tmp_path),
            tier_counters=tiers, joern_server=server,
        )
        return tiers["joern"], result

    def test_uncovered_function_skips_and_leaves_dispatch_record(
            self, tmp_path):
        tc, result = self._run(tmp_path, _Server(covers=False))
        assert tc.refuted == 0
        assert tc.skipped == 1
        assert "joern" not in (result.tools_dispatched or set())

    def test_covered_function_silence_still_refutes_and_ran(
            self, tmp_path):
        tc, result = self._run(tmp_path, _Server(covers=True))
        assert tc.refuted == 1
        assert tc.skipped == 0
        assert "joern" in (result.tools_dispatched or set())


class TestUnqueryableNames:
    """Names outside the substitution allowlist (C++ qualified,
    operators, $-prefixed) are definitional skips: no dial, no
    health accounting — booking them as channel errors farms the
    health breaker on ordinary C++ inventories."""

    def test_tool_chain_leg_skips_quietly(self, tmp_path):
        cfg = _Cfg(tmp_path)
        cfg.joern_health = _Health()
        _write_tree(tmp_path)
        srv = _Server(covers=True)
        tiers = {"joern": TierCounters()}
        skipped: set = set()
        _run_tool_chain(
            [{"type": "joern", "config": {"sinks": ["memcpy"]}}],
            config=cfg, file_path="src/a.c",
            function_name="Foo::operator()",
            source="int f(void){}", hypothesis="taint reaches memcpy",
            line_start=1, tier_counters=tiers,
            joern_server=srv, skipped_types=skipped,
        )
        assert tiers["joern"].skipped == 1
        assert tiers["joern"].refuted == 0
        assert "joern" in skipped
        assert srv.queries == []
        assert cfg.joern_health.errors == []
        assert cfg.joern_health.successes == 0

    def test_proactive_leg_skips_quietly(self, tmp_path):
        from core.audit.orchestrator import (
            ReviewOutcome,
            _proactive_validate,
        )

        cfg = _Cfg(tmp_path)
        cfg.joern_health = _Health()
        _write_tree(tmp_path)
        srv = _Server(covers=True)
        tiers = {"joern": TierCounters(), "smt": TierCounters(),
                 "codeql": TierCounters(), "semgrep": TierCounters()}
        outcome = ReviewOutcome(
            file="src/a.c", function="Foo::operator()",
            status="suspicious", body="looks off",
            hypothesis="attacker data reaches system()", line=3,
        )
        outcome.review_result = {
            "cwe": "CWE-78", "mechanism": "command injection",
        }
        result = _proactive_validate(
            outcome, cfg, tier_counters=tiers, joern_server=srv,
        )
        assert tiers["joern"].skipped == 1
        assert tiers["joern"].refuted == 0
        assert "joern" not in (result.tools_dispatched or set())
        assert srv.queries == []
        assert cfg.joern_health.errors == []

    def test_verify_channel_leg_skips_dotted_names(self, tmp_path):
        # The check functions require the BARE identifier shape —
        # stricter than the query-substitution allowlist, which admits
        # dotted qualified names ('Cls.method' on Python inventories).
        # A dotted name reaching the check returns outcome=error and
        # farms the breaker; the leg must quiet-skip it too.
        cfg = _Cfg(tmp_path)
        cfg.joern_health = _Health()
        _write_tree(tmp_path)
        srv = _Server(covers=True)
        tiers = {"joern_guard": TierCounters()}
        skipped: set = set()
        _run_tool_chain(
            [{"type": "joern_guard",
              "config": {"sinks": ["memcpy"]}}],
            config=cfg, file_path="src/a.c",
            function_name="Cls.method",
            source="int f(void){}",
            hypothesis="missing bounds check on `len` before memcpy",
            line_start=1, tier_counters=tiers,
            joern_server=srv, skipped_types=skipped,
        )
        assert tiers["joern_guard"].skipped == 1
        assert "joern_guard" in skipped
        assert srv.queries == []
        assert cfg.joern_health.errors == []

    def test_verify_channel_leg_skips_unqueryable_names(self, tmp_path):
        # Third live-lane consumer: joern_guard/joern_flow chain steps
        # route through the check functions, which return outcome=error
        # for names they cannot validate — the same breaker-farming
        # shape; the leg must quiet-skip before dispatch.
        cfg = _Cfg(tmp_path)
        cfg.joern_health = _Health()
        _write_tree(tmp_path)
        srv = _Server(covers=True)
        tiers = {"joern_guard": TierCounters()}
        skipped: set = set()
        _run_tool_chain(
            [{"type": "joern_guard",
              "config": {"sinks": ["memcpy"]}}],
            config=cfg, file_path="src/a.c",
            function_name="Foo::operator()",
            source="int f(void){}",
            hypothesis="missing bounds check on `len` before memcpy",
            line_start=1, tier_counters=tiers,
            joern_server=srv, skipped_types=skipped,
        )
        assert tiers["joern_guard"].skipped == 1
        assert "joern_guard" in skipped
        assert srv.queries == []
        assert cfg.joern_health.errors == []
class TestCoverageProbeAnchoring:
    """Pins the probe's two stated defenses.

    Nonce anchoring is the probe's forgery defense — nothing pinned
    it, so a refactor to bare ``":true"``/``":false"`` substring
    checks survived the whole battery. And the coverage query must
    exclude EXTERNAL method stubs: Joern mints a stub ``method`` node
    for every called-but-undefined name, so an unfiltered nameExact
    probe answers true off a mere call site in the parsed tree —
    exactly the gate's target cases (parse-failed file, exclude_dirs
    drop, language sliver). Verified against a live joern: a
    call-site-only name satisfies ``nameExact(...).nonEmpty`` and
    fails ``.filterNot(_.isExternal).nonEmpty``; a defined function
    passes both.
    """

    class _Scripted:
        """Server double echoing a scripted raw_output built from the
        probe's own nonce."""

        def __init__(self, raw_factory):
            self._raw = raw_factory
            self.queries: list[str] = []

        def query(self, query: str, timeout: int = 0,
                  check_length: bool = False,
                  no_restart: bool = False) -> _QueryResult:
            self.queries.append(query)
            last = query.strip().rsplit("\n", 1)[-1]
            nonce = last.split('"')[1]  # '<nonce>:'
            return _QueryResult(self._raw(nonce))

    def test_bare_true_in_noise_never_forges_coverage(self):
        # Noise carrying a bare ':true' while the anchored answer is
        # false: an un-anchored substring check reads the noise.
        srv = self._Scripted(
            lambda n: 'warning: :true is not a member here\n'
                      f'res0: String = "{n}false"'
        )
        assert joern_function_in_cpg(srv, "f") is False

    def test_wrong_nonce_answer_is_unparseable(self):
        # An answer stamped with a DIFFERENT nonce is not this
        # probe's answer — None (did not look), never a verdict.
        srv = self._Scripted(
            lambda n: 'res0: String = "deadbeefdead:true"'
        )
        assert joern_function_in_cpg(srv, "f") is None

    def test_probe_query_excludes_external_stubs(self):
        srv = _Server(covers=True)
        assert joern_function_in_cpg(srv, "f") is True
        q = srv.queries[0]
        assert ".filterNot(_.isExternal)" in q
        # Declared prototypes are isExternal=false with an empty
        # body — the body filter is what excludes them
        # (live-verified alongside the stub filter).
        assert ".filter(_.block.astChildren.nonEmpty)" in q
        # The filters must sit between the name match and the
        # emptiness check — filtering the right traversal.
        assert (q.index('nameExact("f")')
                < q.index(".filterNot(_.isExternal)")
                < q.index(".filter(_.block.astChildren.nonEmpty)")
                < q.index(".nonEmpty"))

    def test_file_bound_probe_pins_filename_binding(self):
        srv = _Server(covers=True)
        assert joern_function_in_cpg(
            srv, "f", file_path="src/a.c") is True
        q = srv.queries[0]
        # Exact-or-suffix compare: relative- and absolute-rooted CPG
        # imports both bind; anything else answers otherfile → False.
        assert 'm.filename == "src/a.c"' in q
        assert 'm.filename.endsWith("/src/a.c")' in q

    def test_same_named_definition_elsewhere_is_not_coverage(self):
        # Live-verified answer shape: a body-bearing definition in a
        # DIFFERENT file echoes "otherfile" — not coverage of this
        # item, so False (the caller skips, never refutes).
        srv = self._Scripted(lambda n: f'res0: String = "{n}otherfile"')
        assert joern_function_in_cpg(
            srv, "f", file_path="src/a.c") is False

    def test_cache_keyed_per_file_anchor(self):
        srv = _Server(covers=True)
        setattr(srv, _FN_COVERAGE_CACHE_ATTR, {})
        assert joern_function_in_cpg(srv, "f", file_path="a.c") is True
        assert joern_function_in_cpg(srv, "f", file_path="b.c") is True
        assert len(srv.queries) == 2  # distinct anchors, distinct memo

class TestCoverageMemoAcrossRestart:
    """The memo dies with the CPG (re)load — INCLUDING the mid-run
    ``restart()`` re-import, which never passes through lane start.

    A probe landing in a restart window gets the fail-fast restarting
    error (empty raw_output → answer None) and memoises it; pre-fix
    the only reset site was lane start, so the poisoned None survived
    the server's recovery and the joern refutation lane stayed
    silently removed for that function for the rest of the run — one
    restart, unbounded within-run evidence loss. The probe now keys
    the memo on the server's ``cpg_load_epoch`` (bumped by every
    successful import) and discards a stale memo.
    """

    class _RestartingServer:
        """Restart-window shape first, then healthy; a successful
        recovery bumps ``cpg_load_epoch`` exactly like the real
        ``restart()`` → ``import_cpg`` path."""

        def __init__(self) -> None:
            self.healthy = False
            self.cpg_load_epoch = 1
            self.calls = 0

        def recover(self) -> None:
            self.healthy = True
            self.cpg_load_epoch += 1

        def query(self, query: str, timeout: int = 0,
                  check_length: bool = False, **kwargs):
            from packages.joern.server import JoernResult, _RESTARTING_ERROR
            self.calls += 1
            if not self.healthy:
                return JoernResult(query=query, errors=[_RESTARTING_ERROR])
            last = query.strip().rsplit("\n", 1)[-1]
            nonce = last.split('"')[1]  # '<nonce>:'
            return JoernResult(
                query=query, raw_output=f'res0: String = "{nonce}true"',
            )

    def test_restart_window_poison_dies_with_the_reload(self):
        srv = self._RestartingServer()
        setattr(srv, _FN_COVERAGE_CACHE_ATTR, {})  # lane start
        assert joern_function_in_cpg(srv, "f") is None  # window: did not look
        srv.recover()
        # The re-import bumped the epoch: the poisoned None describes
        # a dead graph and must be re-asked, not replayed.
        assert joern_function_in_cpg(srv, "f") is True
        assert srv.calls == 2

    def test_memo_still_reused_within_one_epoch(self):
        srv = self._RestartingServer()
        srv.healthy = True
        setattr(srv, _FN_COVERAGE_CACHE_ATTR, {})
        assert joern_function_in_cpg(srv, "f") is True
        assert joern_function_in_cpg(srv, "f") is True
        assert srv.calls == 1  # epoch unchanged — memo answers

    def test_epochless_server_degrades_to_lane_start_reset(self):
        # A server double (or foreign handle) without cpg_load_epoch
        # keeps the pre-existing behavior: memo reset at lane start
        # only. Documented degradation, not an error.
        srv = _Server(covers=True)
        setattr(srv, _FN_COVERAGE_CACHE_ATTR, {})
        assert joern_function_in_cpg(srv, "f") is True
        assert joern_function_in_cpg(srv, "f") is True
        assert len(srv.queries) == 1


class TestCoverageProbeTimeout:
    """The probe's timeout rides the same CPG-scaled, deadline-clamped
    tunables as the live query it gates. The def-time 10s default
    timed out on a loaded shared REPL while the live queries it gates
    ran with minutes of budget — each per-function probe timeout
    booked a channel error, and 8 distinct keys trip the shared
    health gate (the whole joern lane goes dark for the run,
    fail-closed availability loss)."""

    class _TimeoutRecorder(_Server):
        def __init__(self, covers: bool):
            super().__init__(covers)
            self.timeouts: list[int] = []

        def query(self, query: str, timeout: int = 0,
                  check_length: bool = False,
                  no_restart: bool = False) -> _QueryResult:
            self.timeouts.append(timeout)
            return super().query(query, timeout=timeout,
                                 check_length=check_length,
                                 no_restart=no_restart)

    def test_probe_timeout_matches_live_query_budget(self, tmp_path):
        from core.audit.orchestrator import _joern_live_timeout_s
        srv = self._TimeoutRecorder(covers=False)
        cfg = _Cfg(tmp_path)
        expected = _joern_live_timeout_s(cfg, srv)
        assert expected > 0
        _write_tree(tmp_path)
        _run_tool_chain(
            [{"type": "joern", "config": {"sinks": ["memcpy"]}}],
            config=cfg, file_path="src/a.c", function_name="f",
            source="int f(void){}", hypothesis="taint reaches memcpy",
            line_start=1, tier_counters={"joern": TierCounters()},
            joern_server=srv, skipped_types=set(),
        )
        # Last query is the coverage probe (the taint batch rides
        # run_taint_queries_batch, not query()).
        assert srv.timeouts
        assert srv.timeouts[-1] == expected


class TestProbeRestartDecoupling:
    """The probe must never wield query()'s timeout-triggered restart,
    and a probe TIMEOUT must not book a channel error into the shared
    health gate.

    Both halves of the same coupling: the REPL is single-threaded and
    shared across sweep threads, live taint timeouts are scaled to
    minutes, so a short probe queued behind a sibling's taint query
    times out on a HEALTHY server. Pre-fix that timeout (a) dispatched
    restart() — SIGKILL ladder, JVM boot, CPG re-import, the sibling's
    in-flight evidence destroyed — and (b) booked one health-gate
    error per probed function, tripping the gate (8 distinct keys) and
    taking the whole joern lane dark for the run.
    """

    class _TimeoutServer(_Server):
        """Silent taint batches; every probe post times out."""

        def __init__(self) -> None:
            super().__init__(covers=True)

        def query(self, query: str, timeout: int = 0,
                  check_length: bool = False,
                  no_restart: bool = False) -> object:
            self.no_restart_flags.append(no_restart)
            self.queries.append(query)
            from packages.joern.models import JoernResult
            return JoernResult(
                query=query,
                errors=[f"query timed out after {timeout}s"],
            )

    class _StrictLegacyServer:
        """No no_restart seam, no **kwargs — the fallback target."""

        def __init__(self) -> None:
            self.queries: list[str] = []

        def query(self, query: str, timeout: int = 0,
                  check_length: bool = False) -> _QueryResult:
            self.queries.append(query)
            last = query.strip().rsplit("\n", 1)[-1]
            nonce = last.split('"')[1]
            return _QueryResult(f'res0: String = "{nonce}true"')

    def test_probe_posts_with_no_restart(self):
        srv = _Server(covers=True)
        assert joern_function_in_cpg(srv, "f") is True
        assert srv.no_restart_flags == [True]

    def test_probe_falls_back_without_the_seam(self):
        # A duck-typed server without the seam still answers — the
        # probe re-posts plainly (read-only, idempotent).
        srv = self._StrictLegacyServer()
        assert joern_function_in_cpg(srv, "f") is True
        assert len(srv.queries) == 1

    def test_probe_timeout_reported_via_errors_out(self):
        srv = self._TimeoutServer()
        errors: list = []
        assert joern_function_in_cpg(srv, "f", errors_out=errors) is None
        assert any("timed out" in str(e) for e in errors)

    def test_timeout_none_is_not_memoised(self):
        # With no_restart a probe timeout no longer bumps the load
        # epoch via a restart — memoising it would let ONE contention
        # timeout silence this function's lane until a reload that
        # may never come. Contention clears on its own: re-ask.
        srv = self._TimeoutServer()
        setattr(srv, _FN_COVERAGE_CACHE_ATTR, {})
        assert joern_function_in_cpg(srv, "f") is None
        assert getattr(srv, _FN_COVERAGE_CACHE_ATTR) == {}
        assert joern_function_in_cpg(srv, "f") is None
        assert len(srv.queries) == 2  # re-asked, not replayed

    def test_transport_dead_none_stays_memoised(self):
        # The carve-out must not widen: a non-timeout unanswerable
        # transport does not heal within one load — still memoised.
        srv = _Server(covers=None)
        setattr(srv, _FN_COVERAGE_CACHE_ATTR, {})
        assert joern_function_in_cpg(srv, "f") is None
        assert joern_function_in_cpg(srv, "f") is None
        assert len(srv.queries) == 1

    def _run_proactive(self, tmp_path, server):
        from core.audit.orchestrator import (
            ReviewOutcome,
            _proactive_validate,
        )
        cfg = _Cfg(tmp_path)
        cfg.joern_health = _Health()
        _write_tree(tmp_path)
        tiers = {"joern": TierCounters(), "smt": TierCounters(),
                 "codeql": TierCounters(), "semgrep": TierCounters()}
        outcome = ReviewOutcome(
            file="src/a.c", function="f", status="suspicious",
            body="looks off",
            hypothesis="attacker data reaches system()", line=3,
        )
        outcome.review_result = {
            "cwe": "CWE-78", "mechanism": "command injection",
        }
        result = _proactive_validate(
            outcome, cfg, tier_counters=tiers, joern_server=server,
        )
        return cfg, tiers["joern"], result

    def test_proactive_probe_timeout_skips_without_health_error(
            self, tmp_path):
        # The CWE-dispatch verification leg is the SECOND probe
        # booking site — the timeout carve-out must cover it too, or
        # the health-gate poisoning returns through this leg.
        srv = self._TimeoutServer()
        cfg, tc, result = self._run_proactive(tmp_path, srv)
        assert tc.refuted == 0
        assert tc.skipped == 1
        assert "joern" not in (result.tools_dispatched or set())
        assert cfg.joern_health.errors == []
        assert cfg.joern_health.successes == 0

    def test_proactive_unparseable_still_books_channel_error(
            self, tmp_path):
        # Carve-out must not widen on this leg either.
        cfg, tc, _result = self._run_proactive(
            tmp_path, _Server(covers=None),
        )
        assert tc.skipped == 1
        assert cfg.joern_health.errors == ["coverage probe unanswerable"]

    def test_proactive_probe_rides_the_live_budget(self, tmp_path):
        # Mirror of the tool-chain leg's timeout inheritance: the
        # def-time 10s default times out on a loaded shared REPL.
        from core.audit.orchestrator import _joern_live_timeout_s

        class _Recorder(_Server):
            def __init__(self) -> None:
                super().__init__(covers=True)
                self.timeouts: list[int] = []

            def query(self, query: str, timeout: int = 0,
                      check_length: bool = False,
                      no_restart: bool = False) -> _QueryResult:
                self.timeouts.append(timeout)
                return super().query(query, timeout=timeout,
                                     check_length=check_length,
                                     no_restart=no_restart)

        srv = _Recorder()
        cfg, _tc, _result = self._run_proactive(tmp_path, srv)
        expected = _joern_live_timeout_s(cfg, srv)
        assert expected > 0
        assert srv.timeouts
        assert srv.timeouts[-1] == expected

    def test_probe_timeout_skips_without_health_error(self, tmp_path):
        cfg = _Cfg(tmp_path)
        cfg.joern_health = _Health()
        _write_tree(tmp_path)
        tiers = {"joern": TierCounters()}
        skipped: set = set()
        _run_tool_chain(
            [{"type": "joern", "config": {"sinks": ["memcpy"]}}],
            config=cfg, file_path="src/a.c", function_name="f",
            source="int f(void){}", hypothesis="taint reaches memcpy",
            line_start=1, tier_counters=tiers,
            joern_server=self._TimeoutServer(), skipped_types=skipped,
        )
        # Still a skip (no verdict, out of the dispatch record)...
        assert tiers["joern"].refuted == 0
        assert tiers["joern"].skipped == 1
        assert "joern" in skipped
        # ...but the health gate hears NOTHING: contention is not
        # channel sickness (a stuck channel feeds the gate through the
        # live queries' own timeouts).
        assert cfg.joern_health.errors == []
        assert cfg.joern_health.successes == 0

    def test_unparseable_echo_still_books_channel_error(self, tmp_path):
        # The timeout carve-out must not widen: a non-timeout
        # unanswerable probe keeps booking the channel error.
        cfg = _Cfg(tmp_path)
        cfg.joern_health = _Health()
        _write_tree(tmp_path)
        _run_tool_chain(
            [{"type": "joern", "config": {"sinks": ["memcpy"]}}],
            config=cfg, file_path="src/a.c", function_name="f",
            source="int f(void){}", hypothesis="taint reaches memcpy",
            line_start=1, tier_counters={"joern": TierCounters()},
            joern_server=_Server(covers=None), skipped_types=set(),
        )
        assert cfg.joern_health.errors == ["coverage probe unanswerable"]
