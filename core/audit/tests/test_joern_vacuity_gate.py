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

    def run_taint_queries_batch(self, pairs, timeout=0, errors_out=None,
                                **kwargs):
        return []

    def query(self, query: str, timeout: int = 0,
              check_length: bool = False) -> _QueryResult:
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
        assert getattr(srv, _FN_COVERAGE_CACHE_ATTR) == {"f": None}
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
