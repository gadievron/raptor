"""Zero-dispatch re-sweep: receipt supply for suspicious outcomes
whose review dispatched no mechanical tools.

Hermetic — the chain builder, tool runner, prefilter, and source
reads are stubbed. Covers: dispatch + receipt stamping + audit-log
records, the already-dispatched and non-suspicious exclusions, the
wall bound in both directions, the SIGTERM rail, and the invariant
that the pass itself never changes a verdict (flips come only from
the promotion pass consuming the receipts)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import core.audit.orchestrator as orch
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _promote_suspicious,
    _resweep_zero_dispatch_suspicious,
)


def _outcome(name: str, status: str = "suspicious") -> ReviewOutcome:
    o = ReviewOutcome(
        file="a.c", function=name, status=status,
        body="looks off", hypothesis=f"overflow in {name}", line=3,
    )
    o.review_result = {"hypothesis": f"overflow in {name}"}
    return o


def _result(outcomes: list[ReviewOutcome]) -> OrchestratorResult:
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
    r.findings = sum(1 for o in outcomes if o.status == "finding")
    return r


def _config(tmp_path, **kw) -> OrchestratorConfig:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=tmp_path, out_dir=out, **kw)


def _patch_mechanical(
    monkeypatch, *, confirm: set[str], chain=True, calls=None,
) -> None:
    monkeypatch.setattr(
        "core.audit.orchestrator._hypothesis_to_tool_chain",
        lambda *a, **kw: (
            [{"type": "smt", "config": {"verb": "x"}}] if chain else []
        ),
    )

    def fake_chain(_chain, **kw):
        if calls is not None:
            calls.append(kw["function_name"])
        return ["smt:check"] if kw["function_name"] in confirm else []

    monkeypatch.setattr(
        "core.audit.orchestrator._run_tool_chain", fake_chain,
    )
    monkeypatch.setattr(
        "core.audit.orchestrator._is_detection_only", lambda t: False,
    )
    monkeypatch.setattr(
        "core.audit.orchestrator.run_prefilter",
        lambda **kw: SimpleNamespace(hits=[]),
    )
    monkeypatch.setattr(
        "core.audit.orchestrator._read_raw_source",
        lambda *a, **kw: "int f(void) { return 0; }",
    )


def _resweep_records(out_dir):
    path = out_dir / ".audit-log.jsonl"
    if not path.is_file():
        return []
    return [
        rec for rec in map(json.loads, path.read_text().splitlines())
        if rec.get("action") == "zero_dispatch_resweep"
    ]


class TestReceiptSupply:
    def test_zero_tool_suspicious_gets_chain_and_receipts(
        self, tmp_path, monkeypatch,
    ):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm={"fn0"}, calls=calls)
        result = _result([_outcome("fn0")])
        config = _config(tmp_path)
        _resweep_zero_dispatch_suspicious(result, config)
        assert calls == ["fn0"]
        outcome = result.outcomes[0]
        assert outcome.tools_dispatched == {"smt"}
        # Pure receipt supply: the verdict is untouched.
        assert outcome.status == "suspicious"
        assert result.findings == 0
        records = _resweep_records(config.out_dir)
        assert len(records) == 1
        assert records[0]["tools_dispatched"] == ["smt"]
        assert records[0]["confirmed"] == ["smt:check"]
        assert records[0]["cost_usd"] == 0.0

    def test_already_dispatched_and_non_suspicious_excluded(
        self, tmp_path, monkeypatch,
    ):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        had_tools = _outcome("fn_had")
        had_tools.tools_dispatched = {"semgrep"}
        clean = _outcome("fn_clean", status="clean")
        fresh = _outcome("fn_fresh")
        result = _result([had_tools, clean, fresh])
        _resweep_zero_dispatch_suspicious(result, _config(tmp_path))
        assert calls == ["fn_fresh"]

    def test_no_chain_records_skip_reason(self, tmp_path, monkeypatch):
        _patch_mechanical(monkeypatch, confirm=set(), chain=False)
        result = _result([_outcome("fn0")])
        config = _config(tmp_path)
        _resweep_zero_dispatch_suspicious(result, config)
        records = _resweep_records(config.out_dir)
        assert len(records) == 1
        assert records[0]["skip_reason"] == "no-mechanical-chain"
        assert not result.outcomes[0].tools_dispatched

    def test_flip_comes_only_from_the_promotion_pass(
        self, tmp_path, monkeypatch,
    ):
        _patch_mechanical(monkeypatch, confirm={"fn0"})
        result = _result([_outcome("fn0")])
        config = _config(tmp_path)
        _resweep_zero_dispatch_suspicious(result, config)
        assert result.outcomes[0].status == "suspicious"
        _promote_suspicious(result, config)
        assert result.outcomes[0].status == "finding"
        assert result.outcomes[0].evidence_tool == "smt:check"
        # The receipts survived the promotion copy.
        assert "smt" in (result.outcomes[0].tools_dispatched or set())


class TestBounds:
    def test_zero_budget_disables_the_pass(self, tmp_path, monkeypatch):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        result = _result([_outcome("fn0")])
        config = _config(tmp_path, zero_dispatch_resweep_seconds=0.0)
        _resweep_zero_dispatch_suspicious(result, config)
        assert calls == []
        assert _resweep_records(config.out_dir) == []

    def test_wall_bound_stops_mid_pass(self, tmp_path, monkeypatch):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        clock = {"now": 0.0}

        def fake_monotonic():
            clock["now"] += 10.0
            return clock["now"]

        monkeypatch.setattr(orch.time, "monotonic", fake_monotonic)
        result = _result([_outcome(f"fn{i}") for i in range(4)])
        config = _config(tmp_path, zero_dispatch_resweep_seconds=25.0)
        _resweep_zero_dispatch_suspicious(result, config)
        # pass_start=10; item0 checks at 20 (elapsed 10 < 25) and
        # sweeps; item1 checks at 50 (elapsed 40 >= 25) and stops.
        assert calls == ["fn0"]

    def test_generous_bound_sweeps_everything(self, tmp_path, monkeypatch):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        result = _result([_outcome(f"fn{i}") for i in range(4)])
        config = _config(tmp_path, zero_dispatch_resweep_seconds=3600.0)
        _resweep_zero_dispatch_suspicious(result, config)
        assert len(calls) == 4

    def test_sigterm_stops_before_dispatch(self, tmp_path, monkeypatch):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        monkeypatch.setattr(orch, "is_sigterm_requested", lambda: True)
        result = _result([_outcome("fn0")])
        config = _config(tmp_path)
        _resweep_zero_dispatch_suspicious(result, config)
        assert calls == []


@pytest.fixture(autouse=True)
def _quiet_synthesis(monkeypatch):
    # _promote_suspicious falls back to LLM-backed on-demand synthesis
    # for chain-less items; the flip test must stay hermetic.
    monkeypatch.setattr(
        orch, "_synthesize_unmapped_suspicious",
        lambda *a, **kw: None,
    )


class TestScopeExclusions:
    def test_gate_demoted_body_is_excluded(self, tmp_path, monkeypatch):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        o = _outcome("fn0")
        o.body = "[smt-infeasible: path condition unsat]\n\nlooks off"
        result = _result([o])
        config = _config(tmp_path)
        _resweep_zero_dispatch_suspicious(result, config)
        assert calls == []
        records = _resweep_records(config.out_dir)
        assert records[0]["skip_reason"] == "mechanical-gate-demotion"

    def test_counter_fenced_outcome_is_excluded(
        self, tmp_path, monkeypatch,
    ):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        o = _outcome("fn0")
        o.review_result = {
            "hypothesis": "overflow in fn0",
            "hypotheses": [{
                "mechanism": "overflow in fn0",
                "confidence": "medium",
                "counter": "callers validate the length before every "
                           "invocation of this helper",
            }],
        }
        result = _result([o])
        config = _config(tmp_path)
        _resweep_zero_dispatch_suspicious(result, config)
        assert calls == []
        records = _resweep_records(config.out_dir)
        assert records[0]["skip_reason"] == "counter-fenced"

    def test_environment_guard_stops_the_pass(self, tmp_path, monkeypatch):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        result = _result([_outcome("fn0")])
        config = _config(tmp_path)
        config.environment_guard_state = SimpleNamespace(concluded=True)
        _resweep_zero_dispatch_suspicious(result, config)
        assert calls == []


class TestParallelDispatch:
    def _capture_workers(self, monkeypatch) -> dict:
        import core.llm.concurrency as conc

        seen: dict = {}

        def fake_run_parallel(
            items, fn, *, max_workers=None, label="", on_error=None,
            **kw,
        ):
            seen["max_workers"] = max_workers
            seen["label"] = label
            return [fn(item) for item in items]

        monkeypatch.setattr(conc, "run_parallel", fake_run_parallel)
        return seen

    def test_parallel_pass_sweeps_everything_with_records(
        self, tmp_path, monkeypatch,
    ):
        # Real thread fan-out: every candidate gets its chain, its
        # own receipt slots, and its own audit-log record; verdicts
        # stay untouched.
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm={"fn0"}, calls=calls)
        result = _result([_outcome(f"fn{i}") for i in range(4)])
        config = _config(tmp_path)
        _resweep_zero_dispatch_suspicious(result, config, max_workers=4)
        assert sorted(calls) == [f"fn{i}" for i in range(4)]
        records = _resweep_records(config.out_dir)
        assert len(records) == 4
        for o in result.outcomes:
            assert o.tools_dispatched == {"smt"}
            assert o.status == "suspicious"

    def test_sigterm_stops_parallel_pass(self, tmp_path, monkeypatch):
        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        monkeypatch.setattr(orch, "is_sigterm_requested", lambda: True)
        result = _result([_outcome(f"fn{i}") for i in range(4)])
        _resweep_zero_dispatch_suspicious(
            result, _config(tmp_path), max_workers=4,
        )
        assert calls == []

    def test_worker_ceiling_binds_above_the_cap(
        self, tmp_path, monkeypatch,
    ):
        _patch_mechanical(monkeypatch, confirm=set())
        seen = self._capture_workers(monkeypatch)
        result = _result([_outcome(f"fn{i}") for i in range(8)])
        _resweep_zero_dispatch_suspicious(
            result, _config(tmp_path), max_workers=32,
        )
        assert seen["max_workers"] == orch._RESWEEP_SUBPROCESS_MAX_WORKERS

    def test_worker_count_below_the_cap_passes_through(
        self, tmp_path, monkeypatch,
    ):
        _patch_mechanical(monkeypatch, confirm=set())
        seen = self._capture_workers(monkeypatch)
        result = _result([_outcome(f"fn{i}") for i in range(8)])
        _resweep_zero_dispatch_suspicious(
            result, _config(tmp_path), max_workers=3,
        )
        assert seen["max_workers"] == 3

    def test_joern_server_clamps_to_the_joern_pass_cap(
        self, tmp_path, monkeypatch,
    ):
        _patch_mechanical(monkeypatch, confirm=set())
        seen = self._capture_workers(monkeypatch)
        result = _result([_outcome(f"fn{i}") for i in range(8)])
        _resweep_zero_dispatch_suspicious(
            result, _config(tmp_path), max_workers=32,
            joern_server=object(),
        )
        assert seen["max_workers"] == orch._JOERN_PASS_MAX_WORKERS

    def test_joern_server_below_cap_passes_through(
        self, tmp_path, monkeypatch,
    ):
        # Requested workers already below the joern-pass cap: the
        # clamp passes the value through unchanged — effective
        # workers == requested (1), which is the serial path, so the
        # fan-out must never be entered.
        import core.llm.concurrency as conc

        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        monkeypatch.setattr(
            conc, "run_parallel",
            lambda *a, **kw: pytest.fail("serial path must not fan out"),
        )
        result = _result([_outcome(f"fn{i}") for i in range(4)])
        _resweep_zero_dispatch_suspicious(
            result, _config(tmp_path), max_workers=1,
            joern_server=object(),
        )
        assert calls == [f"fn{i}" for i in range(4)]

    def test_ceiling_value_is_pinned(self):
        """Value pin (churn-prone-limits doctrine): the clamp
        assertions above follow the constant, so only an explicit pin
        makes a cap change a deliberate, test-visible act. Raising it
        multiplies concurrent sandboxed scanner subprocesses and
        widens wall-bound overshoot (in-flight items finish after the
        bound trips); lowering it serialises the pass so fewer
        outcomes earn receipts inside the wall budget."""
        assert orch._RESWEEP_SUBPROCESS_MAX_WORKERS == 4

    def test_single_worker_stays_on_the_serial_path(
        self, tmp_path, monkeypatch,
    ):
        import core.llm.concurrency as conc

        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        monkeypatch.setattr(
            conc, "run_parallel",
            lambda *a, **kw: pytest.fail("serial path must not fan out"),
        )
        result = _result([_outcome(f"fn{i}") for i in range(4)])
        _resweep_zero_dispatch_suspicious(
            result, _config(tmp_path), max_workers=1,
        )
        assert calls == [f"fn{i}" for i in range(4)]

    def test_single_candidate_stays_on_the_serial_path(
        self, tmp_path, monkeypatch,
    ):
        import core.llm.concurrency as conc

        calls: list[str] = []
        _patch_mechanical(monkeypatch, confirm=set(), calls=calls)
        monkeypatch.setattr(
            conc, "run_parallel",
            lambda *a, **kw: pytest.fail("serial path must not fan out"),
        )
        result = _result([_outcome("fn0")])
        _resweep_zero_dispatch_suspicious(
            result, _config(tmp_path), max_workers=4,
        )
        assert calls == ["fn0"]


class TestNoPhantomCoverage:
    def test_resweep_then_gate_resolution_never_cleans_gated_joern(
        self, tmp_path, monkeypatch,
    ):
        """MUST-FIX integration: with the joern gate tripped, the
        resweep records the joern step as SKIPPED (not dispatched),
        and the gate-resolution pass therefore cannot demote the
        outcome to clean on coverage the gate prevented."""
        from core.audit.joern_health import JoernChannelHealth

        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: [
                {"type": "joern", "config": {"sinks": ["system"]}},
            ],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: SimpleNamespace(hits=[]),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int f(void) { return 0; }",
        )
        monkeypatch.setattr(
            orch, "_joern_live_query",
            lambda *a, **kw: pytest.fail("dispatched through a trip"),
        )
        o = _outcome("fn0")
        o.hypothesis = "attacker data reaches system()"
        o.review_result = {
            "hypothesis": o.hypothesis,
            "cwe": "CWE-78",
            "mechanism": "command injection",
        }
        result = _result([o])
        config = _config(tmp_path)
        config.joern_health = JoernChannelHealth(unhealthy_after=1)
        config.joern_health.record_error("dead", key="a.c:x")
        config.joern_health.record_error("dead", key="a.c:y")
        assert config.joern_health.tripped

        _resweep_zero_dispatch_suspicious(
            result, config, joern_server=object(),
        )
        assert "joern" in (o.tools_skipped or set())
        assert "joern" not in (o.tools_dispatched or set())

        monkeypatch.setattr(
            orch, "_has_mechanical_corroboration",
            lambda *a, **kw: False,
        )
        monkeypatch.setattr(
            orch, "_probe_backed_suspicious", lambda *a, **kw: False,
        )
        orch._resolve_gate_demoted(
            result, config, None, None,
            available_tools={"joern": True},
        )
        assert result.outcomes[0].status != "clean"
