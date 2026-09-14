"""Parallel adversarial-refutation pass — serial/parallel equivalence.

Zero LLM calls: the refuter is a stub client keyed on the function
named in the prompt. Covers: identical verdicts/counters between the
serial and parallel paths, budget-stop honoured under parallel
dispatch (no new refutations after the trip, in-flight harvested),
the serial fallback for one worker / one item, and two-run
determinism including the audit-log trail (order-insensitive).
"""

from __future__ import annotations

import re
from types import SimpleNamespace

import core.llm.concurrency as _conc
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _adversarial_refute_pass,
)
from core.audit.record import load_audit_log


class _StubResponse:
    def __init__(self, result: dict, cost: float = 0.01, model: str = "stub"):
        self.result = result
        self.cost = cost
        self.model = model


class _PerFunctionClient:
    """Refuter stub: verdict chosen by the function the prompt names.

    ``generate_structured`` appends to ``calls`` (GIL-atomic) — safe
    for concurrent workers.
    """

    def __init__(self, refute: set[str]):
        self.refute = refute
        self.calls: list[str] = []
        self.config = SimpleNamespace(
            config_for_model=lambda name: (_ for _ in ()).throw(ValueError()),
        )

    def generate_structured(self, prompt, schema, *, system_prompt="", **kw):
        m = re.search(r"fn\d+", prompt)
        assert m is not None
        fn = m.group(0)
        self.calls.append(fn)
        if fn in self.refute:
            payload = {
                "verdict": "refuted",
                "counter_argument": "a dominating bounds check rules it out",
            }
        else:
            payload = {"verdict": "stands", "counter_argument": "no defeat"}
        return _StubResponse(payload)


def _outcome(idx: int, status: str) -> ReviewOutcome:
    return ReviewOutcome(
        file="src/a.c", function=f"fn{idx}", status=status,
        body="claimed bug", hypothesis=f"unchecked copy in fn{idx}",
        model="model-a", review_result={"status": status}, line=1,
    )


def _config(tmp_path, client) -> OrchestratorConfig:
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    return OrchestratorConfig(
        target_path=target, out_dir=out,
        adversarial=True, llm_client=client,
    )


def _result(outcomes: list[ReviewOutcome]) -> OrchestratorResult:
    result = OrchestratorResult(outcomes=list(outcomes))
    result.findings = sum(1 for o in outcomes if o.status == "finding")
    result.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
    result.clean = sum(1 for o in outcomes if o.status == "clean")
    return result


def _snapshot(result: OrchestratorResult) -> dict:
    return {
        "statuses": {
            (o.file, o.function): (
                o.status,
                (o.review_result or {}).get(
                    "adversarial_review", {},
                ).get("verdict", ""),
            )
            for o in result.outcomes
        },
        "findings": result.findings,
        "suspicious": result.suspicious,
        "clean": result.clean,
        "stands": result.adversarial_stands,
        "refuted": result.adversarial_refuted,
    }


def _mixed_outcomes(n: int = 6) -> list[ReviewOutcome]:
    return [
        _outcome(i, "finding" if i % 2 == 0 else "suspicious")
        for i in range(n)
    ]


class TestGatePrefixSharedAuthority:
    def test_new_gate_prefix_reaches_the_refuter_skip(self, tmp_path):
        # Drift guard: the refuter skip must read the shared
        # _GATE_DEMOTION_BODY_PREFIXES tuple so a new authoritative
        # gate prefix skips here too (gate-stamped bodies already
        # carry a mechanical resolution — re-attacking them wastes
        # refuter budget).
        import unittest.mock as mock

        from core.audit import orchestrator as orch

        outcome = _outcome(0, "finding")
        outcome.body = "[new-gate: G9] mechanically adjudicated"
        client = _PerFunctionClient(refute=set())
        with mock.patch.object(
            orch, "_GATE_DEMOTION_BODY_PREFIXES",
            orch._GATE_DEMOTION_BODY_PREFIXES + ("[new-gate:",),
        ):
            _adversarial_refute_pass(
                _result([outcome]), _config(tmp_path, client),
            )
        assert client.calls == []


class TestSerialParallelEquivalence:
    def test_same_verdicts_and_counters(self, tmp_path):
        refute = {"fn1", "fn2", "fn5"}

        serial = _result(_mixed_outcomes())
        _adversarial_refute_pass(
            serial, _config(tmp_path / "s", _PerFunctionClient(refute)),
            max_workers=1,
        )

        parallel = _result(_mixed_outcomes())
        _adversarial_refute_pass(
            parallel, _config(tmp_path / "p", _PerFunctionClient(refute)),
            max_workers=4,
        )

        assert _snapshot(serial) == _snapshot(parallel)
        # Refuted findings demote one level; refuted suspicious
        # (no tool receipt) demote to clean; stands keep status.
        by_fn = {o.function: o.status for o in parallel.outcomes}
        assert by_fn["fn2"] == "suspicious"  # finding, refuted
        assert by_fn["fn1"] == "clean"       # suspicious, refuted
        assert by_fn["fn0"] == "finding"     # stands
        assert by_fn["fn3"] == "suspicious"  # stands

    def test_parallel_run_is_deterministic(self, tmp_path):
        refute = {"fn0", "fn3"}
        snaps = []
        logs = []
        for tag in ("a", "b"):
            cfg = _config(tmp_path / tag, _PerFunctionClient(refute))
            result = _result(_mixed_outcomes(5))
            _adversarial_refute_pass(result, cfg, max_workers=4)
            snaps.append(_snapshot(result))
            entries = load_audit_log(cfg.out_dir)
            logs.append(sorted(
                (e["key"], e["verdict"], e["status"]) for e in entries
            ))
        assert snaps[0] == snaps[1]
        assert logs[0] == logs[1]
        assert len(logs[0]) == 5


class TestRefutationCap:
    def test_pretruncation_binds_to_the_serial_first_n(
        self, tmp_path, monkeypatch,
    ):
        """The cap is applied UP FRONT over outcome order, so the
        refutation budget binds to exactly the first N candidates —
        the same items the serial loop's cap bound to. Mutating the
        truncation (tail slice, off-by-one) attacks a different set
        and fails here."""
        import core.audit.orchestrator as orch
        monkeypatch.setattr(orch, "_MAX_ADVERSARIAL_REFUTATIONS", 2)

        serial_client = _PerFunctionClient(set())
        serial = _result(_mixed_outcomes(5))
        _adversarial_refute_pass(
            serial, _config(tmp_path / "s", serial_client), max_workers=1,
        )
        parallel_client = _PerFunctionClient(set())
        parallel = _result(_mixed_outcomes(5))
        _adversarial_refute_pass(
            parallel, _config(tmp_path / "p", parallel_client),
            max_workers=4,
        )
        assert sorted(serial_client.calls) == ["fn0", "fn1"]
        assert sorted(parallel_client.calls) == ["fn0", "fn1"]
        # The capped-out tail keeps its verdicts untouched.
        for res in (serial, parallel):
            for o in res.outcomes[2:]:
                assert "adversarial_review" not in (o.review_result or {})

    def test_at_the_cap_no_candidate_is_dropped(
        self, tmp_path, monkeypatch,
    ):
        """Boundary, other direction: exactly-at-cap candidate sets
        are attacked in full (an over-eager ``>=`` would drop one)."""
        import core.audit.orchestrator as orch
        monkeypatch.setattr(orch, "_MAX_ADVERSARIAL_REFUTATIONS", 5)

        client = _PerFunctionClient(set())
        result = _result(_mixed_outcomes(5))
        _adversarial_refute_pass(
            result, _config(tmp_path, client), max_workers=4,
        )
        assert sorted(client.calls) == [f"fn{i}" for i in range(5)]


class TestBudgetStop:
    def test_mid_run_trip_stops_new_dispatch_and_harvests(self, tmp_path):
        result = _result(_mixed_outcomes(8))

        class _TrippingClient(_PerFunctionClient):
            def generate_structured(self, prompt, schema, **kw):
                resp = super().generate_structured(prompt, schema, **kw)
                with result._lock:
                    result.total_cost_usd = 2.0  # trips max_cost_usd
                return resp

        client = _TrippingClient(set())
        config = _config(tmp_path, client)
        config.max_cost_usd = 1.0
        import time
        _adversarial_refute_pass(
            result, config, max_workers=2, start_time=time.monotonic(),
        )
        # First completed call trips the cap: in-flight calls finish
        # and their verdicts land; nothing new dispatches afterwards.
        assert 1 <= len(client.calls) < 8
        attacked = [
            o for o in result.outcomes
            if (o.review_result or {}).get("adversarial_review")
        ]
        assert len(attacked) == len(client.calls)

    def test_exhausted_budget_dispatches_nothing(self, tmp_path):
        import time
        client = _PerFunctionClient(set())
        config = _config(tmp_path, client)
        config.max_seconds = 1
        result = _result(_mixed_outcomes(4))
        _adversarial_refute_pass(
            result, config, max_workers=4,
            start_time=time.monotonic() - 100.0,
        )
        assert client.calls == []


class TestSerialFallback:
    def _forbid_parallel(self, monkeypatch):
        def _boom(*a, **kw):  # pragma: no cover - failure surface
            raise AssertionError("run_parallel used on the serial path")

        monkeypatch.setattr(_conc, "run_parallel", _boom)

    def test_single_worker_takes_serial_path(self, tmp_path, monkeypatch):
        self._forbid_parallel(monkeypatch)
        client = _PerFunctionClient({"fn0"})
        result = _result(_mixed_outcomes(2))
        _adversarial_refute_pass(
            result, _config(tmp_path, client), max_workers=1,
        )
        assert client.calls == ["fn0", "fn1"]
        assert result.outcomes[0].status == "suspicious"

    def test_single_item_takes_serial_path(self, tmp_path, monkeypatch):
        self._forbid_parallel(monkeypatch)
        client = _PerFunctionClient(set())
        result = _result([_outcome(0, "finding")])
        _adversarial_refute_pass(
            result, _config(tmp_path, client), max_workers=8,
        )
        assert result.outcomes[0].status == "finding"
        assert result.adversarial_stands == 1


class TestJoernCap:
    def test_joern_server_caps_workers(self, tmp_path, monkeypatch):
        captured: dict = {}

        def fake_run_parallel(items, fn, *, max_workers=None, **kw):
            captured["max_workers"] = max_workers
            return [fn(it) for it in items]

        monkeypatch.setattr(_conc, "run_parallel", fake_run_parallel)
        client = _PerFunctionClient(set())
        result = _result(_mixed_outcomes(4))
        _adversarial_refute_pass(
            result, _config(tmp_path, client),
            joern_server=object(), max_workers=8,
        )
        assert captured["max_workers"] == 2
