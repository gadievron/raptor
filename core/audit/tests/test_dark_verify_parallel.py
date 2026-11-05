"""Parallel dark-verification pass — serial/parallel equivalence.

No sandbox or LLM calls: the LLM client is a stub returning a witness
spec and ``execute_witness`` is stubbed to a fixed per-function
verdict. Covers: identical verdicts/records between the serial and
parallel paths, budget-stop honoured under parallel dispatch, the
serial fallback for one worker / one item, two-run determinism, and
the containment-floor record-then-raise contract under parallel
dispatch (exactly one unverifiable-environment record, folded in item
order, typed error re-raised, further dispatch stopped).
"""

from __future__ import annotations

import json
import re
import time

import pytest

import core.llm.concurrency as _conc
from core.audit.dark_verify import DarkVerifyResult
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _run_dark_verification,
)
from core.sandbox.errors import SandboxFloorError
from core.sandbox.tiers import ContainmentTier


def _outcome(idx: int) -> ReviewOutcome:
    return ReviewOutcome(
        file=f"m{idx}.py", function=f"f{idx}", status="dark",
        body="suspected bug", hypothesis=f"bad input handling in f{idx}",
    )


def _result(outcomes: list[ReviewOutcome]) -> OrchestratorResult:
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    r.dormant = sum(1 for o in outcomes if o.status == "dark")
    return r


def _config(tmp_path) -> OrchestratorConfig:
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    return OrchestratorConfig(target_path=tmp_path, out_dir=out)


def _witness_llm(calls: list[str] | None = None):
    """Stub LLM: returns a parseable witness spec for the outcome the
    prompt names (the function name is embedded in the prompt)."""

    def llm(prompt: str, system: str) -> str:
        if calls is not None:
            calls.append(prompt)
        m = re.search(r"m(\d+)\.py", prompt)
        assert m is not None
        fn = f"f{m.group(1)}"
        return json.dumps({
            "module_path": "m",
            "function": fn,
            "args": [1],
            "expected_exception": "ValueError",
            "rationale": "witness",
        })

    return llm


def _stub_execute(monkeypatch, confirm: set[str]) -> None:
    def fake_execute(spec, target_root, **kw):
        verdict = "confirmed" if spec.function in confirm else "refuted"
        return DarkVerifyResult(finding_key=spec.finding_key, verdict=verdict, match_detail="stubbed", violation_observed=verdict == "confirmed")

    monkeypatch.setattr(
        "core.audit.dark_verify.execute_witness", fake_execute,
    )


def _floor_error() -> SandboxFloorError:
    return SandboxFloorError(
        "sandbox containment floor violated",
        "install uidmap; re-run",
        achievable=ContainmentTier.LANDLOCK_ONLY,
        floor=ContainmentTier.MOUNT_NS,
        setup_category="U",
    )


def _stub_execute_refusing(
    monkeypatch, refuse: set[str], confirm: set[str] | None = None,
) -> None:
    confirmed = confirm or set()

    def fake_execute(spec, target_root, **kw):
        if spec.function in refuse:
            raise _floor_error()
        verdict = "confirmed" if spec.function in confirmed else "refuted"
        return DarkVerifyResult(finding_key=spec.finding_key, verdict=verdict, match_detail="stubbed", violation_observed=verdict == "confirmed")

    monkeypatch.setattr(
        "core.audit.dark_verify.execute_witness", fake_execute,
    )


def _snapshot(result: OrchestratorResult) -> dict:
    return {
        "statuses": {
            (o.file, o.function): (o.status, o.evidence_tool or "")
            for o in result.outcomes
        },
        "findings": result.findings,
        "clean": result.clean,
        "dormant": result.dormant,
        "suspicious": result.suspicious,
    }


def _run(result, config, workers: int, calls=None) -> None:
    _run_dark_verification(
        result, config,
        llm_client=_witness_llm(calls),
        start_time=time.monotonic(),
        max_workers=workers,
        include_diagnostics=True,
    )


class TestSerialParallelEquivalence:
    def test_same_verdicts_counters_and_records(self, tmp_path, monkeypatch):
        confirm = {"f0", "f2", "f4"}
        _stub_execute(monkeypatch, confirm)

        serial_cfg = _config(tmp_path / "s")
        serial = _result([_outcome(i) for i in range(6)])
        _run(serial, serial_cfg, workers=1)

        parallel_cfg = _config(tmp_path / "p")
        parallel = _result([_outcome(i) for i in range(6)])
        _run(parallel, parallel_cfg, workers=4)

        assert _snapshot(serial) == _snapshot(parallel)
        for o in parallel.outcomes:
            expected = "finding" if o.function in confirm else "dark"
            assert o.status == expected

        s_recs = json.loads(
            (serial_cfg.out_dir / "dark-verify-results.json").read_text())
        p_recs = json.loads(
            (parallel_cfg.out_dir / "dark-verify-results.json").read_text())
        # Verdicts fold in item order on both paths.
        assert s_recs == p_recs

    def test_parallel_run_is_deterministic(self, tmp_path, monkeypatch):
        _stub_execute(monkeypatch, {"f1", "f3"})
        snaps = []
        recs = []
        for tag in ("a", "b"):
            cfg = _config(tmp_path / tag)
            result = _result([_outcome(i) for i in range(5)])
            _run(result, cfg, workers=4)
            snaps.append(_snapshot(result))
            recs.append(json.loads(
                (cfg.out_dir / "dark-verify-results.json").read_text()))
        assert snaps[0] == snaps[1]
        assert recs[0] == recs[1]


class TestBudgetStop:
    def test_exhausted_budget_dispatches_nothing_parallel(
        self, tmp_path, monkeypatch,
    ):
        _stub_execute(monkeypatch, set())
        config = _config(tmp_path)
        config.max_seconds = 1
        result = _result([_outcome(i) for i in range(4)])
        calls: list[str] = []
        _run_dark_verification(
            result, config,
            llm_client=_witness_llm(calls),
            start_time=time.monotonic() - 100.0,
            max_workers=4,
            include_diagnostics=True,
        )
        assert calls == []
        assert all(o.status == "dark" for o in result.outcomes)

    def test_mid_run_trip_stops_new_dispatch_and_harvests(
        self, tmp_path, monkeypatch,
    ):
        confirm = {f"f{i}" for i in range(8)}
        _stub_execute(monkeypatch, confirm)
        config = _config(tmp_path)
        config.max_cost_usd = 1.0
        result = _result([_outcome(i) for i in range(8)])
        calls: list[str] = []
        base_llm = _witness_llm(calls)

        def tripping_llm(prompt: str, system: str) -> str:
            out = base_llm(prompt, system)
            with result._lock:
                result.total_cost_usd = 2.0  # trips max_cost_usd
            return out

        _run_dark_verification(
            result, config,
            llm_client=tripping_llm,
            start_time=time.monotonic(),
            max_workers=2,
            include_diagnostics=True,
        )
        # The first completed call trips the cap: workers already past
        # the gate finish (and their verdicts land), nothing new
        # dispatches afterwards.
        assert 1 <= len(calls) < 8
        promoted = [o for o in result.outcomes if o.status == "finding"]
        assert len(promoted) == len(calls)
        untouched = [o for o in result.outcomes if o.status == "dark"]
        assert len(untouched) == 8 - len(calls)


class TestFloorRefusalParallel:
    """The landed record-then-raise contract survives parallel
    dispatch: exactly one unverifiable-environment record (the first
    refusing item in ITEM order), persisted, then the typed error
    re-raised from the calling thread; a refusal is host-deterministic
    so further probe dispatch stops."""

    def test_refusal_records_once_then_raises(self, tmp_path, monkeypatch):
        _stub_execute_refusing(
            monkeypatch, refuse={f"f{i}" for i in range(6)},
        )
        config = _config(tmp_path)
        result = _result([_outcome(i) for i in range(6)])
        calls: list[str] = []
        with pytest.raises(SandboxFloorError):
            _run(result, config, workers=4, calls=calls)

        records = json.loads(
            (config.out_dir / "dark-verify-results.json").read_text())
        assert len(records) == 1
        rec = records[0]
        assert rec["verdict"] == "error"
        assert rec["match_detail"].startswith("unverifiable_environment:")
        # Environment verdict, not a hypothesis verdict: no status
        # moves, no counter moves.
        assert rec["status"] == "dark"
        assert all(o.status == "dark" for o in result.outcomes)
        assert result.findings == 0
        assert result.clean == 0
        # Sticky: the refusal stops further probe dispatch — at most
        # the workers already past the gate spend an LLM call.
        assert 1 <= len(calls) <= 4

    def test_prior_verdicts_fold_before_the_refusal(
        self, tmp_path, monkeypatch,
    ):
        """Verdicts already probed AND earlier in item order stay
        applied; the refusal record is appended after them, then the
        pass raises — later slots are discarded, matching the serial
        pass which never probes past the refusal. The refusing probe
        is held until every earlier probe has finished so the
        in-flight-straggler race (an earlier item gated out by the
        sticky stop) cannot blur the assertion."""
        import threading

        earlier_done = threading.Event()
        finished: set[str] = set()
        lock = threading.Lock()

        def fake_execute(spec, target_root, **kw):
            if spec.function == "f5":
                assert earlier_done.wait(timeout=30)
                raise _floor_error()
            with lock:
                finished.add(spec.function)
                if finished >= {f"f{i}" for i in range(5)}:
                    earlier_done.set()
            return DarkVerifyResult(
                finding_key=spec.finding_key, verdict="confirmed", match_detail="stubbed",
                violation_observed=True,
            )

        monkeypatch.setattr(
            "core.audit.dark_verify.execute_witness", fake_execute,
        )
        config = _config(tmp_path)
        result = _result([_outcome(i) for i in range(6)])
        with pytest.raises(SandboxFloorError):
            _run(result, config, workers=2)

        records = json.loads(
            (config.out_dir / "dark-verify-results.json").read_text())
        assert len(records) == 6
        assert [r["verdict"] for r in records[:5]] == ["confirmed"] * 5
        assert records[5]["verdict"] == "error"
        assert records[5]["match_detail"].startswith(
            "unverifiable_environment:")
        assert all(o.status == "finding" for o in result.outcomes[:5])
        assert result.outcomes[5].status == "dark"
        assert result.findings == 5

    def test_serial_parallel_refusal_equivalence(
        self, tmp_path, monkeypatch,
    ):
        """First-item refusal: both paths persist the identical single
        refusal record and leave every outcome untouched — probes that
        raced ahead in the parallel world never fold their verdicts."""
        snaps = []
        recs = []
        for tag, workers in (("s", 1), ("p", 4)):
            _stub_execute_refusing(
                monkeypatch, refuse={"f0"},
                confirm={f"f{i}" for i in range(1, 4)},
            )
            cfg = _config(tmp_path / tag)
            result = _result([_outcome(i) for i in range(4)])
            with pytest.raises(SandboxFloorError):
                _run(result, cfg, workers=workers)
            snaps.append(_snapshot(result))
            recs.append(json.loads(
                (cfg.out_dir / "dark-verify-results.json").read_text()))
        assert snaps[0] == snaps[1]
        assert recs[0] == recs[1]
        assert len(recs[0]) == 1
        assert recs[0][0]["verdict"] == "error"


class TestSerialFallback:
    def _forbid_parallel(self, monkeypatch):
        def _boom(*a, **kw):  # pragma: no cover - failure surface
            raise AssertionError("run_parallel used on the serial path")

        monkeypatch.setattr(_conc, "run_parallel", _boom)

    def test_single_worker_takes_serial_path(self, tmp_path, monkeypatch):
        _stub_execute(monkeypatch, {"f0"})
        self._forbid_parallel(monkeypatch)
        result = _result([_outcome(0), _outcome(1)])
        _run(result, _config(tmp_path), workers=1)
        assert result.outcomes[0].status == "finding"
        assert result.outcomes[1].status == "dark"

    def test_single_item_takes_serial_path(self, tmp_path, monkeypatch):
        _stub_execute(monkeypatch, {"f0"})
        self._forbid_parallel(monkeypatch)
        result = _result([_outcome(0)])
        _run(result, _config(tmp_path), workers=8)
        assert result.outcomes[0].status == "finding"
