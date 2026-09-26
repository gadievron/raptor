"""Pre-dispatch environment gating for passes beyond the main loop.

The main executor pass drives ``EnvironmentGuard.tick()`` before every
dispatch; the passes that run outside it reach the same machinery
through ``environment.make_dispatch_gate`` (and the
``run_executor_sync`` adapter ``make_executor_on_tick``). These tests
cover the helper contract and the shared re-review driver
(``_collect_reviews_until_budget``): a concluding guard stops new
dispatches with in-flight work harvested, a pause defers dispatch and
resumes, and a guard-less run keeps its pre-existing paths.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

import core.audit.orchestrator as _orch
from core.audit.environment import (
    make_dispatch_gate,
    make_executor_on_tick,
)
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _adversarial_refute_pass,
    _callee_contract_requeue,
    _collect_reviews_until_budget,
    _retry_error_outcomes,
    _run_dark_verification,
)


class _StubGuard:
    """Duck-typed guard: countable ticks, settable conclusion, and an
    optional pause (tick blocks until released) — the three behaviours
    the gate consumes. ``conclude_reason`` satisfies ``_check_budget``'s
    booking of a concluded guard."""

    conclude_reason = "stub environment fault"

    def __init__(self) -> None:
        self.ticks = 0
        self.concluded = False
        self._lock = threading.Lock()
        self._release = threading.Event()
        self._release.set()

    def pause(self) -> None:
        self._release.clear()

    def resume(self) -> None:
        self._release.set()

    def tick(self) -> None:
        with self._lock:
            self.ticks += 1
        self._release.wait(timeout=10.0)


def _config(guard: Any) -> SimpleNamespace:
    return SimpleNamespace(environment_guard_state=guard)


# ── make_dispatch_gate ───────────────────────────────────────────────


class TestMakeDispatchGate:
    def test_no_guard_returns_none(self):
        assert make_dispatch_gate(SimpleNamespace()) is None
        assert make_dispatch_gate(_config(None)) is None

    def test_ticks_then_rechecks_stop_rails(self):
        guard = _StubGuard()
        order: list[str] = []

        def stop_check() -> bool:
            order.append(f"rails-after-{guard.ticks}-ticks")
            return False

        gate = make_dispatch_gate(_config(guard), stop_check=stop_check)
        assert gate is not None
        assert gate() is False
        # The stop-rail re-check ran AFTER the tick (main-pass order).
        assert order == ["rails-after-1-ticks"]

    def test_stop_check_verdict_is_returned(self):
        guard = _StubGuard()
        gate = make_dispatch_gate(_config(guard), stop_check=lambda: True)
        assert gate is not None
        assert gate() is True

    def test_without_stop_check_reports_conclusion(self):
        guard = _StubGuard()
        gate = make_dispatch_gate(_config(guard))
        assert gate is not None
        assert gate() is False
        guard.concluded = True
        assert gate() is True
        assert guard.ticks == 2


class TestMakeExecutorOnTick:
    def test_no_guard_returns_none(self):
        assert make_executor_on_tick(SimpleNamespace()) is None

    def test_tick_drives_the_guard(self):
        guard = _StubGuard()
        on_tick = make_executor_on_tick(_config(guard))
        assert on_tick is not None
        assert on_tick({"file": "a.c", "name": "f"}) is None
        assert guard.ticks == 1


# ── _collect_reviews_until_budget with a dispatch gate ───────────────


def _items(n: int) -> list[int]:
    return list(range(n))


class TestCollectReviewsDispatchGate:
    def test_serial_concluding_gate_stops_before_dispatch(self):
        guard = _StubGuard()
        calls: list[int] = []

        def do_review(item: int) -> int:
            calls.append(item)
            if item == 1:
                guard.concluded = True
            return item

        gate = make_dispatch_gate(
            _config(guard), stop_check=lambda: guard.concluded,
        )
        collected = _collect_reviews_until_budget(
            _items(5), do_review, lambda: guard.concluded, 1,
            phase_label="test", dispatch_gate=gate,
        )
        # Items 0 and 1 dispatched; the gate concluded before item 2.
        assert calls == [0, 1]
        assert collected == [0, 1]
        # One tick per attempted dispatch (2 dispatched + 1 refused).
        assert guard.ticks == 3

    def test_serial_no_gate_is_the_pre_existing_path(self):
        calls: list[int] = []
        collected = _collect_reviews_until_budget(
            _items(3), lambda i: calls.append(i) or i, lambda: False, 1,
            phase_label="test",
        )
        assert calls == [0, 1, 2]
        assert collected == [0, 1, 2]

    def test_parallel_gate_refuses_at_worker_entry(self):
        """A gate that trips after two dispatches stops every later
        item at worker entry — futures were all submitted up front, so
        without the worker-entry gate they would all still run."""
        calls: list[int] = []
        calls_lock = threading.Lock()
        allowed = [2]

        def gate() -> bool:
            with calls_lock:
                if allowed[0] > 0:
                    allowed[0] -= 1
                    return False
                return True

        def do_review(item: int) -> int:
            with calls_lock:
                calls.append(item)
            return item

        collected = _collect_reviews_until_budget(
            _items(6), do_review, lambda: False, 2,
            phase_label="test", dispatch_gate=gate,
        )
        assert len(calls) == 2
        assert sorted(collected) == sorted(calls)

    def test_parallel_already_concluded_dispatches_nothing(self):
        guard = _StubGuard()
        guard.concluded = True
        calls: list[int] = []
        gate = make_dispatch_gate(
            _config(guard), stop_check=lambda: guard.concluded,
        )
        collected = _collect_reviews_until_budget(
            _items(4), lambda i: calls.append(i) or i,
            lambda: guard.concluded, 2,
            phase_label="test", dispatch_gate=gate,
        )
        assert calls == []
        assert collected == []

    def test_parallel_pause_defers_dispatch_then_resumes(self):
        """A paused guard blocks every worker at its entry gate — no
        new dispatch starts — and releasing the pause lets the pass
        complete normally."""
        guard = _StubGuard()
        guard.pause()
        calls: list[int] = []
        calls_lock = threading.Lock()

        def do_review(item: int) -> int:
            with calls_lock:
                calls.append(item)
            return item

        gate = make_dispatch_gate(_config(guard), stop_check=lambda: False)
        out: list[list[int]] = []

        def run() -> None:
            out.append(_collect_reviews_until_budget(
                _items(4), do_review, lambda: False, 2,
                phase_label="test", dispatch_gate=gate,
            ))

        t = threading.Thread(target=run)
        t.start()
        # Every worker blocks inside the paused tick before its first
        # dispatch, so no review can have run while the pause holds.
        t.join(timeout=0.3)
        assert t.is_alive()
        with calls_lock:
            assert calls == []
        guard.resume()
        t.join(timeout=10.0)
        assert not t.is_alive()
        assert sorted(out[0]) == [0, 1, 2, 3]

    def test_parallel_no_gate_is_the_pre_existing_path(self):
        calls: list[int] = []
        calls_lock = threading.Lock()

        def do_review(item: int) -> int:
            with calls_lock:
                calls.append(item)
            return item

        collected = _collect_reviews_until_budget(
            _items(4), do_review, lambda: False, 2,
            phase_label="test",
        )
        assert sorted(calls) == [0, 1, 2, 3]
        assert sorted(collected) == [0, 1, 2, 3]


# ── Pass-level fixtures ──────────────────────────────────────────────


class _ConcludeAfterGuard(_StubGuard):
    """Guard that concludes once *allow* dispatch gates have passed —
    tick k sees concluded for every k > allow."""

    def __init__(self, allow: int) -> None:
        super().__init__()
        self._allow = allow

    def tick(self) -> None:
        with self._lock:
            self.ticks += 1
            if self.ticks > self._allow:
                self.concluded = True


def _run_config(tmp_path, guard: Any) -> OrchestratorConfig:
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    config = OrchestratorConfig(target_path=target, out_dir=out)
    config.environment_guard_state = guard
    return config


def _checklist_one() -> dict:
    return {
        "files": [
            {"path": "a.c", "language": "c", "items": [
                {"name": "f", "line_start": 1, "line_end": 100},
            ]},
        ],
    }


def _rv_outcome(status: str, *, function: str = "f",
                review_result: dict | None = None) -> ReviewOutcome:
    o = ReviewOutcome(
        file="a.c", function=function, status=status,
        body="claimed bug", hypothesis="unchecked copy", line=1,
    )
    o.review_result = (
        review_result if review_result is not None else {"body": "claimed bug"}
    )
    return o


@pytest.fixture()
def _light_context(monkeypatch):
    monkeypatch.setattr(_orch, "_build_context", lambda *a, **k: {})
    monkeypatch.setattr(_orch, "_commit_outcome", lambda *a, **k: None)


# ── Re-review family: every driver caller composes the gate ─────────


class TestReReviewCallersWireTheGate:
    """The five _collect_reviews_until_budget callers hand the driver a
    live dispatch gate whenever the run carries a guard. Gate
    SEMANTICS are proven on the driver above; these prove the wiring."""

    def _spy(self, monkeypatch) -> dict[str, Any]:
        captured: dict[str, Any] = {}

        def spy(prepared, do_review, should_stop, max_workers, *,
                phase_label, dispatch_gate=None):
            captured["gate"] = dispatch_gate
            captured["phase"] = phase_label
            return []

        monkeypatch.setattr(_orch, "_collect_reviews_until_budget", spy)
        return captured

    def _assert_live_gate(self, captured: dict, guard: _StubGuard) -> None:
        gate = captured.get("gate")
        assert gate is not None
        before = guard.ticks
        gate()
        assert guard.ticks == before + 1

    def test_deepen(self, tmp_path, monkeypatch, _light_context):
        captured = self._spy(monkeypatch)
        guard = _StubGuard()
        config = _run_config(tmp_path, guard)
        result = OrchestratorResult(outcomes=[_rv_outcome("suspicious")])
        result.suspicious = 1
        _orch._deepen_suspicious(
            result, config, lambda ctx, cfg: _rv_outcome("clean"),
            _checklist_one(), None, None, [], None, set(),
            time.monotonic(), None,
        )
        assert captured["phase"] == "deepen"
        self._assert_live_gate(captured, guard)

    def test_disagreement_re_review(self, tmp_path, monkeypatch,
                                    _light_context):
        captured = self._spy(monkeypatch)
        guard = _StubGuard()
        config = _run_config(tmp_path, guard)
        result = OrchestratorResult(outcomes=[_rv_outcome("clean")])
        d = SimpleNamespace(
            file="a.c", function="f", resolution="mechanical_wins",
            mechanical_claim=None,
        )
        _orch._re_review_disagreements(
            [d], result, config, lambda ctx, cfg: _rv_outcome("clean"),
            _checklist_one(), None, None, time.monotonic(), None,
        )
        assert captured["phase"] == "disagreement re-review"
        self._assert_live_gate(captured, guard)

    def test_iterative_re_review(self, tmp_path, monkeypatch,
                                 _light_context):
        captured = self._spy(monkeypatch)
        guard = _StubGuard()
        config = _run_config(tmp_path, guard)
        result = OrchestratorResult(outcomes=[_rv_outcome("finding")])
        result.findings = 1
        monkeypatch.setattr(
            _orch, "_find_re_review_targets",
            lambda *a, **k: [{
                "gap": {"file": "a.c", "name": "g", "line_start": 1},
                "callee_findings": [],
            }],
        )
        _orch._iterative_re_review(
            result, config, lambda ctx, cfg: _rv_outcome("clean"),
            _checklist_one(), None, None, set(), [], None, None,
            time.monotonic(), None,
        )
        assert captured["phase"] == "iterative re-review"
        self._assert_live_gate(captured, guard)

    def test_joern_enriched_re_review(self, tmp_path, monkeypatch,
                                      _light_context):
        captured = self._spy(monkeypatch)
        guard = _StubGuard()
        config = _run_config(tmp_path, guard)
        result = OrchestratorResult(outcomes=[_rv_outcome("clean")])
        rec = SimpleNamespace(all_joern_flows=lambda: ["flow"])
        _orch._re_review_joern_enriched(
            result, config, lambda ctx, cfg: _rv_outcome("clean"),
            _checklist_one(), None, None, {"a.c:f": rec}, None, set(),
            [{"file": "a.c", "name": "f"}], time.monotonic(), None,
        )
        assert captured["phase"] == "joern re-review"
        self._assert_live_gate(captured, guard)

    def test_study_enriched_re_review(self, tmp_path, monkeypatch,
                                      _light_context):
        captured = self._spy(monkeypatch)
        guard = _StubGuard()
        config = _run_config(tmp_path, guard)
        result = OrchestratorResult(outcomes=[_rv_outcome("clean")])
        _orch._re_review_study_enriched(
            result, config, lambda ctx, cfg: _rv_outcome("clean"),
            _checklist_one(), None, {}, None, set(), {"a.c:f"},
            time.monotonic(), None,
        )
        assert captured["phase"] == "study re-review"
        self._assert_live_gate(captured, guard)


# ── Dark verification ────────────────────────────────────────────────


class TestDarkVerificationGate:
    def _dark_result(self, n: int = 3) -> OrchestratorResult:
        outcomes = [
            _rv_outcome("dark", function=f"f{i}") for i in range(n)
        ]
        result = OrchestratorResult(outcomes=outcomes)
        result.dormant = n
        return result

    @pytest.mark.parametrize("workers", [1, 2])
    def test_concluded_guard_dispatches_no_witnesses(
        self, tmp_path, workers,
    ):
        guard = _StubGuard()
        guard.concluded = True
        config = _run_config(tmp_path, guard)
        result = self._dark_result()
        calls: list[str] = []

        # No start_time: the budget poll is start_time-conditional, so
        # only the environment gate can stop a library-style call.
        _run_dark_verification(
            result, config,
            llm_client=lambda p, s: calls.append(p) or "{}",
            max_workers=workers,
        )
        assert calls == []
        assert all(o.status == "dark" for o in result.outcomes)
        # The gate BOOKS the stop: dark verify runs after the last
        # full rails poll, so an unbooked conclusion would ship
        # terminated_by="complete" over a faulted run.
        assert result.terminated_by == "environment"
        assert result.environment_fault == guard.conclude_reason

    def test_mid_pass_conclusion_stops_new_probes(self, tmp_path):
        guard = _ConcludeAfterGuard(allow=2)
        config = _run_config(tmp_path, guard)
        result = self._dark_result(5)
        calls: list[str] = []

        _run_dark_verification(
            result, config,
            llm_client=lambda p, s: calls.append(p) or "{}",
            start_time=time.monotonic(),
        )
        # Exactly two witness prompts dispatched before the guard
        # concluded; the rest never started — and the stop is booked.
        assert len(calls) == 2
        assert result.terminated_by == "environment"
        assert result.environment_fault == guard.conclude_reason

    def test_healthy_guard_still_probes_and_ticks(self, tmp_path):
        guard = _StubGuard()
        config = _run_config(tmp_path, guard)
        result = self._dark_result(3)
        calls: list[str] = []
        _run_dark_verification(
            result, config,
            llm_client=lambda p, s: calls.append(p) or "{}",
            start_time=time.monotonic(),
        )
        assert len(calls) == 3  # every eligible outcome probed
        assert guard.ticks == 3  # one gate per witness dispatch
        assert result.terminated_by == "complete"

    def test_no_guard_keeps_pre_existing_path(self, tmp_path):
        config = _run_config(tmp_path, None)
        result = self._dark_result(2)
        calls: list[str] = []
        _run_dark_verification(
            result, config,
            llm_client=lambda p, s: calls.append(p) or "{}",
            start_time=time.monotonic(),
        )
        assert len(calls) == 2  # every eligible outcome still probed


# ── Adversarial refutation ───────────────────────────────────────────


class _StandsClient:
    """Refuter stub returning a stands verdict; counts calls."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._lock = threading.Lock()
        self.config = SimpleNamespace(
            config_for_model=lambda name: (_ for _ in ()).throw(
                ValueError(),
            ),
        )

    def generate_structured(self, prompt, schema, *, system_prompt="",
                            **kw):
        with self._lock:
            self.calls.append(prompt)
        return SimpleNamespace(
            result={"verdict": "stands", "counter_argument": "no defeat"},
            cost=0.01, model="stub",
        )


class TestAdversarialRefuteGate:
    def _positives(self, n: int = 4) -> OrchestratorResult:
        outcomes = [
            _rv_outcome(
                "suspicious", function=f"fn{i}",
                review_result={"status": "suspicious"},
            )
            for i in range(n)
        ]
        result = OrchestratorResult(outcomes=outcomes)
        result.suspicious = n
        return result

    @pytest.mark.parametrize("workers", [1, 2])
    def test_concluded_guard_dispatches_no_refutations(
        self, tmp_path, workers,
    ):
        guard = _StubGuard()
        guard.concluded = True
        client = _StandsClient()
        config = _run_config(tmp_path, guard)
        config.llm_client = client
        result = self._positives()

        _adversarial_refute_pass(
            result, config, max_workers=workers,
        )
        assert client.calls == []
        assert all(o.status == "suspicious" for o in result.outcomes)
        # Booked even without a start_time (the rails poll inside the
        # pass is start_time-conditional; the gate's stop check
        # is not).
        assert result.terminated_by == "environment"
        assert result.environment_fault == guard.conclude_reason

    def test_mid_pass_conclusion_stops_new_refutations(self, tmp_path):
        guard = _ConcludeAfterGuard(allow=2)
        client = _StandsClient()
        config = _run_config(tmp_path, guard)
        config.llm_client = client
        result = self._positives(5)

        _adversarial_refute_pass(result, config)
        # Two refutations dispatched (and folded: stands counter) —
        # the gate refused every later item and booked the stop.
        assert len(client.calls) == 2
        assert result.adversarial_stands == 2
        assert result.terminated_by == "environment"
        assert result.environment_fault == guard.conclude_reason

    def test_healthy_guard_still_refutes_and_ticks(self, tmp_path):
        guard = _StubGuard()
        client = _StandsClient()
        config = _run_config(tmp_path, guard)
        config.llm_client = client
        result = self._positives(3)
        _adversarial_refute_pass(result, config)
        assert len(client.calls) == 3
        assert result.adversarial_stands == 3
        assert guard.ticks == 3  # one gate per refutation dispatch
        assert result.terminated_by == "complete"

    def test_no_guard_keeps_pre_existing_path(self, tmp_path):
        client = _StandsClient()
        config = _run_config(tmp_path, None)
        config.llm_client = client
        result = self._positives(3)
        _adversarial_refute_pass(result, config)
        assert len(client.calls) == 3
        assert result.adversarial_stands == 3


# ── Callee-contract requeue ──────────────────────────────────────────


def _contract_result() -> OrchestratorResult:
    caller = _rv_outcome(
        "clean", function="handle",
        review_result={"relies_on": [
            {"callee": "parse_input", "assumption": "validates length"},
        ]},
    )
    callee = ReviewOutcome(
        file="parser.c", function="parse_input", status="finding",
        body="missing bounds check", hypothesis="missing bounds check",
    )
    callee.evidence_tool = "semgrep:rule-1"
    return OrchestratorResult(outcomes=[caller, callee])


class TestCalleeContractGate:
    @pytest.mark.parametrize("workers", [1, 4])
    def test_concluded_guard_skips_all_re_reviews(
        self, tmp_path, workers, _light_context,
    ):
        guard = _StubGuard()
        guard.concluded = True
        config = _run_config(tmp_path, guard)
        result = _contract_result()
        calls: list = []

        n = _callee_contract_requeue(
            result, config,
            lambda ctx, cfg: calls.append(ctx) or _rv_outcome(
                "suspicious", function="handle",
            ),
            checklist={}, context_map=None, fuzz_coverage=None,
            evidence_index={}, start_time=time.monotonic(),
            max_workers=workers,
        )
        assert n == 0
        assert calls == []
        assert result.terminated_by == "environment"

    def test_healthy_guard_still_re_reviews(
        self, tmp_path, _light_context,
    ):
        guard = _StubGuard()
        config = _run_config(tmp_path, guard)
        result = _contract_result()
        calls: list = []

        n = _callee_contract_requeue(
            result, config,
            lambda ctx, cfg: calls.append(ctx) or _rv_outcome(
                "suspicious", function="handle",
            ),
            checklist={}, context_map=None, fuzz_coverage=None,
            evidence_index={}, start_time=time.monotonic(),
        )
        assert n == 1
        assert len(calls) == 1
        assert guard.ticks >= 1  # the gate drove the guard


# ── Error retry ──────────────────────────────────────────────────────


class TestErrorRetryGate:
    def _error_result(self) -> OrchestratorResult:
        o = ReviewOutcome(
            file="a.c", function="f", status="error",
            body="review failed", line=1, error_class="timeout",
        )
        result = OrchestratorResult(outcomes=[o])
        result.errors = 1
        result.error_counts = {"timeout": 1}
        return result

    def test_concluded_guard_skips_all_retries(
        self, tmp_path, _light_context,
    ):
        guard = _StubGuard()
        guard.concluded = True
        config = _run_config(tmp_path, guard)
        result = self._error_result()
        calls: list = []

        _retry_error_outcomes(
            result, config,
            lambda ctx, cfg: calls.append(ctx) or _rv_outcome("clean"),
            _checklist_one(), None, None, time.monotonic(), None,
        )
        assert calls == []
        assert result.outcomes[0].status == "error"

    def test_healthy_guard_still_retries(self, tmp_path, _light_context):
        guard = _StubGuard()
        config = _run_config(tmp_path, guard)
        result = self._error_result()
        calls: list = []

        _retry_error_outcomes(
            result, config,
            lambda ctx, cfg: calls.append(ctx) or _rv_outcome("clean"),
            _checklist_one(), None, None, time.monotonic(), None,
        )
        assert len(calls) == 1
        assert guard.ticks >= 1


# ── Edge-obligation review ───────────────────────────────────────────


class _EdgeLLM:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def generate_structured(self, prompt, schema, system_prompt=None,
                            **kw):
        with self._lock:
            self.calls.append(prompt)
        return SimpleNamespace(
            result={"status": "clean", "body": "edge audit",
                    "hypothesis": ""},
            cost=0.01, model="stub", usage=None,
        )

    def is_budget_exhausted(self, estimated_cost=0.1) -> bool:
        return False


def _edge_fixture(tmp_path, monkeypatch, guard: Any, n: int = 3):
    from core.audit.edge_review import run_edge_pass

    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    (target / "routes.c").write_text(
        "".join(
            f"int handle{i}(const char *r) {{\n"
            f"    return run_query{i}(r);\n}}\n" for i in range(n)
        ), encoding="utf-8",
    )
    (target / "svc.c").write_text(
        "".join(
            f"int run_query{i}(const char *q) {{\n"
            f"    return exec(q);\n}}\n" for i in range(n)
        ), encoding="utf-8",
    )
    checklist = {
        "target_path": str(target),
        "files": [
            {"path": "routes.c", "language": "c", "items": [
                {"name": f"handle{i}", "kind": "function",
                 "line_start": 3 * i + 1, "line_end": 3 * i + 3}
                for i in range(n)]},
            {"path": "svc.c", "language": "c", "items": [
                {"name": f"run_query{i}", "kind": "function",
                 "line_start": 3 * i + 1, "line_end": 3 * i + 3}
                for i in range(n)]},
        ],
    }
    recs = [
        {"caller_file": "routes.c", "caller": f"handle{i}",
         "callee_file": "svc.c", "callee": f"run_query{i}",
         "call_line": 3 * i + 2, "reason": "boundary:socket",
         "touched": False}
        for i in range(n)
    ]
    monkeypatch.setattr(
        "core.audit.edge_obligations.build_and_write",
        lambda out_dir, checklist, context_map, **kw: {
            "tier1": list(recs), "tier2": [], "blind_spots": [],
            "stats": {},
        },
    )
    monkeypatch.setattr(
        "core.audit.edge_review.compute_edge_gaps",
        lambda obligations, **kw: list(obligations["tier1"]),
    )
    llm = _EdgeLLM()
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    config = SimpleNamespace(
        out_dir=out, target_path=target,
        llm_client=llm, llm_budget_client=llm,
        environment_guard_state=guard,
    )
    summary, _tier2 = run_edge_pass(
        config, checklist, None,
        commit_fn=lambda config, outcome, gap: None,
        max_workers=1,
    )
    return summary, llm


class TestEdgeReviewGate:
    def test_concluded_guard_skips_every_edge(self, tmp_path,
                                              monkeypatch):
        guard = _StubGuard()
        guard.concluded = True
        summary, llm = _edge_fixture(tmp_path, monkeypatch, guard)
        assert llm.calls == []
        assert summary["reviewed"] == 0
        # Concluded edges join the budget-skip lane: they stay
        # obligation gaps with an explicit count.
        assert summary["skipped_budget"] == 3

    def test_healthy_guard_reviews_and_ticks(self, tmp_path,
                                             monkeypatch):
        guard = _StubGuard()
        summary, llm = _edge_fixture(tmp_path, monkeypatch, guard)
        assert summary["reviewed"] == 3
        assert len(llm.calls) == 3
        assert guard.ticks == 3  # one gate per edge dispatch

    def test_no_guard_keeps_pre_existing_path(self, tmp_path,
                                              monkeypatch):
        summary, llm = _edge_fixture(tmp_path, monkeypatch, None)
        assert summary["reviewed"] == 3
        assert len(llm.calls) == 3


# ── Flow-trace review ────────────────────────────────────────────────


class TestFlowTraceGate:
    def _write_trace(self, out: Any) -> None:
        import json
        (out / "flow-trace-1.json").write_text(json.dumps({
            "id": "t1",
            "source": {"file": "a.c", "name": "src", "line": 1},
            "sink": {"file": "a.c", "name": "snk", "line": 9},
            "hops": [{"file": "a.c", "name": "mid", "line": 5}],
        }), encoding="utf-8")

    def test_concluded_guard_reviews_no_traces_and_books(self, tmp_path):
        guard = _StubGuard()
        guard.concluded = True
        config = _run_config(tmp_path, guard)
        self._write_trace(config.out_dir)
        result = OrchestratorResult()
        calls: list = []

        _orch._review_flow_traces(
            result, config,
            lambda ctx, cfg: calls.append(ctx) or _rv_outcome("clean"),
            {},
        )
        assert calls == []
        assert result.terminated_by == "environment"
        assert result.environment_fault == guard.conclude_reason

    def test_healthy_guard_still_reviews_and_ticks(self, tmp_path):
        guard = _StubGuard()
        config = _run_config(tmp_path, guard)
        self._write_trace(config.out_dir)
        result = OrchestratorResult()
        calls: list = []

        _orch._review_flow_traces(
            result, config,
            lambda ctx, cfg: calls.append(ctx) or _rv_outcome("clean"),
            {},
        )
        assert len(calls) == 1
        assert guard.ticks >= 1

    def test_no_guard_keeps_pre_existing_path(self, tmp_path):
        config = _run_config(tmp_path, None)
        self._write_trace(config.out_dir)
        result = OrchestratorResult()
        calls: list = []
        _orch._review_flow_traces(
            result, config,
            lambda ctx, cfg: calls.append(ctx) or _rv_outcome("clean"),
            {},
        )
        assert len(calls) == 1


# ── Concept-discovery rule compilation ───────────────────────────────


class TestConceptDiscoveryGate:
    def _drive(self, tmp_path, monkeypatch, guard: Any) -> list:
        import core.audit.concept_discovery as cd_mod
        import core.concepts.compiler as compiler_mod

        entries = [
            {"id": f"inv{i}", "statement": f"s{i}", "negation": f"n{i}",
             "description": "", "confidence": "observed",
             "relevant_cwes": [], "evidence": []}
            for i in range(3)
        ]
        monkeypatch.setattr(
            cd_mod, "discover_invariants", lambda snapshot, dm: ["c"],
        )
        monkeypatch.setattr(
            cd_mod, "candidates_to_model_entries",
            lambda candidates: [dict(e) for e in entries],
        )
        compiled: list = []

        def fake_compile(inv, engine, llm, out_dir):
            compiled.append(inv.id)
            return SimpleNamespace(success=False)

        monkeypatch.setattr(compiler_mod, "compile_invariant", fake_compile)
        monkeypatch.setattr(
            _orch, "_run_llm_client", lambda cfg: SimpleNamespace(),
        )

        config = _run_config(tmp_path, guard)
        shared = SimpleNamespace(domain_model={})
        _orch._run_concept_discovery(
            {"a.c:f": _rv_outcome("finding")}, config, shared,
            [], {}, set(),
        )
        return compiled

    def test_concluded_guard_compiles_nothing(self, tmp_path, monkeypatch):
        guard = _StubGuard()
        guard.concluded = True
        compiled = self._drive(tmp_path, monkeypatch, guard)
        assert compiled == []

    def test_healthy_guard_still_compiles_and_ticks(
        self, tmp_path, monkeypatch,
    ):
        guard = _StubGuard()
        compiled = self._drive(tmp_path, monkeypatch, guard)
        assert compiled == ["inv0", "inv1", "inv2"]
        assert guard.ticks == 3  # one gate per compilation dispatch

    def test_no_guard_keeps_pre_existing_path(self, tmp_path, monkeypatch):
        compiled = self._drive(tmp_path, monkeypatch, None)
        assert compiled == ["inv0", "inv1", "inv2"]


# ── Phase 2: security classification + chain evaluation ─────────────


class _Phase2Client:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.config = SimpleNamespace(
            config_for_model=lambda name: (_ for _ in ()).throw(
                ValueError(),
            ),
        )

    def generate_structured(self, prompt, schema, system_prompt="",
                            **kw):
        self.calls.append(prompt)
        return SimpleNamespace(
            result={"is_security": True, "classification": "memory",
                    "rationale": "r", "is_chain": False},
            cost=0.0,
        )


class TestPhase2Gates:
    def _positives(self, n: int = 3) -> list[ReviewOutcome]:
        return [
            _rv_outcome("finding", function=f"fn{i}") for i in range(n)
        ]

    def test_classifier_stops_when_gate_trips(self, tmp_path):
        from core.audit.security_classifier import classify_security_impact

        client = _Phase2Client()
        stops = iter([False, True, True])
        results = classify_security_impact(
            self._positives(), tmp_path, client,
            should_stop=lambda: next(stops),
        )
        assert len(client.calls) == 1  # stopped before the second call
        assert len(results) == 1

    def test_classifier_without_gate_classifies_all(self, tmp_path):
        from core.audit.security_classifier import classify_security_impact

        client = _Phase2Client()
        results = classify_security_impact(
            self._positives(), tmp_path, client,
        )
        assert len(client.calls) == 3
        assert len(results) == 3

    def test_chain_evaluator_stops_when_gate_trips(self):
        from core.audit.chain_detector import evaluate_chains

        client = _Phase2Client()
        pairs = [
            (_rv_outcome("finding", function=f"a{i}"),
             _rv_outcome("finding", function=f"b{i}"))
            for i in range(3)
        ]
        stops = iter([False, True, True])
        evaluate_chains(pairs, client, should_stop=lambda: next(stops))
        assert len(client.calls) == 1

    def test_chain_evaluator_without_gate_evaluates_all(self):
        from core.audit.chain_detector import evaluate_chains

        client = _Phase2Client()
        pairs = [
            (_rv_outcome("finding", function=f"a{i}"),
             _rv_outcome("finding", function=f"b{i}"))
            for i in range(2)
        ]
        evaluate_chains(pairs, client)
        assert len(client.calls) == 2

    def test_run_phase2_wires_a_booking_gate(self, tmp_path, monkeypatch):
        """_run_phase2 hands both loops a gate that ticks the guard and
        BOOKS a conclusion — this phase runs after the last full rails
        poll, so nothing downstream would re-book it."""
        import core.audit.security_classifier as sc_mod

        seen: dict[str, Any] = {}

        def fake_classify(outcomes, out_dir, client, *, model_name=None,
                          should_stop=None):
            seen["should_stop"] = should_stop
            return {}

        monkeypatch.setattr(
            sc_mod, "classify_security_impact", fake_classify,
        )
        guard = _StubGuard()
        guard.concluded = True
        config = _run_config(tmp_path, guard)
        # Stub client on the budget seam (as the budget-client test
        # below does): patching core.llm.client.LLMClient no longer
        # intercepts construction — it goes through the transcript
        # seam, whose module body subclasses whatever LLMClient is
        # bound to at first import.
        config.llm_budget_client = SimpleNamespace()
        result = OrchestratorResult()
        _orch._run_phase2(result, config)

        gate = seen["should_stop"]
        assert gate is not None
        assert gate() is True  # concluded guard: do not dispatch
        assert guard.ticks == 1
        assert result.terminated_by == "environment"
        assert result.environment_fault == guard.conclude_reason

    def test_run_phase2_uses_the_budget_client(self, tmp_path, monkeypatch):
        """Phase-2/2b spend must ride the run's budget-governed
        client: a private LLMClient carries its own default cap, so
        its calls bypass the --max-cost reservation gate and never
        reach the run's spend ledger."""
        import core.audit.security_classifier as sc_mod

        seen: dict[str, Any] = {}

        def fake_classify(outcomes, out_dir, client, *, model_name=None,
                          should_stop=None):
            seen["client"] = client
            return {}

        monkeypatch.setattr(
            sc_mod, "classify_security_impact", fake_classify,
        )
        config = _run_config(tmp_path, _StubGuard())
        budget_client = SimpleNamespace()
        config.llm_budget_client = budget_client
        result = OrchestratorResult()
        _orch._run_phase2(result, config)

        assert seen["client"] is budget_client


# ── Run-level gate bindings (full orchestrator, stub review) ─────────


class _SiteRecordingGuard:
    """Stands in for EnvironmentGuard inside a full run_orchestrator
    run; records, for every tick, the two frames above it — enough to
    tell WHICH dispatch surface drove the guard."""

    last: Any = None

    def __init__(self, **_kw: Any) -> None:
        import sys as _sys
        self._sys = _sys
        self.tick_callers: list[tuple[str, str]] = []
        self.concluded = False
        self.conclude_reason = ""
        self._lock = threading.Lock()
        type(self).last = self

    def tick(self) -> None:
        frame = self._sys._getframe(1)
        outer = frame.f_back.f_code.co_name if frame.f_back else ""
        with self._lock:
            self.tick_callers.append((frame.f_code.co_name, outer))

    def note_dispatch_failure(self, key: Any, exc: Any) -> None:
        return


def _binding_target(tmp_path):
    """Two trivial (sub-threshold SLOC) functions in one file: with the
    default batch_sloc_threshold both route through the trivial-batch
    pass and the main executor graph is empty."""
    import json

    target = tmp_path / "target"
    target.mkdir()
    (target / "src").mkdir()
    (target / "src" / "auth.c").write_text(
        "int check_pw(char *pw, int len) {\n"
        "  char buf[256];\n"
        "  memcpy(buf, pw, len);\n"
        "  return 0;\n"
        "}\n"
        "\n"
        "int validate(char *input, size_t sz) {\n"
        "  char tmp[128];\n"
        "  memcpy(tmp, input, sz);\n"
        "  return 1;\n"
        "}\n"
    )
    out = tmp_path / "out"
    out.mkdir()
    checklist = {
        "files": [
            {
                "path": "src/auth.c",
                "items": [
                    {"name": "check_pw", "line_start": 1, "line_end": 5},
                    {"name": "validate", "line_start": 7, "line_end": 11},
                ],
            },
        ],
    }
    (out / "checklist.json").write_text(json.dumps(checklist))
    return target, out


def _binding_run(tmp_path, monkeypatch, *, before_run=None,
                 guard_cls=_SiteRecordingGuard):
    import core.audit.environment as env_mod
    from core.audit.orchestrator import run_orchestrator

    monkeypatch.setattr(env_mod, "EnvironmentGuard", guard_cls)
    guard_cls.last = None
    target, out = _binding_target(tmp_path)

    def review_fn(ctx, config):
        return ReviewOutcome(
            file=ctx.get("file", ""), function=ctx.get("function", ""),
            status="clean", body="reviewed", model="test-model",
        )

    config = OrchestratorConfig(
        target_path=target, out_dir=out, resume=False,
    )
    if before_run is not None:
        before_run(config)
    result = run_orchestrator(config, review_fn)
    guard = guard_cls.last
    assert guard is not None  # the run constructed its guard
    return result, guard


@pytest.mark.slow
class TestRunLevelGateBindings:
    """Mutation-killing bindings for the gates that live inside the
    orchestrator run body (not directly callable): remove the wiring
    line and the corresponding tick-caller assertion goes red."""

    def test_trivial_batch_worker_gates(self, tmp_path, monkeypatch):
        result, guard = _binding_run(tmp_path, monkeypatch)
        assert result.reviewed == 2
        # The trivial-batch worker drove the guard at its entry.
        assert ("_gate", "_review_batch") in guard.tick_callers

    def test_synthesis_second_pass_executor_ticks(
        self, tmp_path, monkeypatch,
    ):
        def seed_synthesis(config, result, shared, checklist):
            shared.synthesis_queue.append({
                "file": "src/auth.c", "line": 2, "rule_id": "bind-test",
            })
            return 1

        monkeypatch.setattr(
            _orch, "_synthesize_external_seeds", seed_synthesis,
        )
        result, guard = _binding_run(tmp_path, monkeypatch)
        # The synthesis second pass ran its executor with the
        # environment on_tick adapter wired.
        assert ("_gate", "_tick") in guard.tick_callers

    def test_bypass_pass_executor_ticks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            _orch, "_refine_bypass_post_loop_findings",
            lambda *a, **kw: [{
                "source": "iris_refine_loop", "file": "src/auth.c",
                "function": "check_pw", "line_start": 2,
                "hypothesis": "bypass reachable",
            }],
        )
        result, guard = _binding_run(tmp_path, monkeypatch)
        assert ("_gate", "_tick") in guard.tick_callers

    def test_concept_discovery_conclusion_is_booked_terminally(
        self, tmp_path, monkeypatch,
    ):
        """A conclusion observed only by concept discovery's
        flag-stop gate on an otherwise-empty run (no suspicious /
        disagreements / errors / darks / traces, adversarial off,
        non-security mode — every later rails-polling pass is
        conditional) must still book the environment stop: the
        terminal sweep at the end of the run body guarantees it."""
        import core.audit.concept_discovery as cd_mod
        import core.concepts.compiler as compiler_mod

        class _ConcludeInConceptGuard(_SiteRecordingGuard):
            conclude_reason = "stub environment fault"

            def tick(self) -> None:
                # Own frame walk (super().tick() would record THIS
                # method as the caller and mask the real site).
                names: list[str] = []
                frame = self._sys._getframe(1)
                while frame is not None and len(names) < 3:
                    names.append(frame.f_code.co_name)
                    frame = frame.f_back
                names += [""] * (3 - len(names))
                with self._lock:
                    self.tick_callers.append((names[0], names[1]))
                if "_run_concept_discovery" in names:
                    self.concluded = True

        monkeypatch.setattr(
            cd_mod, "discover_invariants", lambda snapshot, dm: ["c"],
        )
        monkeypatch.setattr(
            cd_mod, "candidates_to_model_entries",
            lambda candidates: [{
                "id": "inv0", "statement": "s", "negation": "n",
                "description": "", "confidence": "observed",
                "relevant_cwes": [], "evidence": [],
            }],
        )
        compiled: list = []
        monkeypatch.setattr(
            compiler_mod, "compile_invariant",
            lambda inv, engine, llm, out_dir: compiled.append(inv.id)
            or SimpleNamespace(success=False),
        )
        monkeypatch.setattr(
            _orch, "_run_llm_client", lambda cfg: SimpleNamespace(),
        )
        def before_run(config):
            # Disable trivial batching: concept discovery mines the
            # graph executor's reviewed_outcomes, which the batch
            # lane does not feed — an all-trivial run would return
            # before its dispatch gate ever ran.
            config.batch_sloc_threshold = 0

        result, guard = _binding_run(
            tmp_path, monkeypatch, guard_cls=_ConcludeInConceptGuard,
            before_run=before_run,
        )
        # The gate concluded inside the concept loop (before the first
        # compile) — and the stop is booked even though no later
        # rails-polling pass ran on this empty run.
        assert ("_gate", "_run_concept_discovery") in guard.tick_callers
        assert compiled == []
        assert result.terminated_by == "environment"
        assert result.environment_fault == guard.conclude_reason

    def test_live_sink_requeue_worker_gates(self, tmp_path, monkeypatch):
        import core.audit.live_classifications as live_mod

        stub = SimpleNamespace(
            sinks={"exec_query"},  # non-empty: arms the re-queue block
            should_upgrade_triage=lambda key, callees: True,
        )
        monkeypatch.setattr(
            live_mod, "load_from_project_context",
            lambda learnings, checklist=None: stub,
        )
        monkeypatch.setattr(
            live_mod, "expand_wrapper_sinks", lambda *a, **kw: None,
        )
        result, guard = _binding_run(tmp_path, monkeypatch)
        assert ("_gate", "_do_ls_review") in guard.tick_callers


# ── Study consumer ───────────────────────────────────────────────────


class TestStudyConsumerGate:
    def test_pause_defers_batch_and_conclusion_stops_drain(
        self, tmp_path,
    ):
        """A paused guard blocks the consumer BEFORE it dequeues a new
        study batch (queued work stays queued, nothing dispatches);
        concluding the guard while paused stops the drain through the
        environment rails without touching the batch."""
        from core.audit.orchestrator import (
            StudyQueue,
            StudyRequest,
            _study_consumer_loop,
        )

        guard = _StubGuard()
        guard.pause()
        config = _run_config(tmp_path, guard)
        result = OrchestratorResult()
        queue = StudyQueue()
        queue.enqueue(StudyRequest("what is sk_buff?", "a.c", "f"))

        def run() -> None:
            _study_consumer_loop(
                queue, config, SimpleNamespace(domain_model={}),
                lambda ctx, cfg: _rv_outcome("clean"),
                SimpleNamespace(), result,
                checklist={}, context_map=None, evidence_index={},
                sarif_cache=None, entry_points=set(),
                start_time=time.monotonic(), on_progress=None,
            )

        t = threading.Thread(target=run)
        t.start()
        # The consumer blocks inside the paused tick before its first
        # dequeue — the queued request is still there and no study
        # work has started.
        t.join(timeout=0.3)
        assert t.is_alive()
        _progress, queue_empty, working = queue.drain_state()
        assert not queue_empty
        assert not working

        guard.concluded = True
        guard.resume()
        t.join(timeout=10.0)
        assert not t.is_alive()
        # The drain stopped on the environment rails; the batch was
        # never dequeued, let alone dispatched — and the stop is
        # booked with the fault reason.
        assert result.terminated_by == "environment"
        assert result.environment_fault == guard.conclude_reason
        assert len(queue.dequeue_batch(max_items=10, timeout=0.05)) == 1


class _NthTickPauseGuard:
    """Blocks only on the Nth tick (the pre-batch gate), releasable —
    models a pause that begins after the top-of-iteration checkpoints
    already passed."""

    conclude_reason = "stub environment fault"

    def __init__(self, pause_on_tick: int) -> None:
        self.ticks = 0
        self.concluded = False
        self._pause_on = pause_on_tick
        self.paused = threading.Event()
        self.release = threading.Event()

    def tick(self) -> None:
        self.ticks += 1
        if self.ticks == self._pause_on:
            self.paused.set()
            assert self.release.wait(timeout=15.0), "test guard stuck"


class TestStudyConsumerPreBatchGate:
    """The pre-batch gate sits between the stop_requested checkpoint
    and the paid study call. Tick 1 is the top-of-iteration gate,
    tick 2 is the pre-batch gate — a pause there models a fault
    arising during dedup/flush/prep."""

    def _drive(self, tmp_path, monkeypatch, *, on_paused):
        import json

        from core.audit.orchestrator import (
            StudyQueue,
            StudyRequest,
            _study_consumer_loop,
        )

        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        study_list = out / "study-list.json"
        study_list.write_text(json.dumps({"concepts": []}),
                              encoding="utf-8")

        config = OrchestratorConfig(target_path=target, out_dir=out)
        guard = _NthTickPauseGuard(pause_on_tick=2)
        config.environment_guard_state = guard

        study_ran = threading.Event()

        import core.concepts.study as _study_mod

        def fake_run_study(*a, **kw):
            study_ran.set()
            raise RuntimeError("test: stop after recording")

        monkeypatch.setattr(_study_mod, "run_study", fake_run_study)
        monkeypatch.setattr(
            _orch, "_run_llm_client", lambda cfg: SimpleNamespace(),
        )
        monkeypatch.setattr(
            _orch, "_client_class_cost", lambda client, cls: 0.0,
        )
        monkeypatch.setattr(
            _orch, "_resolve_multilang_requests", lambda *a, **kw: {},
        )

        queue = StudyQueue()
        queue.enqueue(StudyRequest("what is sk_buff?", "a.c", "f"))
        queue.signal_producer_done()
        result = OrchestratorResult()

        def run() -> None:
            _study_consumer_loop(
                queue, config, SimpleNamespace(domain_model={}),
                lambda ctx, cfg: None,
                SimpleNamespace(), result,
                checklist={}, context_map=None, evidence_index={},
                sarif_cache=None, entry_points=set(),
                start_time=time.monotonic(), on_progress=None,
                state={
                    "study_list_built": True,
                    "study_list_path": study_list,
                },
            )

        t = threading.Thread(target=run, daemon=True)
        t.start()
        assert guard.paused.wait(timeout=10.0), (
            "consumer never reached the pre-batch gate"
        )
        on_paused(queue, guard)
        guard.release.set()
        t.join(timeout=10.0)
        assert not t.is_alive()
        return study_ran, result, guard

    def test_stop_during_prebatch_pause_skips_the_batch(
        self, tmp_path, monkeypatch,
    ):
        """A drain-abandonment stop arriving while the pre-batch gate
        is paused must be honoured when the gate returns — pre-fix the
        paid study batch dispatched after the run was over."""
        def on_paused(queue, guard):
            queue.request_stop()

        study_ran, _result, _guard = self._drive(
            tmp_path, monkeypatch, on_paused=on_paused,
        )
        assert not study_ran.is_set()

    def test_conclusion_during_prebatch_pause_books_and_stops(
        self, tmp_path, monkeypatch,
    ):
        def on_paused(queue, guard):
            guard.concluded = True

        study_ran, result, guard = self._drive(
            tmp_path, monkeypatch, on_paused=on_paused,
        )
        assert not study_ran.is_set()
        assert result.terminated_by == "environment"
        assert result.environment_fault == guard.conclude_reason

    def test_healthy_gate_still_dispatches_the_batch(
        self, tmp_path, monkeypatch,
    ):
        """Positive control (and the binding for the pre-batch gate:
        reaching tick 2 IS the wiring): with nothing stopping it, the
        released gate lets the batch's study call dispatch."""
        study_ran, result, guard = self._drive(
            tmp_path, monkeypatch, on_paused=lambda queue, guard: None,
        )
        assert study_ran.is_set()
        assert guard.ticks >= 2
        assert result.terminated_by == "complete"
