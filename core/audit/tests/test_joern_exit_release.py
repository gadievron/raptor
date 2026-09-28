"""Joern release on exit: the bounded salvage-path stop, the bound in
both directions, and the exactly-once wiring through the flush-hook
registry + the run's ``finally``. Stubbed server only — no JVM, no
spatch, no LLM."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

import pytest

import core.audit.orchestrator as orch
from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    _bounded_joern_exit_release,
    run_orchestrator,
)


@pytest.fixture(autouse=True)
def _reset_term_state():
    """Never leak TERM/shutdown state into other tests."""
    yield
    orch._sigterm_event.clear()
    orch._shutdown_event.clear()
    orch._sigterm_state["count"] = 0
    orch._sigterm_flush_hooks.clear()


# ── the bound itself, both directions ────────────────────────────────


def test_exit_stop_timeout_value_two_directions() -> None:
    # Not lower: a sibling briefly holding the lifecycle file lock
    # legitimately needs a few seconds — a sub-5s bound abandons
    # releases that were about to succeed.
    assert orch._JOERN_EXIT_STOP_TIMEOUT_S >= 5.0
    # Not higher: the release shares the SIGTERM grace with the
    # ledger/journal flush and the salvage export — it must never be
    # able to consume more than half the window.
    assert orch._JOERN_EXIT_STOP_TIMEOUT_S <= orch._SIGTERM_GRACE_S / 2


def test_bounded_release_runs_release_to_completion() -> None:
    calls: list[str] = []
    _bounded_joern_exit_release(lambda: calls.append("released"))
    assert calls == ["released"]


def test_bounded_release_abandons_a_hung_release(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    """A release wedged on the lifecycle file lock must not delay the
    exit past the bound — it is abandoned with one warning."""
    monkeypatch.setattr(orch, "_JOERN_EXIT_STOP_TIMEOUT_S", 0.2)
    hang = threading.Event()
    started = threading.Event()

    def _wedged() -> None:
        started.set()
        hang.wait(30.0)

    t0 = time.monotonic()
    with caplog.at_level(logging.WARNING, logger=orch.__name__):
        _bounded_joern_exit_release(_wedged)
    elapsed = time.monotonic() - t0
    assert started.is_set()
    assert elapsed < 5.0  # returned at the bound, not the hang
    warnings = [
        r for r in caplog.records if "abandoning" in r.getMessage()
    ]
    assert len(warnings) == 1
    hang.set()  # release the daemon worker


def test_bounded_release_under_bound_no_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    """The other direction: a release slower than instant but inside
    the bound completes silently — the bound must not clip it."""
    monkeypatch.setattr(orch, "_JOERN_EXIT_STOP_TIMEOUT_S", 5.0)
    calls: list[str] = []

    def _slowish() -> None:
        time.sleep(0.05)
        calls.append("released")

    with caplog.at_level(logging.WARNING, logger=orch.__name__):
        _bounded_joern_exit_release(_slowish)
    assert calls == ["released"]
    assert not [
        r for r in caplog.records if "abandoning" in r.getMessage()
    ]


# ── wiring through run_orchestrator ──────────────────────────────────


class _StubServer:
    """Shape-only joern server stand-in (no ``_proc`` attribute, so
    the run takes the plain ``_stop_joern_server`` release leg)."""


def _setup_target(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    body = (
        "int handler_0(char *input, int len) {\n"
        "  char buf[64];\n"
        "  memcpy(buf, input, len);\n"
        "  return buf[0];\n"
        "}\n"
    )
    (target / "src" / "a.c").write_text(body)
    out = tmp_path / "out"
    out.mkdir()
    checklist = {"files": [{"path": "src/a.c", "items": [
        {"name": "handler_0", "line_start": 1, "line_end": 5},
    ]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    return target, out


def _config(target: Path, out: Path, **kw) -> OrchestratorConfig:
    defaults: dict = {
        "target_path": target,
        "out_dir": out,
        "resume": False,
        "max_workers": 1,
        "batch_sloc_threshold": 0,
        "prefilter": False,
        "validate": False,
        # The joern CHANNEL stays off (no real server); the release
        # seam under test is driven by the monkeypatched server-start.
        "joern_overrides": {"enabled": False},
    }
    defaults.update(kw)
    return OrchestratorConfig(**defaults)


def _clean(ctx: dict, config: OrchestratorConfig) -> ReviewOutcome:
    return ReviewOutcome(
        file=ctx["file"], function=ctx["function"],
        status="clean", body="ok", cost_usd=0.0,
    )


@pytest.mark.slow
class TestExitReleaseWiring:
    """Real run_orchestrator invocations (multi-second prep) — slow
    tier, like the other stubbed-loop orchestrator tests."""

    def _run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
             review_fn, **cfg_kw) -> tuple[_StubServer, list]:
        target, out = _setup_target(tmp_path)
        stub = _StubServer()
        stops: list = []
        monkeypatch.setattr(
            orch, "_start_joern_server_raw",
            lambda *a, **k: stub,
        )
        monkeypatch.setattr(orch, "_stop_joern_server", stops.append)
        run_orchestrator(_config(target, out, **cfg_kw), review_fn)
        return stub, stops

    def test_graceful_exit_releases_exactly_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        stub, stops = self._run(tmp_path, monkeypatch, _clean)
        assert stops == [stub]

    def test_forced_exit_hook_plus_finally_release_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A watchdog firing mid-teardown runs the flush hooks AND the
        ``finally`` still runs — the guard keeps the release single."""

        def _review(ctx: dict, config: OrchestratorConfig) -> ReviewOutcome:
            # Simulate the forced-exit flush (watchdog expiry / second
            # TERM) while the run is live — hooks are registered now.
            orch._run_sigterm_flush_hooks()
            return _clean(ctx, config)

        stub, stops = self._run(tmp_path, monkeypatch, _review)
        assert stops == [stub]  # once via the hook, finally no-ops

    def test_sigterm_salvage_path_is_bounded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """SIGTERM salvage conclusion: the release rides the bounded
        path, and a wedged stop cannot stall the exit."""
        monkeypatch.setattr(orch, "_JOERN_EXIT_STOP_TIMEOUT_S", 0.2)
        target, out = _setup_target(tmp_path)
        stub = _StubServer()
        hang = threading.Event()
        attempts: list = []

        def _wedged_stop(server) -> None:
            attempts.append(server)
            hang.wait(30.0)

        monkeypatch.setattr(
            orch, "_start_joern_server_raw", lambda *a, **k: stub,
        )
        monkeypatch.setattr(orch, "_stop_joern_server", _wedged_stop)

        def _review(ctx: dict, config: OrchestratorConfig) -> ReviewOutcome:
            orch._sigterm_event.set()  # drain from here on
            return _clean(ctx, config)

        t0 = time.monotonic()
        with caplog.at_level(logging.WARNING, logger=orch.__name__):
            run_orchestrator(_config(target, out), _review)
        elapsed = time.monotonic() - t0
        assert attempts == [stub]  # the stop WAS attempted
        assert elapsed < 20.0  # returned at the bound, not the hang
        assert [
            r for r in caplog.records if "abandoning" in r.getMessage()
        ]
        hang.set()

    def test_caller_owned_server_never_stopped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An embedder's server outlives the run — neither the hook
        nor the ``finally`` may touch it."""
        target, out = _setup_target(tmp_path)
        stub = _StubServer()
        stops: list = []
        monkeypatch.setattr(orch, "_stop_joern_server", stops.append)

        def _review(ctx: dict, config: OrchestratorConfig) -> ReviewOutcome:
            orch._run_sigterm_flush_hooks()  # forced-exit shape too
            return _clean(ctx, config)

        run_orchestrator(
            _config(target, out, joern_server=stub), _review,
        )
        assert stops == []
