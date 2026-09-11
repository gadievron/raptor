"""End-of-sweep retry for timeout-abandoned stress scans.

A per-scan timeout is one sample of the same network-dominated
process the elapsed re-measure machinery exists for — one throttled
registry run must not error the biggest project and block the
baseline refresh. The retry runs exactly once per timed-out project,
at end of sweep, and ONLY when the orphaned worker has finished:
abandoned worker threads cannot be killed, and two concurrent scans
of one project would race on the same clone dir and caches.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import pytest

from packages.sca.calibration import stress as stress_mod
from packages.sca.calibration.project_samples import ProjectSample
from packages.sca.calibration.stress import (
    StressResult,
    decide_baseline_refresh,
)


@pytest.fixture(autouse=True)
def _clean_in_flight_registry():
    """Abandoned workers deliberately keep their in-flight entries
    (post-mortems must name them); clear the process-global registry
    around every test so leakage stays order-independent."""
    with stress_mod._ACTIVE_SCANS_LOCK:
        stress_mod._ACTIVE_SCANS.clear()
    yield
    with stress_mod._ACTIVE_SCANS_LOCK:
        stress_mod._ACTIVE_SCANS.clear()


def _sample(name: str) -> ProjectSample:
    return ProjectSample(
        name=name, ecosystem="PyPI",
        repo_url="https://example.invalid/x.git",
        git_ref="v1", license_spdx="MIT",
    )


def _ok_result(name: str, elapsed: float = 0.1) -> StressResult:
    return StressResult(
        project=name, ecosystem="PyPI", elapsed_seconds=elapsed,
        deps_analysed=5, vuln_findings=1, eco_breakdown={"PyPI": 1},
    )


def _register(label: str) -> None:
    """Register a fake scan in the in-flight registry so the sweep's
    per-scan budget applies to it (only STARTED scans can time out)."""
    with stress_mod._ACTIVE_SCANS_LOCK:
        stress_mod._ACTIVE_SCANS[label] = time.monotonic()


def _unregister(label: str) -> None:
    with stress_mod._ACTIVE_SCANS_LOCK:
        stress_mod._ACTIVE_SCANS.pop(label, None)


def test_timeout_retry_succeeds_and_replaces_result_wholesale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Timed-out scan whose orphan finished before the retry slot:
    retried exactly once, and the successful attempt replaces the
    timeout result wholesale (counts, breakdown AND elapsed)."""
    caplog.set_level(logging.INFO)
    calls: dict[str, int] = {}
    release = threading.Event()
    orphan_finished = threading.Event()
    sink: list[StressResult] = []

    def _scan(
        sample: ProjectSample, out_root: Path, *, git_clone_timeout: float,
    ) -> StressResult:
        calls[sample.name] = n = calls.get(sample.name, 0) + 1
        if sample.name == "slow":
            if n == 1:
                # The orphan: registered (so the budget applies),
                # blocked past its budget, then finishes.
                _register("PyPI/slow")
                release.wait(timeout=30)
                _unregister("PyPI/slow")
                orphan_finished.set()
                return _ok_result("slow")   # never read (abandoned)
            return _ok_result("slow", elapsed=2.5)   # the retry
        # The escort keeps the sweep loop alive until the orphan has
        # fully finished, so the retry slot sees a done orphan. It
        # never registers, so the per-scan budget can't abandon it.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if any(r.project == "slow" and r.error for r in sink):
                break
            time.sleep(0.01)
        release.set()
        assert orphan_finished.wait(timeout=30)
        # Grace for the executor to run set_result after the orphan
        # fn returned (a few instructions; .done() flips only then).
        time.sleep(0.5)
        return _ok_result("escort")

    monkeypatch.setattr(stress_mod, "_scan_one", _scan)
    results = stress_mod.run_stress_sweep(
        samples=[_sample("slow"), _sample("escort")],
        out_root=tmp_path, max_workers=2,
        git_clone_timeout=0.1, sca_timeout=0.3,   # 0.4s budget
        results_sink=sink,
    )

    by = {r.project: r for r in results}
    assert len(results) == 2
    assert calls["slow"] == 2, "retried exactly once"
    # Wholesale replacement: no error, counts AND elapsed from the
    # successful attempt (the timeout record carried elapsed >= 0.4).
    assert by["slow"].error is None
    assert by["slow"] == _ok_result("slow", elapsed=2.5)
    assert "timeout retry for PyPI/slow" in caplog.text
    assert "succeeded in 2.5s (warm cache)" in caplog.text
    # The refresh gate now has nothing to refuse over.
    decision = decide_baseline_refresh(
        2, results, operator_refresh=True, expected_count=2,
    )
    assert decision.allowed


def test_orphan_still_running_skips_retry_and_keeps_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When the orphaned worker is still running at the retry slot,
    the retry is skipped — never two concurrent scans of one project
    — and the timeout error stands."""
    caplog.set_level(logging.INFO)
    calls: list[str] = []
    release = threading.Event()
    orphan_finished = threading.Event()

    def _scan(
        sample: ProjectSample, out_root: Path, *, git_clone_timeout: float,
    ) -> StressResult:
        calls.append(sample.name)
        _register("PyPI/slow")
        try:
            release.wait(timeout=30)
        finally:
            _unregister("PyPI/slow")
            orphan_finished.set()
        return _ok_result("slow")

    monkeypatch.setattr(stress_mod, "_scan_one", _scan)
    try:
        results = stress_mod.run_stress_sweep(
            samples=[_sample("slow")],
            out_root=tmp_path, max_workers=2,
            git_clone_timeout=0.1, sca_timeout=0.3,
        )
    finally:
        # Let the abandoned worker finish AND wait for its registry
        # pop before returning: a pop landing after a later test
        # re-registers the same label would disarm that test's
        # budget (process-global registry).
        release.set()
        assert orphan_finished.wait(timeout=30)

    (r,) = results
    assert len(calls) == 1, "no retry may start while the orphan runs"
    assert r.error is not None and "budget" in r.error
    assert "orphan still running, retry skipped" in caplog.text
    # The refresh gate still refuses over the kept error.
    decision = decide_baseline_refresh(
        2, results, operator_refresh=True, expected_count=1,
    )
    assert not decision.allowed


def test_retry_that_also_times_out_keeps_error_no_second_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A retry that itself overruns the budget is abandoned like any
    other scan; the original timeout error stands and there is never
    a third attempt."""
    caplog.set_level(logging.INFO)
    calls: dict[str, int] = {}
    release = threading.Event()
    orphan_finished = threading.Event()
    retry_release = threading.Event()
    sink: list[StressResult] = []

    def _scan(
        sample: ProjectSample, out_root: Path, *, git_clone_timeout: float,
    ) -> StressResult:
        calls[sample.name] = n = calls.get(sample.name, 0) + 1
        if sample.name == "slow":
            if n == 1:
                _register("PyPI/slow")
                release.wait(timeout=30)
                _unregister("PyPI/slow")
                orphan_finished.set()
                return _ok_result("slow")
            # The retry: blocks past the fresh budget too.
            retry_release.wait(timeout=30)
            return _ok_result("slow")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if any(r.project == "slow" and r.error for r in sink):
                break
            time.sleep(0.01)
        release.set()
        assert orphan_finished.wait(timeout=30)
        time.sleep(0.5)
        return _ok_result("escort")

    monkeypatch.setattr(stress_mod, "_scan_one", _scan)
    try:
        results = stress_mod.run_stress_sweep(
            samples=[_sample("slow"), _sample("escort")],
            out_root=tmp_path, max_workers=2,
            git_clone_timeout=0.1, sca_timeout=0.3,
            results_sink=sink,
        )
    finally:
        retry_release.set()   # let the abandoned retry finish

    by = {r.project: r for r in results}
    assert calls["slow"] == 2, "exactly one retry — never a third"
    assert by["slow"].error is not None
    assert "scan timed out" in by["slow"].error
    assert "retry also timed out" in caplog.text


def test_non_timeout_errors_are_never_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Clone failures (including clone timeouts, which return
    normally from the worker) and raising scans complete without
    abandonment — none of them qualify for the timeout retry."""
    caplog.set_level(logging.INFO)
    calls: list[str] = []

    def _scan(
        sample: ProjectSample, out_root: Path, *, git_clone_timeout: float,
    ) -> StressResult:
        calls.append(sample.name)
        if sample.name == "cloneto":
            return StressResult(
                project=sample.name, ecosystem="PyPI",
                elapsed_seconds=0.0, deps_analysed=0,
                vuln_findings=0, eco_breakdown={},
                error="git clone failed: clone timed out after 300s",
            )
        raise RuntimeError("resolver exploded")

    monkeypatch.setattr(stress_mod, "_scan_one", _scan)
    results = stress_mod.run_stress_sweep(
        samples=[_sample("cloneto"), _sample("crash")],
        out_root=tmp_path, max_workers=2,
        git_clone_timeout=0.1, sca_timeout=0.3,
    )

    by = {r.project: r for r in results}
    assert sorted(calls) == ["cloneto", "crash"], "one attempt each"
    assert by["cloneto"].error == (
        "git clone failed: clone timed out after 300s"
    )
    assert by["crash"].error is not None
    assert "unexpected RuntimeError" in by["crash"].error
    assert "timeout retry" not in caplog.text


def test_sweep_without_timeouts_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No timeouts → the retry pass is a no-op: scan count, execution
    order, and result values are pinned to the pre-retry behavior,
    and no retry line reaches the log."""
    caplog.set_level(logging.INFO)
    calls: list[str] = []

    def _scan(
        sample: ProjectSample, out_root: Path, *, git_clone_timeout: float,
    ) -> StressResult:
        calls.append(sample.name)
        return _ok_result(sample.name)

    monkeypatch.setattr(stress_mod, "_scan_one_inner", _scan)
    results = stress_mod.run_stress_sweep(
        samples=[_sample(f"p{i}") for i in range(3)],
        out_root=tmp_path, max_workers=1,
        git_clone_timeout=0.5, sca_timeout=1.5,
    )
    # max_workers=1 makes EXECUTION order deterministic (FIFO off the
    # queue) — pin it via ``calls``. Result-list order is not
    # pinnable even pre-retry: the sweep loop iterates a done-future
    # SET, whose order within one poll batch is hash-order; compare
    # results project-sorted instead.
    assert calls == [f"p{i}" for i in range(3)]
    assert sorted(results, key=lambda r: r.project) == [
        _ok_result(f"p{i}") for i in range(3)
    ]
    assert "timeout retry" not in caplog.text
