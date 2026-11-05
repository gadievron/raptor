"""Re-measurement of elapsed-only stress-sweep failures.

Elapsed is one sample of a network-dominated process; only a
reproducing slowdown should block the sweep. Count drifts are
deterministic and must never be re-measured away.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.calibration import stress as stress_mod
from packages.sca.calibration.project_samples import ProjectSample
from packages.sca.calibration.stress import (
    StressResult,
    compare_to_baseline,
    confirm_elapsed_regressions,
)

import pytest


@pytest.fixture(autouse=True)
def _clean_in_flight_registry(monkeypatch):
    """Own registry entries and finish test workers before restoring the caller."""
    from core.testing.stress_state import isolated_stress_workers

    with isolated_stress_workers(stress_mod, monkeypatch):
        yield



def _baseline(tmp_path: Path, projects: dict) -> Path:
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps({"_source": {}, "projects": projects}))
    return p


def _sample(name: str = "proj") -> ProjectSample:
    return ProjectSample(
        name=name, ecosystem="PyPI",
        repo_url="https://example.invalid/x.git",
        git_ref="v1", license_spdx="MIT",
    )


def _result(name: str = "proj", elapsed: float = 100.0,
            vulns: int = 10, deps: int = 50,
            error: str | None = None) -> StressResult:
    return StressResult(
        project=name, ecosystem="PyPI", elapsed_seconds=elapsed,
        deps_analysed=deps, vuln_findings=vulns,
        eco_breakdown={"PyPI": vulns}, error=error,
    )


_BASE_ENTRY = {
    "ecosystem": "PyPI", "deps_analysed": 50, "vuln_findings": 10,
    "eco_breakdown": {"PyPI": 10}, "elapsed_seconds_p50": 18.0,
}


def test_transient_elapsed_fail_clears_on_fast_remeasure(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=20.0),
    )
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=100.0)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].elapsed_seconds == 20.0
    diffs = compare_to_baseline(confirmed, baseline)
    assert diffs[0].severity == "ok"


def test_reproducing_slowdown_still_fails(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=95.0),
    )
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=100.0)], [_sample()], baseline,
        out_root=tmp_path,
    )
    # min(100, 95) still >= 5x of 18.0 — a real regression survives.
    assert confirmed[0].elapsed_seconds == 95.0
    diffs = compare_to_baseline(confirmed, baseline)
    assert diffs[0].severity == "fail"


def test_count_fails_are_never_remeasured(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})

    def _boom(*a, **k):
        raise AssertionError("count-driven fail must not re-scan")

    monkeypatch.setattr(stress_mod, "_scan_one", _boom)
    # vuln_findings 10 -> 2 is a count fail (and elapsed is fine).
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=19.0, vulns=2)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].vuln_findings == 2


def test_mixed_count_and_elapsed_fail_keeps_count_verdict(
    tmp_path: Path, monkeypatch,
) -> None:
    """When counts already fail, the timing re-measure may clear the
    elapsed NOISE but must never launder the count failure — counts
    always stay from the first scan, whatever the re-scan reports."""
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        # Re-scan reports baseline-matching counts — taking them
        # would erase the recorded drift.
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=5.0, vulns=10),
    )
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=100.0, vulns=2)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].vuln_findings == 2          # first scan's counts
    assert confirmed[0].elapsed_seconds == 5.0      # min-folded timing
    diffs = compare_to_baseline(confirmed, baseline)
    assert diffs[0].severity == "fail"
    assert not any("elapsed" in i for i in diffs[0].issues)


def test_errored_remeasure_keeps_original_sample(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=1.0, error="clone blew up"),
    )
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=100.0)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].elapsed_seconds == 100.0
    assert confirmed[0].error is None


def test_remeasure_cap_bounds_extra_scans(
    tmp_path: Path, monkeypatch,
) -> None:
    projects = {
        f"p{i}": dict(_BASE_ENTRY) for i in range(5)
    }
    baseline = _baseline(tmp_path, projects)
    calls: list[str] = []

    def _fake_scan(sample, out_root, *, git_clone_timeout):
        calls.append(sample.name)
        return _result(name=sample.name, elapsed=20.0)

    monkeypatch.setattr(stress_mod, "_scan_one", _fake_scan)
    results = [_result(name=f"p{i}", elapsed=100.0) for i in range(5)]
    samples = [_sample(f"p{i}") for i in range(5)]
    confirm_elapsed_regressions(
        results, samples, baseline, out_root=tmp_path,
        max_remeasures=3,
    )
    assert len(calls) == 3


def test_scan_error_results_pass_through(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})

    def _boom(*a, **k):
        raise AssertionError("errored scans are not timing fails")

    monkeypatch.setattr(stress_mod, "_scan_one", _boom)
    confirmed = confirm_elapsed_regressions(
        [_result(error="scan timed out")], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].error == "scan timed out"


def test_elapsed_only_warn_also_remeasured(
    tmp_path: Path, monkeypatch,
) -> None:
    """Warn-level elapsed noise (3-5x) is the same single-sample
    roulette as fail-level — a fast second sample clears it from the
    report."""
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=20.0),
    )
    # 60s vs baseline 18s = 3.3x → warn band.
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=60.0)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].elapsed_seconds == 20.0
    diffs = compare_to_baseline(confirmed, baseline)
    assert diffs[0].severity == "ok"


def test_count_warn_with_fast_elapsed_not_remeasured(
    tmp_path: Path, monkeypatch,
) -> None:
    """A pure count warn must not trigger a re-scan — only the
    elapsed dimension is noisy."""
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})

    def _boom(*a, **k):
        raise AssertionError("count-driven warn must not re-scan")

    monkeypatch.setattr(stress_mod, "_scan_one", _boom)
    # vulns 10 -> 13 (+30%) = count warn; elapsed fine.
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=19.0, vulns=13)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].vuln_findings == 13


def test_fails_take_remeasure_budget_before_warns(
    tmp_path: Path, monkeypatch,
) -> None:
    """Warn-level elapsed noise earlier in the sweep order must not
    starve a genuine elapsed-only FAIL out of the shared budget —
    that would turn throttle noise back into a blocking rc=2."""
    projects = {f"p{i}": dict(_BASE_ENTRY) for i in range(4)}
    baseline = _baseline(tmp_path, projects)
    remeasured: list[str] = []

    def _fake_scan(sample, out_root, *, git_clone_timeout):
        remeasured.append(sample.name)
        return _result(name=sample.name, elapsed=20.0)

    monkeypatch.setattr(stress_mod, "_scan_one", _fake_scan)
    results = [
        _result(name="p0", elapsed=60.0),    # warn (3.3x)
        _result(name="p1", elapsed=60.0),    # warn
        _result(name="p2", elapsed=60.0),    # warn
        _result(name="p3", elapsed=200.0),   # FAIL (11x), last in order
    ]
    samples = [_sample(f"p{i}") for i in range(4)]
    confirmed = confirm_elapsed_regressions(
        results, samples, baseline, out_root=tmp_path,
        max_remeasures=3,
    )
    # The fail was re-measured (first), and the sweep exits clean.
    assert "p3" in remeasured
    assert len(remeasured) == 3
    diffs = compare_to_baseline(confirmed, baseline)
    assert all(d.severity != "fail" for d in diffs)


# ---------------------------------------------------------------------------
# run_sweep_and_report — the never-summary-less driver
# ---------------------------------------------------------------------------

def _driver_setup(tmp_path, monkeypatch, scan_fn):
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(stress_mod, "_scan_one_inner", scan_fn)
    lines: list[str] = []
    return baseline, lines


def test_endpoint_distress_degrades_project_not_sweep(
    tmp_path, monkeypatch,
) -> None:
    """A circuit-breaker fail-fast (registry 429 storm shape) raising
    out of a scan degrades THAT project with a named reason in the
    summary — the sweep completes and reports."""
    from core.http import HttpError
    from packages.sca.calibration.stress import run_sweep_and_report

    def _breaker_scan(sample, out_root, *, git_clone_timeout):
        raise HttpError(
            "Circuit open for registry.example:443; aborting retry",
            circuit_break=True,
        )

    baseline, lines = _driver_setup(tmp_path, monkeypatch, _breaker_scan)
    rc, results = run_sweep_and_report(
        [_sample()], baseline, out=lines.append, max_workers=1,
    )
    assert rc == 2
    text = "\n".join(lines)
    assert "summary:" in text
    assert "Circuit open" in text          # named reason in the report
    assert results and results[0].error


def test_systemexit_in_scan_degrades_project_not_sweep(
    tmp_path, monkeypatch,
) -> None:
    """A library sys.exit() inside a scan thread must not kill the
    driver (an uncaught SystemExit exits with NO traceback and NO
    summary — the worst post-mortem shape)."""
    from packages.sca.calibration.stress import run_sweep_and_report

    def _exiting_scan(sample, out_root, *, git_clone_timeout):
        raise SystemExit(3)

    baseline, lines = _driver_setup(tmp_path, monkeypatch, _exiting_scan)
    rc, results = run_sweep_and_report(
        [_sample()], baseline, out=lines.append, max_workers=1,
    )
    assert rc == 2
    text = "\n".join(lines)
    assert "summary:" in text
    assert "SystemExit" in text
    assert results and results[0].error and "SystemExit" in results[0].error


def test_driver_phase_failure_prints_partial_summary(
    tmp_path, monkeypatch,
) -> None:
    """A raise AFTER the scans (re-measure / compare / render) still
    produces a traceback plus a partial summary and rc=2."""
    from packages.sca.calibration.stress import run_sweep_and_report

    def _ok_scan(sample, out_root, *, git_clone_timeout):
        return _result(elapsed=19.0)

    baseline, lines = _driver_setup(tmp_path, monkeypatch, _ok_scan)

    def _boom(*a, **k):
        raise RuntimeError("post-sweep phase exploded")

    monkeypatch.setattr(
        stress_mod, "confirm_elapsed_regressions", _boom,
    )
    rc, results = run_sweep_and_report(
        [_sample()], baseline, out=lines.append, max_workers=1,
    )
    assert rc == 2
    text = "\n".join(lines)
    assert "sweep driver caught RuntimeError" in text
    assert "post-sweep phase exploded" in text
    assert "completed scans: 1/1" in text
    assert "summary:" in text              # partial summary rendered


def test_partial_summary_keeps_accepted_timeout_over_late_completion(
    tmp_path, monkeypatch,
) -> None:
    """A finished orphan must not replace the driver's timeout verdict."""
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    lines: list[str] = []

    def interrupted_sweep(*, results_sink, completed_sink, **kwargs):
        results_sink.append(_result(error="scan timed out: test budget"))
        completed_sink.append(_result())
        raise KeyboardInterrupt

    monkeypatch.setattr(stress_mod, "run_stress_sweep", interrupted_sweep)
    with pytest.raises(KeyboardInterrupt):
        stress_mod.run_sweep_and_report(
            [_sample()], baseline, out=lines.append,
        )
    text = "\n".join(lines)
    assert "completed scans: 1/1" in text
    assert "scan timed out: test budget" in text


def test_in_flight_registry_tracks_scans(tmp_path, monkeypatch) -> None:
    seen: list[list[str]] = []

    def _peeking_scan(sample, out_root, *, git_clone_timeout):
        # Keyed by invoking sample: a straggler worker from a
        # cancellation test can execute ITS scan under this test's
        # monkeypatch, appending a snapshot that is not ours.
        seen.append((sample.name, stress_mod._in_flight()))
        return _result(name=sample.name, elapsed=1.0)

    monkeypatch.setattr(stress_mod, "_scan_one_inner", _peeking_scan)
    stress_mod.run_stress_sweep(
        samples=[_sample("proj")], out_root=tmp_path, max_workers=1,
    )
    # Label-scoped and sample-keyed: an abandoned worker from a
    # cancellation test can lazily run ITS scan on this test's clock
    # (the interrupt path deliberately never joins a worker holding a
    # blocked scan), so neither registry exclusivity nor seen[0]
    # identity is assertable — this test pins that OUR scan is
    # registered while it runs.
    ours = [snap for name, snap in seen if name == "proj"]
    assert ours and "PyPI/proj" in ours[0]
    assert "PyPI/proj" not in stress_mod._in_flight()


def test_sigterm_prints_in_flight_and_partial_summary(tmp_path) -> None:
    """Runner cancellation (SIGTERM grace) must name the in-flight
    scans and print a partial summary before the process dies."""
    from core.testing.processes import reap_on_exit
    import signal
    import subprocess
    import sys
    import time as _time
    from pathlib import Path as _Path

    repo = str(_Path(stress_mod.__file__).resolve().parents[3])
    code = f"""
import json, sys, time
sys.path.insert(0, {repo!r})
from pathlib import Path
from packages.sca.calibration import stress as stress_mod
from packages.sca.calibration.stress import StressResult, run_sweep_and_report
from packages.sca.calibration.project_samples import ProjectSample

def scan(sample, out_root, *, git_clone_timeout):
    if sample.name == "fastproj":
        return StressResult(project=sample.name, ecosystem=sample.ecosystem,
                            elapsed_seconds=1.0, deps_analysed=1,
                            vuln_findings=0, eco_breakdown={{}})
    print("SCAN_STARTED", flush=True)
    time.sleep(30)

stress_mod._scan_one_inner = scan
# Hold the driver before it can collect any completed future. The worker
# still finishes fastproj and starts slowproj, so SIGTERM must recover
# fastproj from the worker-published completion journal, not lucky timing.
def hold_driver(*args, **kwargs):
    while True:
        time.sleep(0.05)
stress_mod.concurrent.futures.wait = hold_driver
baseline = Path({str(tmp_path)!r}) / "baseline.json"
baseline.write_text(json.dumps({{"_source": {{}}, "projects": {{}}}}))
def mk(name):
    return ProjectSample(name=name, ecosystem="PyPI",
                         repo_url="https://example.invalid/x.git",
                         git_ref="v1", license_spdx="MIT")
run_sweep_and_report([mk("fastproj"), mk("slowproj")], baseline,
                     max_workers=1)
"""
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin",
             "RAPTOR_DIR": repo},
    )
    with reap_on_exit(proc):
        # Wait for the scan to be registered before signalling.
        deadline = _time.monotonic() + 8
        line = ""
        while _time.monotonic() < deadline:
            line = proc.stdout.readline()
            if "SCAN_STARTED" in line:
                break
        assert "SCAN_STARTED" in line, "scan never started"
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=8)
    assert "sweep interrupted — SIGTERM" in out, out + err
    assert "in-flight scans: PyPI/slowproj" in out, out
    # The COMPLETED scan is visible to the post-mortem — a partial
    # summary claiming zero after real completions is actively
    # misleading in exactly the scenario this exists for.
    assert "completed scans: 1/2" in out, out
    assert "fastproj" in out, out
    # The default disposition then terminates the process.
    assert proc.returncode != 0


def test_keyboard_interrupt_cancels_queued_backlog(
    tmp_path, monkeypatch,
) -> None:
    """Ctrl-C must not drain the queued backlog — queued scans that
    the worker has not dequeued when the cancel lands must NEVER run,
    not even after the interrupt (pre-fix all four ran to completion
    before the interrupt surfaced).

    Determinism note: with instant scans this is a pure race — a
    worker dequeues its next item in microseconds, faster than the
    main thread can wake from as_completed and call cancel_futures,
    so any exact bound on executed scans flakes with code warmth
    (an earlier revision of this test did exactly that). Production
    scans run seconds to minutes, which this models by BLOCKING the
    scan the worker holds when the cancel lands: the queued items
    behind it deterministically never start.
    """
    import threading

    import pytest as _pytest

    release = threading.Event()
    started: list[str] = []

    def _scan(sample, out_root, *, git_clone_timeout):
        started.append(sample.name)
        if sample.name == "p0":
            raise KeyboardInterrupt
        # Model a realistic in-flight scan: hold the worker here
        # while the main thread processes the interrupt and cancels
        # the backlog.
        release.wait(timeout=30)
        return _result(name=sample.name, elapsed=1.0)

    monkeypatch.setattr(stress_mod, "_scan_one_inner", _scan)
    samples = [_sample(f"p{i}") for i in range(4)]
    try:
        with _pytest.raises(KeyboardInterrupt):
            stress_mod.run_stress_sweep(
                samples=samples, out_root=tmp_path, max_workers=1,
            )
    finally:
        # Unblock the held worker so the (non-daemon) pool thread can
        # finish and the process exits cleanly.
        release.set()
    # p0 raised; the worker had at most dequeued p1 (now blocked/
    # finishing); p2 and p3 were cancelled before dequeue and must
    # never start — including after the release above (post-cancel
    # dispatch would be exactly the bug class this pins).
    assert started[0] == "p0"
    assert set(started) <= {"p0", "p1"}, started


def test_elapsed_noise_on_count_warn_rows_is_remeasured(
    tmp_path, monkeypatch,
) -> None:
    """A row whose severity already comes from count drift can still
    carry a throttle-noise elapsed line — it must be re-measured too
    (lowest budget priority), or the noise reaches the report glued
    to the genuine count warn."""
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=20.0, vulns=13),
    )
    # vulns 10->13 = count warn; elapsed 65s vs 18s = 3.6x elapsed
    # warn — severity NOT raised by elapsed, but the line fires.
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=65.0, vulns=13)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].elapsed_seconds == 20.0
    diffs = compare_to_baseline(confirmed, baseline)
    (d,) = [x for x in diffs if x.project == "proj"]
    assert d.severity == "warn"                    # count warn stands
    assert not any("elapsed" in i for i in d.issues)


def test_elapsed_noise_tier_never_starves_raising_tiers(
    tmp_path, monkeypatch,
) -> None:
    projects = {f"p{i}": dict(_BASE_ENTRY) for i in range(4)}
    baseline = _baseline(tmp_path, projects)
    remeasured: list[str] = []

    def _fake_scan(sample, out_root, *, git_clone_timeout):
        remeasured.append(sample.name)
        return _result(name=sample.name, elapsed=20.0)

    monkeypatch.setattr(stress_mod, "_scan_one", _fake_scan)
    results = [
        _result(name="p0", elapsed=65.0, vulns=13),  # count+elapsed warn
        _result(name="p1", elapsed=65.0, vulns=13),
        _result(name="p2", elapsed=65.0, vulns=13),
        _result(name="p3", elapsed=200.0),           # elapsed-only FAIL
    ]
    confirm_elapsed_regressions(
        results, [_sample(f"p{i}") for i in range(4)], baseline,
        out_root=tmp_path, max_remeasures=3,
    )
    # Membership is the guarantee: the raised-tier fail wins a slot
    # even with three noise-tier rows ahead of it in input order
    # (execution then follows input order; the lowest-priority noise
    # row is the one dropped).
    assert "p3" in remeasured
    assert len(remeasured) == 3
    assert "p2" not in remeasured
