"""Per-scan budget enforcement + human rendering in the stress sweep.

The scan budget is per scan, measured from the moment a worker
starts it — an earlier revision applied it as one global deadline
from sweep start, falsely reporting every still-running/queued
healthy project as timed out once total wall time exceeded a
single scan's budget.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from packages.sca.calibration import stress as stress_mod
from packages.sca.calibration.project_samples import ProjectSample
from packages.sca.calibration.stress import StressDiff, StressResult


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


def _ok_result(name: str) -> StressResult:
    return StressResult(
        project=name, ecosystem="PyPI", elapsed_seconds=0.1,
        deps_analysed=5, vuln_findings=1, eco_breakdown={"PyPI": 1},
    )


def test_slow_sweep_does_not_falsely_time_out_healthy_scans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Five 0.3s scans on ONE worker: total wall (~1.5s) exceeds a
    single scan's 1.0s budget, but every scan stays well inside its
    OWN budget — none may be reported as timed out."""
    def _scan(
        sample: ProjectSample, out_root: Path, *, git_clone_timeout: float,
    ) -> StressResult:
        time.sleep(0.3)
        return _ok_result(sample.name)

    monkeypatch.setattr(stress_mod, "_scan_one_inner", _scan)
    results = stress_mod.run_stress_sweep(
        samples=[_sample(f"p{i}") for i in range(5)],
        out_root=tmp_path, max_workers=1,
        git_clone_timeout=0.2, sca_timeout=0.8,   # 1.0s per-scan budget
    )
    assert len(results) == 5
    assert all(r.error is None for r in results), [
        (r.project, r.error) for r in results
    ]


def test_scan_exceeding_own_budget_is_timed_out_and_abandoned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scan that overruns its own budget is reported as timed out
    with a truthful message, without blocking the sweep on its
    unkillable thread; a parallel healthy scan is untouched."""
    release = threading.Event()

    def _scan(
        sample: ProjectSample, out_root: Path, *, git_clone_timeout: float,
    ) -> StressResult:
        if sample.name == "slow":
            release.wait(timeout=30)
        return _ok_result(sample.name)

    monkeypatch.setattr(stress_mod, "_scan_one_inner", _scan)
    try:
        t0 = time.monotonic()
        results = stress_mod.run_stress_sweep(
            samples=[_sample("slow"), _sample("quick")],
            out_root=tmp_path, max_workers=2,
            git_clone_timeout=0.1, sca_timeout=0.4,   # 0.5s budget
        )
        wall = time.monotonic() - t0
    finally:
        release.set()   # let the abandoned worker finish

    by = {r.project: r for r in results}
    assert by["quick"].error is None
    assert by["slow"].error is not None and "budget" in by["slow"].error
    # Truthful timing: the recorded elapsed reflects the scan's own
    # runtime, at least its budget.
    assert by["slow"].elapsed_seconds >= 0.5
    # The sweep returned instead of joining the abandoned worker
    # (which was held for up to 30s).
    assert wall < 10


def test_queued_scans_cancelled_when_all_workers_over_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When every worker is held by an over-budget scan, queued
    scans are cancelled with an honest 'never started' reason —
    not falsely reported as having timed out themselves."""
    release = threading.Event()

    def _scan(
        sample: ProjectSample, out_root: Path, *, git_clone_timeout: float,
    ) -> StressResult:
        if sample.name == "hog":
            release.wait(timeout=30)
        return _ok_result(sample.name)

    monkeypatch.setattr(stress_mod, "_scan_one_inner", _scan)
    try:
        results = stress_mod.run_stress_sweep(
            samples=[_sample("hog"), _sample("queued")],
            out_root=tmp_path, max_workers=1,
            git_clone_timeout=0.1, sca_timeout=0.4,
        )
    finally:
        release.set()

    by = {r.project: r for r in results}
    assert by["hog"].error is not None and "budget" in by["hog"].error
    assert by["queued"].error is not None
    assert "never started" in by["queued"].error


# ---------------------------------------------------------------------------
# render_diffs — Title Case labels for the human text block
# ---------------------------------------------------------------------------


def test_render_diffs_title_cases_severity_labels() -> None:
    diffs = [
        StressDiff(project="a", ecosystem="PyPI", severity="fail",
                   issues=["scan error: x"]),
        StressDiff(project="b", ecosystem="npm", severity="warn",
                   issues=["vuln_findings 10 → 14"]),
        StressDiff(project="c", ecosystem="Go", severity="ok"),
        StressDiff(project="d", ecosystem="Cargo", severity="new"),
        StressDiff(project="e", ecosystem="Maven", severity="orphan"),
    ]
    text = stress_mod.render_diffs(diffs)
    assert "[ Fail ]" in text
    assert "[ Warn ]" in text
    assert "[  Ok  ]" in text
    assert "[ New  ]" in text
    assert "[Orphan]" in text
    assert "Ok=1 Warn=1 Fail=1 New=1 Orphan=1" in text
    # No lowercase enum leaks into the rendered labels.
    assert "[ fail ]" not in text and "ok=" not in text


def test_severity_enum_values_stay_lowercase_in_data() -> None:
    """The Title Case mapping is render-only: the enum on the data
    structures (what JSON consumers and diffs_to_exit_code see)
    stays lowercase."""
    d = StressDiff(project="a", ecosystem="PyPI", severity="fail")
    assert d.severity == "fail"
    assert stress_mod.diffs_to_exit_code([d]) == 2
