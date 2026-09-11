"""Baseline-refresh gating (``decide_baseline_refresh``).

The stress sweep's baseline may be captured automatically at
warn-only drift (rc=1, the pre-existing unconditional refresh —
errored scans always rank ``fail``, so rc=1 cannot carry them), and
at fail-level drift ONLY on an explicit operator adjudication (the
workflow's ``refresh-baseline`` dispatch input). The adjudicated
path refuses outright when the run is broken rather than drifted:
errored scans, an incomplete result set, or a driver-phase crash —
``write_baseline`` skips errored projects, so such a capture would
bless a partial run as the expected state.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.calibration import stress as stress_mod
from packages.sca.calibration.project_samples import ProjectSample
from packages.sca.calibration.stress import (
    StressResult,
    decide_baseline_refresh,
)


def _result(name: str, *, error: str | None = None) -> StressResult:
    return StressResult(
        project=name, ecosystem="PyPI", elapsed_seconds=1.0,
        deps_analysed=10, vuln_findings=2, eco_breakdown={"PyPI": 2},
        error=error,
    )


def test_operator_refresh_allowed_for_drift_only_fails() -> None:
    """Flag + rc=2 where every result completed cleanly (the fails
    are count/elapsed drift): the refresh is authorized."""
    results = [_result("a"), _result("b"), _result("c")]
    decision = decide_baseline_refresh(
        2, results, operator_refresh=True, expected_count=3,
    )
    assert decision.allowed
    assert "operator-adjudicated" in decision.reason


def test_operator_refresh_refused_when_any_scan_errored() -> None:
    """Flag + rc=2 with even ONE errored scan (timeout / clone
    failure / driver exception): the WHOLE refresh is refused —
    never a silent partial capture — and the reason names the
    errored project."""
    results = [
        _result("a"),
        _result("b", error="scan timed out: exceeded its 900s budget"),
        _result("c"),
    ]
    decision = decide_baseline_refresh(
        2, results, operator_refresh=True, expected_count=3,
    )
    assert not decision.allowed
    assert "PyPI/b" in decision.reason
    assert "never captured from a broken run" in decision.reason


def test_operator_refresh_refused_for_incomplete_sweep() -> None:
    """Flag + rc=2 with fewer results than samples (driver-phase
    failure left a partial list, none individually errored): refuse
    — the capture would silently drop the missing projects."""
    results = [_result("a"), _result("b")]
    decision = decide_baseline_refresh(
        2, results, operator_refresh=True, expected_count=3,
    )
    assert not decision.allowed
    assert "2 of 3" in decision.reason


def test_operator_refresh_refused_on_driver_phase_failure() -> None:
    """Flag + rc=2 where every scan completed cleanly AND the count
    matches — but the driver itself crashed in a post-sweep phase
    (re-measure / compare / render). rc=2 was earned by the crash,
    not by adjudicable drift; only the driver-failure signal can
    distinguish the two shapes, and it must refuse."""
    results = [_result("a"), _result("b"), _result("c")]
    decision = decide_baseline_refresh(
        2, results, operator_refresh=True, expected_count=3,
        driver_failures=["driver-phase failure: RuntimeError: boom"],
    )
    assert not decision.allowed
    assert "driver itself failed" in decision.reason
    assert "RuntimeError: boom" in decision.reason


def test_driver_failure_sink_records_post_sweep_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: a crash AFTER the scans leaves a complete,
    error-free results list — exactly the drift-only rc=2 shape —
    and ``run_sweep_and_report`` must record the failure in the
    caller-owned sink so the refresh gate refuses."""
    def _ok_scan(
        sample: ProjectSample, out_root: Path, *, git_clone_timeout: float,
    ) -> StressResult:
        return _result(sample.name)

    monkeypatch.setattr(stress_mod, "_scan_one_inner", _ok_scan)

    def _boom(*a: object, **k: object) -> None:
        raise RuntimeError("post-sweep phase exploded")

    monkeypatch.setattr(
        stress_mod, "confirm_elapsed_regressions", _boom,
    )
    # run_sweep_and_report has no out_root passthrough — without
    # this, run_stress_sweep would mkdir under the real per-user
    # cache root. Keep every write inside tmp_path.
    import packages.sca as sca_pkg
    monkeypatch.setattr(sca_pkg, "SCA_CACHE_ROOT", tmp_path / "cache")
    sample = ProjectSample(
        name="a", ecosystem="PyPI",
        repo_url="https://example.invalid/x.git",
        git_ref="v1", license_spdx="MIT",
    )
    sink: list[str] = []
    rc, results = stress_mod.run_sweep_and_report(
        [sample], tmp_path / "baseline.json",
        out=lambda _line: None, max_workers=1,
        driver_failure_sink=sink,
    )
    assert rc == 2
    assert results and all(r.error is None for r in results)
    assert sink and "RuntimeError" in sink[0]
    decision = decide_baseline_refresh(
        rc, results, operator_refresh=True, expected_count=1,
        driver_failures=sink,
    )
    assert not decision.allowed


def test_no_flag_keeps_fail_red_and_unrefreshed() -> None:
    """Without the operator flag, rc=2 never refreshes — even when
    every scan completed cleanly (pure drift). Cron and plain
    dispatch behaviour is unchanged."""
    results = [_result("a"), _result("b"), _result("c")]
    decision = decide_baseline_refresh(
        2, results, operator_refresh=False, expected_count=3,
    )
    assert not decision.allowed
    assert "operator must investigate" in decision.reason


def test_warn_only_drift_refreshes_with_or_without_flag() -> None:
    """rc=1 keeps the long-standing automatic refresh; the flag
    neither enables nor disables it, and the reason string is the
    exact log phrase the workflow has always printed."""
    results = [_result("a")]
    for flag in (False, True):
        decision = decide_baseline_refresh(
            1, results, operator_refresh=flag, expected_count=1,
        )
        assert decision.allowed
        assert decision.reason == "warn-only drift"


def test_clean_sweep_never_refreshes() -> None:
    """rc=0: nothing drifted, nothing to capture — with or without
    the flag."""
    results = [_result("a")]
    for flag in (False, True):
        decision = decide_baseline_refresh(
            0, results, operator_refresh=flag, expected_count=1,
        )
        assert not decision.allowed
