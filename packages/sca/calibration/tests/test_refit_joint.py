"""Tests for the joint refitter — multi-pass coordinate descent
with random restarts.

The fixture-shape helpers from ``test_refit.py`` are reused via
direct import; algorithm asserts here cover the joint-specific
contract: convergence, restart determinism, drift bound, basin-
floor detection, status semantics, report shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.sca.calibration.refit import (
    DEFAULT_MAX_DELTA,
    JointRefitReport,
    joint_grid_search_refit,
)
from packages.sca.calibration.tests.test_refit import (
    _make_finding,
    _write_sample,
    _write_signals,
)

# Multi-pass coordinate descent with random restarts: ~22s for the
# 9 tests in this module. Each restart pass converges on a held-out
# corpus, so the runtime is intrinsic, not setup overhead. Gate as
# slow — default CI skips, nightly runs full grid.
pytestmark = pytest.mark.slow


# ---------------------------------------------------------------------------
# Smoke + report shape.
# ---------------------------------------------------------------------------

def test_joint_runs_on_realistic_corpus(tmp_path: Path):
    """End-to-end smoke: joint refitter runs, produces a report
    with all per-constant rows + restart traces, status one of
    the documented values."""
    exploited_cves = [f"CVE-2026-{i}" for i in range(60)]
    _write_signals(tmp_path, exploited_cves)
    findings = []
    for i, cve in enumerate(exploited_cves):
        findings.append(_make_finding(
            cve=cve, in_kev=(i % 3 == 0),
            cvss=8.0 if i % 2 == 0 else 5.0,
            epss=0.8 if i % 4 == 0 else 0.4,
            name=f"exp-{i}",
        ))
    for i in range(100):
        findings.append(_make_finding(
            cve=f"CVE-N-{i}", in_kev=False,
            cvss=6.0, epss=0.3, name=f"non-{i}",
        ))
    _write_sample(tmp_path, "PyPI", "p", findings)

    report = joint_grid_search_refit(
        tmp_path, improvement_threshold=0.0, seed=42,
    )

    from packages.sca.risk import TUNABLE_CONSTANTS
    assert isinstance(report, JointRefitReport)
    # Per-constant row per tunable.
    assert len(report.per_constant) == len(TUNABLE_CONSTANTS)
    # At least one restart trace (restart 0 = current).
    assert len(report.restarts) >= 1
    assert report.restarts[0].seed_index == 0
    # Status is one of the documented values.
    assert report.status in (
        "proposed", "rejected", "insufficient_samples", "error",
    )
    # Joint metric ≥ baseline (search keeps best seen).
    assert report.joint_winning_metric >= report.restarts[0].starting_metric


def test_joint_insufficient_samples_short_circuits(tmp_path: Path):
    """Below MIN_SAMPLES_FOR_REFIT, joint refuses to run and
    reports ``insufficient_samples`` without invoking the
    coordinate descent."""
    _write_signals(tmp_path, [])
    findings = [_make_finding(cve=f"CVE-{i}") for i in range(50)]
    _write_sample(tmp_path, "PyPI", "p", findings)
    report = joint_grid_search_refit(tmp_path, seed=42)
    assert report.status == "insufficient_samples"
    assert report.restarts == []


def test_joint_no_samples_short_circuits(tmp_path: Path):
    """No samples at all → ``error`` status, no traces."""
    report = joint_grid_search_refit(tmp_path, seed=42)
    assert report.status == "error"
    assert report.restarts == []


def test_joint_report_writes_to_dot_joint_path(tmp_path: Path):
    """Default report path is ``<corpus>/refit/<date>.joint.json``
    so a joint refit doesn't clobber a same-day single-pass run."""
    _write_signals(tmp_path, [f"CVE-{i}" for i in range(60)])
    findings = [
        _make_finding(cve=f"CVE-{i}", in_kev=True) for i in range(60)
    ] + [
        _make_finding(cve=f"CVE-N-{i}") for i in range(100)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)
    report = joint_grid_search_refit(
        tmp_path, improvement_threshold=0.0, seed=42,
    )
    expected = tmp_path / "refit" / f"{report.snapshot_date}.joint.json"
    assert expected.is_file()
    payload = json.loads(expected.read_text())
    assert payload["mode"] == "joint"
    # Restart traces serialise as lists for the JSON round-trip.
    assert isinstance(payload["restarts"], list)
    assert all(
        set(r) >= {"seed_index", "passes", "converged",
                   "starting_metric", "final_metric", "final_values"}
        for r in payload["restarts"]
    )


# ---------------------------------------------------------------------------
# Determinism + restart count.
# ---------------------------------------------------------------------------

def test_joint_seed_makes_restarts_deterministic(tmp_path: Path):
    """Same seed → same restart trajectories. Without this, CI
    auto-PRs would propose different values on each run."""
    _write_signals(tmp_path, [f"CVE-{i}" for i in range(60)])
    findings = [
        _make_finding(cve=f"CVE-{i}", in_kev=True) for i in range(60)
    ] + [
        _make_finding(cve=f"CVE-N-{i}") for i in range(100)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)

    r1 = joint_grid_search_refit(
        tmp_path, improvement_threshold=0.0, seed=1234, restarts=3,
    )
    r2 = joint_grid_search_refit(
        tmp_path, improvement_threshold=0.0, seed=1234, restarts=3,
    )
    # Same seed → same trace endpoints.
    assert [t.final_values for t in r1.restarts] == \
           [t.final_values for t in r2.restarts]


def test_joint_different_seeds_can_diverge(tmp_path: Path):
    """Two different seeds may produce different RANDOM restart
    trajectories — restart 0 (current_constants) is always the
    same, but restart 1+ depend on the seed."""
    _write_signals(tmp_path, [f"CVE-{i}" for i in range(60)])
    findings = [
        _make_finding(cve=f"CVE-{i}", in_kev=(i % 2 == 0))
        for i in range(60)
    ] + [
        _make_finding(cve=f"CVE-N-{i}") for i in range(100)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)
    r1 = joint_grid_search_refit(
        tmp_path, improvement_threshold=0.0, seed=1, restarts=4,
    )
    r2 = joint_grid_search_refit(
        tmp_path, improvement_threshold=0.0, seed=999, restarts=4,
    )
    # Restart 0 (current_constants) IS shared: same starting point.
    assert r1.restarts[0].final_values == r2.restarts[0].final_values
    # The random restarts (index ≥ 1) sample different points across
    # seeds — at least one such trace should differ.
    differs = any(
        a.final_values != b.final_values
        for a, b in zip(r1.restarts[1:], r2.restarts[1:])
    )
    assert differs


def test_joint_restart_count_honoured(tmp_path: Path):
    """``restarts=N`` produces UP TO N traces (some may skip if
    no admissible random point can be sampled in 10 attempts —
    in practice that's rare)."""
    _write_signals(tmp_path, [f"CVE-{i}" for i in range(60)])
    findings = [
        _make_finding(cve=f"CVE-{i}", in_kev=True) for i in range(60)
    ] + [
        _make_finding(cve=f"CVE-N-{i}") for i in range(100)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)
    for r_count in (1, 2, 5):
        report = joint_grid_search_refit(
            tmp_path, improvement_threshold=0.0,
            seed=42, restarts=r_count,
        )
        assert len(report.restarts) <= r_count
        assert len(report.restarts) >= 1


# ---------------------------------------------------------------------------
# Safety: drift bound vs starting constants.
# ---------------------------------------------------------------------------

def test_joint_drift_bounded_to_max_delta(tmp_path: Path):
    """The headline safety guarantee — no constant moves more
    than ±max_delta of its STARTING (current_constants) value,
    regardless of how many coordinate-descent passes run.

    Without this bound, coord-descent could drift a constant
    arbitrarily far over many passes; with this bound,
    multi-pass is just a more efficient grid search over the
    same admissible window the single-pass already considers.
    """
    _write_signals(tmp_path, [f"CVE-{i}" for i in range(60)])
    findings = [
        _make_finding(cve=f"CVE-{i}", in_kev=(i % 2 == 0))
        for i in range(60)
    ] + [
        _make_finding(cve=f"CVE-N-{i}") for i in range(100)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)

    from packages.sca.risk import current_constants, TUNABLE_CONSTANTS
    starting = current_constants()
    max_delta = DEFAULT_MAX_DELTA

    report = joint_grid_search_refit(
        tmp_path, max_delta=max_delta,
        improvement_threshold=0.0, seed=42, restarts=4,
    )
    for trace in report.restarts:
        for name in TUNABLE_CONSTANTS:
            cur = starting[name]
            val = trace.final_values[name]
            # Allow a 1e-9 fudge for float arithmetic.
            lo = cur * (1.0 - max_delta) - 1e-9
            hi = cur * (1.0 + max_delta) + 1e-9
            assert lo <= val <= hi, (
                f"{name}: descent drifted out of bracket "
                f"[{lo:.6f}, {hi:.6f}] to {val:.6f} "
                f"(restart={trace.seed_index})"
            )


def test_joint_per_constant_winners_within_bracket(tmp_path: Path):
    """The endpoint values surfaced as per_constant rows must
    also be in the bracket — sanity-check that the report
    proposal matches the safety guarantee."""
    _write_signals(tmp_path, [f"CVE-{i}" for i in range(60)])
    findings = [
        _make_finding(cve=f"CVE-{i}", in_kev=True) for i in range(60)
    ] + [
        _make_finding(cve=f"CVE-N-{i}") for i in range(100)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)

    from packages.sca.risk import current_constants

    report = joint_grid_search_refit(
        tmp_path, max_delta=DEFAULT_MAX_DELTA,
        improvement_threshold=0.0, seed=42,
    )
    starting = current_constants()
    for c in report.per_constant:
        cur = starting[c.name]
        lo = cur * (1.0 - DEFAULT_MAX_DELTA) - 1e-9
        hi = cur * (1.0 + DEFAULT_MAX_DELTA) + 1e-9
        assert lo <= c.proposed <= hi


# ---------------------------------------------------------------------------
# Status semantics: basin-floor detection.
# ---------------------------------------------------------------------------

def test_joint_rejects_when_no_gain_over_single_pass(tmp_path: Path):
    """When the per-constant winners already capture all the
    signal in the corpus, joint search shouldn't find more.
    Status=rejected with a note that confirms per-constant
    is at the basin floor."""
    # Constant-label corpus: every finding has the SAME exploited
    # flag. ρ is undefined → 0; precision is also flat. Joint can't
    # improve here because there's no signal to optimise on.
    _write_signals(tmp_path, [])
    findings = [
        _make_finding(cve=f"CVE-{i}", in_kev=False, score=50.0)
        for i in range(120)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)
    report = joint_grid_search_refit(
        tmp_path, improvement_threshold=0.05, seed=42,
    )
    assert report.status == "rejected"
    # The note explains what's happening so the operator can act
    # on it (add signal sources, expand corpus, etc.) rather than
    # going looking for a code bug.
    assert any("basin floor" in n for n in report.notes)


def test_joint_winning_metric_at_least_starting(tmp_path: Path):
    """Joint refitter always returns the BEST endpoint seen
    across restarts; that endpoint is at least as good as the
    starting metric (restart 0 starts from current_constants
    which IS a valid endpoint when the descent can't improve)."""
    _write_signals(tmp_path, [f"CVE-{i}" for i in range(60)])
    findings = [
        _make_finding(cve=f"CVE-{i}", in_kev=True) for i in range(60)
    ] + [
        _make_finding(cve=f"CVE-N-{i}") for i in range(100)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)
    report = joint_grid_search_refit(
        tmp_path, improvement_threshold=0.0, seed=42,
    )
    # joint_winning_metric ≥ restart 0's starting metric.
    assert report.joint_winning_metric >= report.restarts[0].starting_metric


# ---------------------------------------------------------------------------
# Admissibility: per-step constraint check.
# ---------------------------------------------------------------------------

def test_joint_endpoints_pass_admissibility(tmp_path: Path):
    """Every restart's endpoint values, taken jointly, must pass
    ``is_admissible``. The per-step admissibility check inside
    the coordinate descent rejects inadmissible moves; this test
    verifies the safety property end-to-end."""
    _write_signals(tmp_path, [f"CVE-{i}" for i in range(60)])
    findings = [
        _make_finding(cve=f"CVE-{i}", in_kev=True) for i in range(60)
    ] + [
        _make_finding(cve=f"CVE-N-{i}") for i in range(100)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)
    from packages.sca.risk import is_admissible

    report = joint_grid_search_refit(
        tmp_path, improvement_threshold=0.0, seed=42, restarts=4,
    )
    for trace in report.restarts:
        ok, reason = is_admissible(trace.final_values)
        assert ok, (
            f"restart {trace.seed_index} ended at inadmissible "
            f"values: {reason}"
        )
