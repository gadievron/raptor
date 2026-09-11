"""Joint-refit gate semantics + single-pass tmp-file lifecycle.

Fast tests: the corpus is tiny and the search metric / single-pass
search are stubbed, so no coordinate-descent runtime is involved.
The full-descent behaviour tests live in ``test_refit_joint.py``
(gated slow); these pin the gate's status decisions, which don't
need a real descent to exercise.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from packages.sca.calibration import refit as refit_mod
from packages.sca.calibration.refit import (
    ConstantRefit,
    RefitReport,
    joint_grid_search_refit,
)
from packages.sca.calibration.tests.test_refit import (
    _make_finding,
    _write_sample,
    _write_signals,
)


def _tiny_corpus(tmp_path: Path) -> None:
    _write_signals(tmp_path, ["CVE-1"])
    _write_sample(tmp_path, "PyPI", "p", [
        _make_finding(cve="CVE-1"),
        _make_finding(cve="CVE-2", name="other"),
    ])


def _canned_single_pass(status: str, per_constant: list[ConstantRefit]):
    """Stub for ``grid_search_refit`` returning a fixed report."""
    report = RefitReport(
        snapshot_date="2026-08-31", status=status, sample_count=2,
        overall_baseline_precision=0.5, overall_proposed_precision=0.6,
        improvement=0.1, improvement_threshold=0.05, max_delta=0.10,
        per_constant=per_constant,
    )

    def _stub(corpus_dir: Path, **kwargs: Any) -> RefitReport:
        return report
    return _stub


def _flat_metric(
    samples: list, *, overrides: dict | None = None,
) -> tuple[float, float, float]:
    """Any override set scores identically — the joint descent can
    only re-find what the single-pass already found."""
    return (0.6, 0.6, 0.6) if overrides else (0.5, 0.5, 0.5)


def test_joint_tying_passing_single_pass_propagates_proposed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When coordinate descent merely re-finds the single-pass
    optimum, a single-pass refit that passed its OWN gate must be
    propagated as ``proposed`` — requesting the more thorough
    search must never yield strictly less than the cheap one."""
    _tiny_corpus(tmp_path)
    from packages.sca.risk import current_constants
    cur = current_constants()["_KEV_FLOOR"]
    proposed = cur * 0.95
    single_row = ConstantRefit(
        name="_KEV_FLOOR", current=cur, proposed=proposed,
        baseline_precision=0.5, proposed_precision=0.6,
    )
    monkeypatch.setattr(
        refit_mod, "grid_search_refit",
        _canned_single_pass("proposed", [single_row]),
    )
    monkeypatch.setattr(refit_mod, "_search_metric", _flat_metric)

    report = joint_grid_search_refit(
        tmp_path, min_samples=1, seed=7, restarts=1,
        improvement_threshold=0.05,
        out_path=tmp_path / "joint.json",
    )
    assert report.status == "proposed"
    assert report.proposed_values == {"_KEV_FLOOR": proposed}


def test_joint_strictly_better_stays_joint_proposed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A joint result that clears the gate on its own merits keeps
    the joint values (not the single-pass ones)."""
    _tiny_corpus(tmp_path)
    from packages.sca.risk import current_constants
    constants = current_constants()
    kev_cur = constants["_KEV_FLOOR"]

    def _metric(
        samples: list, *, overrides: dict | None = None,
    ) -> tuple[float, float, float]:
        if not overrides:
            return (0.5, 0.5, 0.5)
        # Reward moving _KEV_FLOOR away from its current value —
        # at the ±10% bracket edge the P20 gain is 0.10 ≥ threshold.
        moved = abs(overrides.get("_KEV_FLOOR", kev_cur) - kev_cur)
        return (0.5 + moved / kev_cur, 0.5, 0.5)

    monkeypatch.setattr(
        refit_mod, "grid_search_refit", _canned_single_pass("rejected", []),
    )
    monkeypatch.setattr(refit_mod, "_search_metric", _metric)

    report = joint_grid_search_refit(
        tmp_path, min_samples=1, seed=7, restarts=1,
        improvement_threshold=0.05,
        out_path=tmp_path / "joint.json",
    )
    assert report.status == "proposed"
    proposed = report.proposed_values.get("_KEV_FLOOR")
    assert proposed is not None
    # The metric rewards lowering KEV_FLOOR, but the joint search must
    # respect the cross-constraint that it stays at or above the exploit-
    # evidence floor. A refit may move that floor, so do not pin the old
    # assumption that the exact -10% bracket edge is admissible.
    assert constants["_EXPLOIT_EVIDENCE_FLOOR"] <= proposed < kev_cur


def test_joint_rejected_when_single_pass_also_failed_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neither search clears its gate → rejected, nothing proposed."""
    _tiny_corpus(tmp_path)
    monkeypatch.setattr(
        refit_mod, "grid_search_refit", _canned_single_pass("rejected", []),
    )
    monkeypatch.setattr(
        refit_mod, "_search_metric",
        lambda samples, *, overrides=None: (0.5, 0.5, 0.5),
    )
    report = joint_grid_search_refit(
        tmp_path, min_samples=1, seed=7, restarts=1,
        improvement_threshold=0.05,
        out_path=tmp_path / "joint.json",
    )
    assert report.status == "rejected"
    assert report.proposed_values == {}


def test_single_pass_tmp_removed_when_grid_search_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raise inside the in-line single-pass search must not leak
    the throwaway ``.<date>.single.tmp`` report file."""
    _tiny_corpus(tmp_path)

    def _boom(corpus_dir: Path, **kwargs: Any) -> RefitReport:
        out: Path = kwargs["out_path"]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("{}")            # partial write, then die
        raise RuntimeError("mid-search failure")

    monkeypatch.setattr(refit_mod, "grid_search_refit", _boom)
    with pytest.raises(RuntimeError, match="mid-search failure"):
        joint_grid_search_refit(
            tmp_path, min_samples=1, seed=7, restarts=1,
            out_path=tmp_path / "joint.json",
        )
    leftovers = list((tmp_path / "refit").glob(".*.single.tmp"))
    assert leftovers == []
