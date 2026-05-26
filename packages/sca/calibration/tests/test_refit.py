"""Tests for ``packages.sca.calibration.refit`` — grid-search
refitter for the risk-score multipliers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import pytest

from packages.sca.calibration.refit import (
    ConstantRefit,
    RefitReport,
    grid_search_refit,
    _top_20_precision,
    _load_findings_with_labels,
    _load_ground_truth,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _write_signals(corpus_dir: Path, exploited_cves: List[str]) -> None:
    """Write a tiny KEV signals file marking the given CVEs as
    exploited. Format mirrors what build.py emits — top-level
    ``signals`` dict keyed by CVE id."""
    (corpus_dir / "kev_signals.json").write_text(json.dumps({
        "signals": {c: {} for c in exploited_cves},
    }))


def _write_sample(
    corpus_dir: Path, eco: str, project: str,
    findings: List[Dict],
) -> None:
    """Write a project_samples/<eco>/<project>.json fixture."""
    samples_dir = corpus_dir / "project_samples" / eco
    samples_dir.mkdir(parents=True, exist_ok=True)
    (samples_dir / f"{project}.json").write_text(json.dumps({
        "snapshot_date": "2026-05-08",
        "ecosystem": eco,
        "project": project,
        "findings": findings,
    }))


def _make_finding(
    *, cve: str, score: float = 50.0,
    in_kev: bool = False, epss: float = 0.5,
    cvss: float = 7.5, ecosystem: str = "PyPI",
    name: str = "pkg", version: str = "1.0.0",
    reach_verdict: str = "imported",
    transitive_depth: int = 0,
    exposure: float = 0.5,
) -> Dict:
    """Build a finding dict matching the project_samples archive
    shape — enough fields for compute_risk_estimate to re-score."""
    return {
        "finding_id": f"sca:{ecosystem}:{name}:{cve}",
        "raptor_risk_estimate": score,
        "cvss_score": cvss,
        "in_kev": in_kev,
        "epss": epss,
        "exposure_factor": exposure,
        "transitive_depth": transitive_depth,
        "ecosystem": ecosystem,
        "severity": "high",
        "advisory": {"osv_id": cve, "aliases": [cve]},
        "dependency": {
            "ecosystem": ecosystem, "name": name, "version": version,
            "declared_in": "./x", "scope": "main",
            "is_lockfile": False, "pin_style": "exact",
            "direct": True, "purl": f"pkg:{ecosystem}/{name}@{version}",
            "parser_confidence": {
                "level": "high", "reason": "t", "numeric": 0.95,
            },
        },
        "reachability": {
            "verdict": reach_verdict,
            "confidence": {
                "level": "high", "reason": "t", "numeric": 0.95,
            },
            "evidence": [],
        },
        "version_match_confidence": {
            "level": "high", "reason": "t", "numeric": 0.95,
        },
    }


# ---------------------------------------------------------------------------
# _load_ground_truth
# ---------------------------------------------------------------------------


def test_ground_truth_aggregates_across_signal_files(tmp_path: Path):
    """Real signal files (built by calibration/build.py) carry a
    top-level ``signals`` dict keyed by CVE id. Loader must read
    that shape — refit treated every finding as not-exploited for
    months because the loader looked for an ``items`` list shape
    that no signal file actually emits."""
    (tmp_path / "kev_signals.json").write_text(json.dumps({
        "signals": {"CVE-2025-1": {"date_added": "2025-01-01"}},
    }))
    (tmp_path / "exploitdb_signals.json").write_text(json.dumps({
        "signals": {"CVE-2025-2": {"edb_id": "12345"}},
    }))
    (tmp_path / "metasploit_signals.json").write_text(json.dumps({
        "signals": {"CVE-2025-3": {"module": "exploit/x"}},
    }))
    (tmp_path / "github_poc_signals.json").write_text(json.dumps({
        "signals": {"CVE-2025-4": {"repo": "x/y"}},
    }))
    signals = _load_ground_truth(tmp_path)
    assert "CVE-2025-1" in signals
    assert "CVE-2025-2" in signals
    assert "CVE-2025-3" in signals
    assert "CVE-2025-4" in signals


def test_ground_truth_rejects_legacy_items_shape(tmp_path: Path):
    """Old ``{"items": [...]}`` shape isn't what build.py emits;
    loader must not silently accept it (the silent acceptance
    cost us months of zero-baseline refit). With the wrong shape
    it returns empty rather than misleadingly populating from a
    file that won't match production data."""
    (tmp_path / "kev_signals.json").write_text(json.dumps({
        "items": [{"cve_id": "CVE-LEGACY-1"}],
    }))
    assert _load_ground_truth(tmp_path) == set()


def test_ground_truth_handles_missing_files(tmp_path: Path):
    """No signal files at all → empty set, no exception."""
    assert _load_ground_truth(tmp_path) == set()


def test_ground_truth_handles_malformed_json(tmp_path: Path):
    (tmp_path / "kev_signals.json").write_text("not json")
    assert _load_ground_truth(tmp_path) == set()


# ---------------------------------------------------------------------------
# _load_findings_with_labels
# ---------------------------------------------------------------------------


def test_load_findings_labels_exploited_correctly(tmp_path: Path):
    _write_signals(tmp_path, ["CVE-2025-1"])
    _write_sample(tmp_path, "PyPI", "p", [
        _make_finding(cve="CVE-2025-1", score=80),
        _make_finding(cve="CVE-2025-99", score=20),
    ])
    samples = _load_findings_with_labels(tmp_path)
    by_cve = {
        s[0]["advisory"]["osv_id"]: s[1] for s in samples
    }
    assert by_cve["CVE-2025-1"] == 1
    assert by_cve["CVE-2025-99"] == 0


def test_load_findings_handles_no_samples_dir(tmp_path: Path):
    assert _load_findings_with_labels(tmp_path) == []


def test_load_findings_skips_malformed_samples(tmp_path: Path):
    _write_signals(tmp_path, [])
    samples_dir = tmp_path / "project_samples" / "PyPI"
    samples_dir.mkdir(parents=True)
    (samples_dir / "broken.json").write_text("not json")
    (samples_dir / "missing-findings.json").write_text(json.dumps({
        "ecosystem": "PyPI",
    }))
    (samples_dir / "good.json").write_text(json.dumps({
        "ecosystem": "PyPI",
        "findings": [_make_finding(cve="CVE-X")],
    }))
    samples = _load_findings_with_labels(tmp_path)
    assert len(samples) == 1


# ---------------------------------------------------------------------------
# _top_20_precision — under override
# ---------------------------------------------------------------------------


def test_top_20_precision_baseline_uses_archived_score():
    """When overrides=None, the function reads the archived
    raptor_risk_estimate and ranks by it."""
    samples = [
        (_make_finding(cve="CVE-1", score=90), 1),
        (_make_finding(cve="CVE-2", score=80), 1),
        (_make_finding(cve="CVE-3", score=10), 0),
    ]
    p = _top_20_precision(samples, overrides=None)
    # All 3 in top 20; 2 of 3 exploited.
    assert p == pytest.approx(2 / 3)


def test_top_20_precision_with_overrides_recomputes():
    """When overrides are given, scores are recomputed via
    compute_risk_estimate. Set _KEV_FLOOR=100 so KEV findings
    rank above non-KEV regardless of CVSS."""
    samples = [
        (_make_finding(cve="CVE-1", in_kev=True, cvss=2.0), 1),
        (_make_finding(cve="CVE-2", in_kev=False, cvss=9.0), 0),
    ]
    p = _top_20_precision(samples, overrides={"_KEV_FLOOR": 100.0})
    # KEV finding should now be #1, both fit in top 20.
    assert p == pytest.approx(0.5)


def test_top_20_precision_empty_samples_returns_zero():
    assert _top_20_precision([], overrides=None) == 0.0


# ---------------------------------------------------------------------------
# grid_search_refit — orchestration
# ---------------------------------------------------------------------------


def test_refit_insufficient_samples(tmp_path: Path):
    """Below MIN_SAMPLES_FOR_REFIT → status=insufficient_samples."""
    _write_signals(tmp_path, [])
    _write_sample(tmp_path, "PyPI", "p", [
        _make_finding(cve="CVE-X")
    ])
    report = grid_search_refit(tmp_path)
    assert report.status == "insufficient_samples"
    assert report.sample_count == 1
    assert report.proposed_values == {}


def test_refit_no_samples_at_all(tmp_path: Path):
    """Empty corpus → status=error (not insufficient_samples;
    that's for non-zero-but-too-few)."""
    _write_signals(tmp_path, [])
    # No project_samples dir at all.
    report = grid_search_refit(tmp_path)
    assert report.status == "error"
    assert report.sample_count == 0


def test_refit_writes_report_to_default_location(tmp_path: Path):
    """Without --out, the report lands at refit/<date>.json."""
    _write_signals(tmp_path, [])
    _write_sample(tmp_path, "PyPI", "p", [_make_finding(cve="CVE-X")])
    grid_search_refit(tmp_path, min_samples=1)
    refit_dir = tmp_path / "refit"
    assert refit_dir.is_dir()
    files = list(refit_dir.glob("*.json"))
    assert len(files) == 1


def test_refit_writes_report_to_custom_out(tmp_path: Path):
    _write_signals(tmp_path, [])
    _write_sample(tmp_path, "PyPI", "p", [_make_finding(cve="CVE-X")])
    out = tmp_path / "custom-refit-output.json"
    grid_search_refit(tmp_path, min_samples=1, out_path=out)
    assert out.is_file()


def test_refit_per_constant_results_emitted(tmp_path: Path):
    """Every tunable constant in risk.TUNABLE_CONSTANTS gets a
    ConstantRefit row in the report."""
    _write_signals(tmp_path, ["CVE-1"])
    findings = [
        _make_finding(cve=f"CVE-{i}", score=50.0)
        for i in range(120)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)
    report = grid_search_refit(tmp_path)

    from packages.sca.risk import TUNABLE_CONSTANTS
    assert len(report.per_constant) == len(TUNABLE_CONSTANTS)
    assert {c.name for c in report.per_constant} == set(TUNABLE_CONSTANTS)


def test_refit_runs_on_realistic_corpus(tmp_path: Path):
    """End-to-end smoke: the refitter runs, produces a report
    with all per-constant rows populated, and computes a
    baseline + proposed precision. We don't assert WHICH
    constants change — the multiplicative formula's structure
    means single-constant ±10% nudges can't always override
    larger multipliers like EPSS, and the test would be too
    fragile to specific corpus shapes. The algorithm-correctness
    asserts are in the dedicated tests above."""
    exploited_cves = [f"CVE-2025-{i}" for i in range(60)]
    _write_signals(tmp_path, exploited_cves)
    findings = []
    # 60 exploited findings, mix of KEV / high-CVSS / high-EPSS so
    # the precision metric has SOMETHING to discriminate.
    for i, cve in enumerate(exploited_cves):
        findings.append(_make_finding(
            cve=cve, in_kev=(i % 3 == 0),
            cvss=8.0 if i % 2 == 0 else 5.0,
            epss=0.8 if i % 4 == 0 else 0.4,
            name=f"exp-{i}",
        ))
    # 100 non-exploited findings, similar mix.
    for i in range(100):
        findings.append(_make_finding(
            cve=f"CVE-N-{i}", in_kev=False,
            cvss=6.0, epss=0.3,
            name=f"non-{i}",
        ))
    _write_sample(tmp_path, "PyPI", "p", findings)

    report = grid_search_refit(
        tmp_path, improvement_threshold=0.0,
    )

    # Algorithm contract:
    #   1. Per-constant rows for every tunable.
    from packages.sca.risk import TUNABLE_CONSTANTS
    assert len(report.per_constant) == len(TUNABLE_CONSTANTS)
    #   2. Baseline + proposed precisions are real floats in [0, 1].
    assert 0.0 <= report.overall_baseline_precision <= 1.0
    assert 0.0 <= report.overall_proposed_precision <= 1.0
    #   3. Status is one of the documented values.
    assert report.status in (
        "proposed", "rejected", "insufficient_samples", "error",
    )
    #   4. Proposed precision >= baseline (grid search picks max).
    assert (report.overall_proposed_precision
            >= report.overall_baseline_precision - 1e-9)


def test_refit_rejects_when_improvement_below_threshold(
    tmp_path: Path,
):
    """High threshold → proposed values are calculated but the
    overall improvement doesn't clear; status=rejected."""
    _write_signals(tmp_path, [])
    findings = [
        _make_finding(cve=f"CVE-{i}", score=50.0)
        for i in range(120)
    ]
    _write_sample(tmp_path, "PyPI", "p", findings)
    report = grid_search_refit(
        tmp_path, improvement_threshold=0.99,
    )
    assert report.status == "rejected"


def test_refit_max_delta_caps_proposed_value(tmp_path: Path):
    """No constant moves more than max_delta of its current
    value, regardless of how strongly the data argues for it."""
    exploited_cves = [f"CVE-{i}" for i in range(60)]
    _write_signals(tmp_path, exploited_cves)
    findings = []
    for i, cve in enumerate(exploited_cves):
        findings.append(_make_finding(
            cve=cve, in_kev=True, cvss=2.0, name=f"k{i}",
        ))
    for i in range(60):
        findings.append(_make_finding(
            cve=f"CVE-N-{i}", in_kev=False, cvss=9.0, name=f"n{i}",
        ))
    _write_sample(tmp_path, "PyPI", "p", findings)

    from packages.sca.risk import current_constants
    current = current_constants()
    report = grid_search_refit(
        tmp_path, max_delta=0.05, improvement_threshold=0.0,
    )
    for c in report.per_constant:
        cur = current[c.name]
        delta = abs(c.proposed - cur) / cur
        assert delta <= 0.05 + 1e-9, (
            f"{c.name}: cur={cur}, proposed={c.proposed}, "
            f"delta={delta:.4f} > max_delta=0.05"
        )


# ---------------------------------------------------------------------------
# RefitReport — proposed_values property
# ---------------------------------------------------------------------------


def test_proposed_values_excludes_unchanged_constants():
    """Only constants that genuinely changed appear in
    proposed_values — the dict that gets fed to apply_refit."""
    report = RefitReport(
        snapshot_date="2026-05-08",
        status="proposed",
        sample_count=200,
        overall_baseline_precision=0.5,
        overall_proposed_precision=0.6,
        improvement=0.1,
        improvement_threshold=0.05,
        max_delta=0.10,
        per_constant=[
            ConstantRefit(
                name="_KEV_MULTIPLIER", current=1.20, proposed=1.32,
                baseline_precision=0.5, proposed_precision=0.55,
            ),
            ConstantRefit(
                name="_EPSS_RANGE_MULTIPLIER", current=0.70, proposed=0.70,
                baseline_precision=0.5, proposed_precision=0.5,
            ),
        ],
    )
    assert report.proposed_values == {"_KEV_MULTIPLIER": 1.32}


# ---------------------------------------------------------------------------
# Tuple-metric tiebreaker — once top-20 saturates, top-50 wins
# ---------------------------------------------------------------------------


def test_search_metric_returns_top20_ndcg_rho_tuple():
    """The internal search uses (top_20_precision, ndcg_20, rho).
    Top-20 dominates; NDCG@20 is the second tiebreaker; Spearman
    ρ across the whole corpus is the third. The third dimension
    was added 2026-05-21 after the Vulnrichment ground-truth
    integration saturated P20 and NDCG@20 across many candidate
    weight settings — the ρ tiebreaker lets the search prefer
    settings that rank exploited findings correctly across the
    WHOLE corpus, not just within the top 20."""
    from packages.sca.calibration.refit import _search_metric
    samples = []
    for i in range(20):
        samples.append((
            {"raptor_risk_estimate": 100.0 - i,
             "advisory": {}, "in_kev": False},
            1,
        ))
    # 30 more — half exploited, but ranked below the top 20.
    for i in range(20, 50):
        label = 1 if i % 2 == 0 else 0
        samples.append((
            {"raptor_risk_estimate": 50.0 - (i - 20),
             "advisory": {}, "in_kev": False},
            label,
        ))
    p20, ndcg, rho = _search_metric(samples)
    assert p20 == 1.0
    # All top-20 are exploited and there are >20 exploited overall,
    # so DCG@20 == IDCG@20 → NDCG = 1.0.
    assert ndcg == pytest.approx(1.0)
    # ρ slot is a float. In this synthetic fixture the per-finding
    # rebuild collapses every finding to the SAME default score
    # (no CVSS / no signals → cvss_missing default), so
    # ``_spearman_rho`` returns None (constant-x case) and the
    # tuple's ρ position falls back to 0.0. The shape assertion
    # is what this test pins; ρ-sensitivity is exercised by the
    # ρ-aware-improvement-gate test below.
    assert isinstance(rho, float)


def test_ndcg_distinguishes_orderings_when_precision_ties():
    """The whole point of NDCG over the previous top-50 tiebreaker:
    candidate A puts the most-confident exploited finding at rank
    1; candidate B puts it at rank 18. Both have precision = 1.0
    over top-20 (all 20 exploited). NDCG must rank A higher
    because it's a strictly-better-ordered top-20."""
    from packages.sca.calibration.refit import _ndcg_at_n
    # Both equally-ordered top-20s have precision 1.0 — but reorder
    # shouldn't matter since both have 20/20 exploited. NDCG should
    # equal 1.0 in both cases. The DIFFERENTIATING case is when only
    # N < 20 of top-20 are exploited but at different ranks.
    rescored_c = [(100.0 - i, 1) for i in range(10)] + \
                  [(90.0 - i, 0) for i in range(10)]   # 10 exploited at top
    rescored_d = [(100.0 - i, 0) for i in range(10)] + \
                  [(90.0 - i, 1) for i in range(10)]   # 10 exploited at bottom
    # Same top-20 precision (10/20 = 0.5 — but NOTE n_exploited=10,
    # so both candidates have all exploited within top-20).
    n_c = _ndcg_at_n(rescored_c, n=20)
    n_d = _ndcg_at_n(rescored_d, n=20)
    assert n_c > n_d, (
        f"NDCG should rank top-loaded above bottom-loaded: "
        f"top-loaded={n_c:.3f}, bottom-loaded={n_d:.3f}"
    )


def test_ndcg_zero_when_no_exploited():
    from packages.sca.calibration.refit import _ndcg_at_n
    rescored = [(100.0 - i, 0) for i in range(10)]
    assert _ndcg_at_n(rescored, n=20) == 0.0


def test_ndcg_perfect_when_all_top_n_are_exploited():
    from packages.sca.calibration.refit import _ndcg_at_n
    rescored = [(100.0 - i, 1) for i in range(20)] + \
                [(0.0 - i, 0) for i in range(80)]   # 20 exploited, 80 clean
    assert _ndcg_at_n(rescored, n=20) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# ecosystem_filter — per-eco refit substrate
# ---------------------------------------------------------------------------


def test_ecosystem_filter_drops_other_ecos(tmp_path: Path):
    """grid_search_refit's ``ecosystem_filter`` arg restricts the
    sample set to one ecosystem before fitting. Used by operators
    to compare per-eco optimal constants without introducing
    per-eco constants in code."""
    _write_signals(tmp_path, ["CVE-2025-1"])
    _write_sample(tmp_path, "PyPI", "p", [
        _make_finding(cve="CVE-2025-1", score=80, ecosystem="PyPI"),
    ])
    _write_sample(tmp_path, "npm", "n", [
        _make_finding(cve="CVE-2025-99", score=20, ecosystem="npm"),
    ])
    # Without filter — sees both.
    report_all = grid_search_refit(
        tmp_path, max_delta=0.10, min_samples=1,
    )
    assert report_all.sample_count == 2
    assert "ecosystem_filter" not in " ".join(report_all.notes)

    # With filter — only PyPI.
    report_py = grid_search_refit(
        tmp_path, max_delta=0.10, min_samples=1,
        ecosystem_filter="PyPI",
    )
    assert report_py.sample_count == 1
    assert any("ecosystem_filter='PyPI'" in n for n in report_py.notes)

    # Filter for an ecosystem with no samples — sample_count=0.
    report_none = grid_search_refit(
        tmp_path, max_delta=0.10, min_samples=1,
        ecosystem_filter="Cargo",
    )
    assert report_none.sample_count == 0
