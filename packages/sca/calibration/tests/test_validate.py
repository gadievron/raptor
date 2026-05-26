"""Tests for ``packages.sca.calibration.validate``.

Spearman + top-N math checks first (no fixtures needed), then
end-to-end against a small synthetic corpus.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.calibration.validate import (
    _ranks,
    _spearman_rho,
    _top_n_precision,
    _verdict,
    validate_corpus,
)


# ---------------------------------------------------------------------------
# _ranks — average-rank for ties
# ---------------------------------------------------------------------------


def test_ranks_no_ties():
    assert _ranks([10, 20, 30]) == [1.0, 2.0, 3.0]


def test_ranks_with_two_way_tie():
    """Two equal values share the average of their positions."""
    # Values [10, 20, 20, 30]: ranks 1, 2.5, 2.5, 4
    assert _ranks([10, 20, 20, 30]) == [1.0, 2.5, 2.5, 4.0]


def test_ranks_with_three_way_tie():
    # [5, 5, 5, 10]: ranks 2, 2, 2, 4
    assert _ranks([5, 5, 5, 10]) == [2.0, 2.0, 2.0, 4.0]


def test_ranks_unsorted_input():
    """Input order is preserved in the output (rank by position)."""
    assert _ranks([30, 10, 20]) == [3.0, 1.0, 2.0]


# ---------------------------------------------------------------------------
# _spearman_rho
# ---------------------------------------------------------------------------


def test_spearman_perfect_positive_correlation():
    """Score rank exactly matches signal rank → ρ = 1.0."""
    x = [0.1, 0.5, 0.9]
    y = [0, 0, 1]   # higher y at higher x
    rho = _spearman_rho(x, y)
    # Hand-computed: ranks(x)=[1,2,3] ranks(y)=[1.5,1.5,3]
    # d²=0.25+0.25+0=0.5; ρ = 1 - 6*0.5/(3*8) = 1 - 0.125 = 0.875
    assert rho is not None and rho > 0.85


def test_spearman_perfect_negative_correlation():
    x = [0.1, 0.5, 0.9]
    y = [1, 1, 0]
    rho = _spearman_rho(x, y)
    assert rho is not None and rho < 0


def test_spearman_no_correlation():
    """Random pairing of scores and signals → ρ near 0."""
    x = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
    y = [1, 0, 1, 0, 1, 0]
    rho = _spearman_rho(x, y)
    # ρ should be close to 0 (alternating pattern is anti-correlated
    # with the rank order — slightly negative).
    assert rho is not None and abs(rho) < 0.3


def test_spearman_too_few_pairs_returns_none():
    assert _spearman_rho([], []) is None
    assert _spearman_rho([0.5], [1]) is None


def test_spearman_constant_input_returns_none():
    """All-equal scores OR all-equal signals → correlation
    undefined."""
    assert _spearman_rho([0.5, 0.5, 0.5], [0, 1, 0]) is None
    assert _spearman_rho([0.1, 0.5, 0.9], [1, 1, 1]) is None


def test_spearman_mismatched_lengths_returns_none():
    assert _spearman_rho([0.1, 0.5], [1, 0, 1]) is None


# ---------------------------------------------------------------------------
# _top_n_precision
# ---------------------------------------------------------------------------


def test_top_n_precision_full_match():
    sorted_findings = [
        ("PyPI", 0.9, True), ("PyPI", 0.8, True), ("PyPI", 0.7, True),
    ]
    assert _top_n_precision(sorted_findings, n=3) == 1.0


def test_top_n_precision_partial():
    sorted_findings = [
        ("PyPI", 0.9, True), ("PyPI", 0.8, False),
        ("PyPI", 0.7, True), ("PyPI", 0.6, False),
    ]
    assert _top_n_precision(sorted_findings, n=4) == 0.5


def test_top_n_precision_n_larger_than_list():
    """When fewer findings than N, denominator is the list size."""
    sorted_findings = [("PyPI", 0.9, True), ("PyPI", 0.8, False)]
    assert _top_n_precision(sorted_findings, n=20) == 0.5


def test_top_n_precision_empty_list():
    assert _top_n_precision([], n=20) == 0.0


# ---------------------------------------------------------------------------
# _verdict
# ---------------------------------------------------------------------------


def test_verdict_validated_when_both_thresholds_met():
    verdict, notes = _verdict(
        p20=0.6, rho=0.5, with_score=100,
        threshold_top_20=0.5, threshold_spearman=0.4,
    )
    assert verdict == "validated_v1"
    assert notes == []


def test_verdict_needs_retune_on_low_top20():
    verdict, notes = _verdict(
        p20=0.3, rho=0.5, with_score=100,
        threshold_top_20=0.5, threshold_spearman=0.4,
    )
    assert verdict == "needs_retune"
    assert any("top-20 precision" in n for n in notes)


def test_verdict_needs_retune_on_low_spearman():
    verdict, notes = _verdict(
        p20=0.7, rho=0.2, with_score=100,
        threshold_top_20=0.5, threshold_spearman=0.4,
    )
    assert verdict == "needs_retune"
    assert any("Spearman" in n for n in notes)


def test_verdict_unverified_when_corpus_too_small():
    """Below the 50-findings minimum, the verdict is always
    ``unverified`` regardless of metrics — small samples produce
    untrustworthy correlations."""
    verdict, notes = _verdict(
        p20=1.0, rho=1.0, with_score=10,
        threshold_top_20=0.5, threshold_spearman=0.4,
    )
    assert verdict == "unverified"
    assert any("only 10 scored findings" in n for n in notes)


# ---------------------------------------------------------------------------
# validate_corpus — end-to-end on a synthetic corpus
# ---------------------------------------------------------------------------


def _build_synthetic_corpus(corpus_dir: Path, *, scored: int) -> None:
    """Lay down a small corpus for end-to-end validation tests.

    Constructed so the score perfectly correlates with the
    ground-truth signal: the first half of CVEs are EXPLOITED AND
    high-scoring; the second half are NOT exploited AND low-scoring.
    Validation should produce ρ close to +1 and top-N precision
    near 1.0.
    """
    half = scored // 2
    # Ground truth: first half (indices 0..half-1) are KEV-listed.
    kev = {
        "_source": {"license": "PD", "url": "x", "fetched_at": "2024-01-01"},
        "signals": {
            f"CVE-2024-{i:04d}": {"kev": True}
            for i in range(half)
        },
    }
    (corpus_dir / "kev_signals.json").write_text(json.dumps(kev))

    # Project samples: scores aligned with the exploited half.
    # i in [0, half) -> exploited + score >= 0.5
    # i in [half, scored) -> not exploited + score < 0.5
    findings = []
    for i in range(scored):
        if i < half:
            score = 1.0 - (i / scored)   # 1.0 down to 0.5
        else:
            score = 1.0 - (i / scored)   # 0.5 down to ~0.0
        findings.append({
            "finding_id": f"id-{i}",
            "severity": "high" if i < half else "medium",
            "ecosystem": "PyPI",
            "dep_name": f"dep{i}",
            "dep_version": "1.0",
            "purl": f"pkg:pypi/dep{i}@1.0",
            "advisory": {"osv_id": f"CVE-2024-{i:04d}",
                         "aliases": [f"CVE-2024-{i:04d}"]},
            "in_kev": (i < half),
            "raptor_risk_estimate": score,
        })
    sample = {
        "_source": {"license": "MIT", "url": "x"},
        "findings": findings,
    }
    samples_dir = corpus_dir / "project_samples" / "PyPI"
    samples_dir.mkdir(parents=True, exist_ok=True)
    (samples_dir / "synthetic.json").write_text(json.dumps(sample))


def test_validate_corpus_emits_report_file(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "calibration"
    corpus_dir.mkdir()
    _build_synthetic_corpus(corpus_dir, scored=80)
    validate_corpus(corpus_dir)
    out_files = list((corpus_dir / "validation").iterdir())
    assert len(out_files) == 1
    on_disk = json.loads(out_files[0].read_text())
    assert on_disk["findings_with_score"] == 80


def test_validate_corpus_validated_when_score_correlates(
    tmp_path: Path,
) -> None:
    """Scores that perfectly correlate with KEV signals should
    pass both thresholds."""
    corpus_dir = tmp_path / "calibration"
    corpus_dir.mkdir()
    _build_synthetic_corpus(corpus_dir, scored=80)
    report = validate_corpus(corpus_dir)
    # Half the CVEs are exploited; top-half by score IS the
    # exploited half (we built it that way), so top-20 should be
    # 100% exploited. ρ between continuous scores + binary
    # outcomes maxes out around 0.87 for a clean split (binary
    # outcomes have heavy mid-rank ties that pull ρ off 1.0
    # even when the ordering is otherwise perfect).
    assert report.top_20_precision == 1.0
    assert report.spearman_rho is not None
    assert report.spearman_rho > 0.8
    assert report.verdict == "validated_v1"


def test_validate_corpus_unverified_when_too_few_samples(
    tmp_path: Path,
) -> None:
    corpus_dir = tmp_path / "calibration"
    corpus_dir.mkdir()
    _build_synthetic_corpus(corpus_dir, scored=10)
    report = validate_corpus(corpus_dir)
    assert report.verdict == "unverified"
    assert any("only 10 scored findings" in n for n in report.notes)


def test_validate_corpus_per_ecosystem_breakdown(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "calibration"
    corpus_dir.mkdir()
    _build_synthetic_corpus(corpus_dir, scored=60)
    report = validate_corpus(corpus_dir)
    # Synthetic corpus has only PyPI — breakdown should reflect that.
    assert "PyPI" in report.by_ecosystem
    assert report.by_ecosystem["PyPI"]["total"] == 60


def test_validate_corpus_provenance_captured(tmp_path: Path) -> None:
    """Reports cite which snapshot date each ground-truth source
    had at validation time."""
    corpus_dir = tmp_path / "calibration"
    corpus_dir.mkdir()
    _build_synthetic_corpus(corpus_dir, scored=60)
    report = validate_corpus(corpus_dir)
    assert "kev_signals.json" in report.corpus_provenance
    assert report.corpus_provenance["kev_signals.json"] == "2024-01-01"


def test_validate_corpus_skips_findings_without_scores(
    tmp_path: Path,
) -> None:
    """Findings missing ``raptor_risk_estimate`` aren't counted
    in the with_score total or in metric calculations."""
    corpus_dir = tmp_path / "calibration"
    corpus_dir.mkdir()
    (corpus_dir / "kev_signals.json").write_text(
        json.dumps({"_source": {"license": "PD", "url": "x"},
                    "signals": {"CVE-2024-X": {"kev": True}}}),
    )
    samples_dir = corpus_dir / "project_samples" / "PyPI"
    samples_dir.mkdir(parents=True)
    (samples_dir / "x.json").write_text(json.dumps({
        "_source": {"license": "MIT", "url": "x"},
        "findings": [
            {"raptor_risk_estimate": 0.7, "advisory": {"osv_id": "CVE-2024-X"}},
            {"raptor_risk_estimate": None, "advisory": {"osv_id": "CVE-2024-Y"}},
            {"advisory": {"osv_id": "CVE-2024-Z"}},  # missing entirely
        ],
    }))
    report = validate_corpus(corpus_dir)
    assert report.findings_total == 3
    assert report.findings_with_score == 1
