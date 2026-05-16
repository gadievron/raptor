"""Tests for ``core.dataflow.corpus_metrics``."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

import pytest

from core.dataflow.corpus_metrics import (
    Metrics,
    PIVOT_GATE_THRESHOLD,
    check_pivot_gate,
    compute,
    main,
    render,
)
from core.dataflow.label import (
    FP_DEAD_CODE,
    FP_MISSING_SANITIZER_MODEL,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)
from core.dataflow.run_corpus import CSV_HEADER


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADER)
        w.writeheader()
        for r in rows:
            full = {col: "" for col in CSV_HEADER}
            full.update(r)
            w.writerow(full)


def _row(
    finding_id: str,
    label_verdict: str,
    validator_label: str,
    fp_category: str = "",
) -> dict:
    return {
        "finding_id": finding_id,
        "producer": "codeql",
        "rule_id": "py/x",
        "label_verdict": label_verdict,
        "fp_category": fp_category,
        "validator_verdict": "exploitable" if validator_label == VERDICT_TRUE_POSITIVE else "not_exploitable",
        "validator_label": validator_label,
        "agreement": "agree" if label_verdict == validator_label else "disagree",
    }


def test_compute_counts_tp_fp_tn_fn(tmp_path: Path):
    csv_path = tmp_path / "r.csv"
    _write_csv(
        csv_path,
        [
            _row("a", VERDICT_TRUE_POSITIVE, VERDICT_TRUE_POSITIVE),                       # TP
            _row("b", VERDICT_TRUE_POSITIVE, VERDICT_FALSE_POSITIVE),                      # FN
            _row("c", VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE, FP_DEAD_CODE),        # FP
            _row("d", VERDICT_FALSE_POSITIVE, VERDICT_FALSE_POSITIVE, FP_DEAD_CODE),       # TN
        ],
    )
    m = compute(csv_path)
    assert (m.tp, m.fp, m.tn, m.fn) == (1, 1, 1, 1)
    assert m.total == 4


def test_compute_counts_uncertain_separately(tmp_path: Path):
    csv_path = tmp_path / "r.csv"
    _write_csv(
        csv_path,
        [
            _row("a", VERDICT_TRUE_POSITIVE, "uncertain"),
            _row("b", VERDICT_FALSE_POSITIVE, "uncertain", FP_DEAD_CODE),
        ],
    )
    m = compute(csv_path)
    assert m.uncertain == 2
    assert (m.tp, m.fp, m.tn, m.fn) == (0, 0, 0, 0)


def test_metrics_precision_recall_f1():
    m = Metrics(total=10, tp=4, fp=1, tn=4, fn=1)
    assert m.precision == pytest.approx(4 / 5)
    assert m.recall == pytest.approx(4 / 5)
    assert m.f1 == pytest.approx(0.8)


def test_metrics_undefined_when_no_predictions():
    m = Metrics()
    assert m.precision is None
    assert m.recall is None
    assert m.f1 is None


def test_metrics_undefined_when_only_uncertain():
    m = Metrics(total=3, uncertain=3)
    assert m.precision is None
    assert m.recall is None


def test_compute_collects_fp_categories(tmp_path: Path):
    csv_path = tmp_path / "r.csv"
    _write_csv(
        csv_path,
        [
            _row("a", VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE, FP_MISSING_SANITIZER_MODEL),
            _row("b", VERDICT_FALSE_POSITIVE, VERDICT_FALSE_POSITIVE, FP_MISSING_SANITIZER_MODEL),
            _row("c", VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE, FP_DEAD_CODE),
            _row("d", VERDICT_TRUE_POSITIVE, VERDICT_TRUE_POSITIVE),
        ],
    )
    m = compute(csv_path)
    assert m.fp_categories[FP_MISSING_SANITIZER_MODEL] == 2
    assert m.fp_categories[FP_DEAD_CODE] == 1


def test_check_pivot_gate_passes_above_threshold():
    m = Metrics(fp_categories=Counter({FP_MISSING_SANITIZER_MODEL: 3, FP_DEAD_CODE: 1}))
    ok, msg = check_pivot_gate(m)
    assert ok
    assert "75.0%" in msg or "75%" in msg


def test_check_pivot_gate_fails_below_threshold():
    m = Metrics(fp_categories=Counter({FP_MISSING_SANITIZER_MODEL: 0, FP_DEAD_CODE: 10}))
    ok, msg = check_pivot_gate(m)
    assert not ok
    assert "BELOW" in msg


def test_check_pivot_gate_undefined_when_no_fps():
    m = Metrics()
    ok, msg = check_pivot_gate(m)
    assert not ok
    assert "no FPs" in msg


def test_check_pivot_gate_at_exact_threshold():
    msm = int(PIVOT_GATE_THRESHOLD * 10)  # 1
    other = 10 - msm  # 9
    m = Metrics(fp_categories=Counter({FP_MISSING_SANITIZER_MODEL: msm, FP_DEAD_CODE: other}))
    ok, _ = check_pivot_gate(m)
    assert ok


def test_render_includes_distribution_when_fps_present():
    m = Metrics(
        total=5, tp=3, fp=1, tn=1, fn=0,
        fp_categories=Counter({FP_MISSING_SANITIZER_MODEL: 2}),
    )
    out = render(m)
    assert "Total findings: 5" in out
    assert "Precision:" in out
    assert "Recall:" in out
    assert FP_MISSING_SANITIZER_MODEL in out


def test_render_handles_empty_corpus_gracefully():
    out = render(Metrics())
    assert "Total findings: 0" in out
    assert "undefined" in out


def test_main_returns_2_when_csv_missing(tmp_path: Path):
    rc = main([str(tmp_path / "nope.csv")])
    assert rc == 2


def test_main_with_check_pivot_gate_exits_3_below_threshold(tmp_path: Path):
    csv_path = tmp_path / "r.csv"
    _write_csv(
        csv_path,
        [
            _row("a", VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE, FP_DEAD_CODE),
        ],
    )
    rc = main([str(csv_path), "--check-pivot-gate"])
    assert rc == 3


def test_main_with_check_pivot_gate_exits_0_at_or_above_threshold(tmp_path: Path):
    csv_path = tmp_path / "r.csv"
    _write_csv(
        csv_path,
        [
            _row("a", VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE, FP_MISSING_SANITIZER_MODEL),
        ],
    )
    rc = main([str(csv_path), "--check-pivot-gate"])
    assert rc == 0


def test_main_runs_without_pivot_gate(tmp_path: Path):
    csv_path = tmp_path / "r.csv"
    _write_csv(
        csv_path,
        [_row("a", VERDICT_TRUE_POSITIVE, VERDICT_TRUE_POSITIVE)],
    )
    rc = main([str(csv_path)])
    assert rc == 0
