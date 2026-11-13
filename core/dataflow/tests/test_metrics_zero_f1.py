"""Fully wrong, classifiable predictions have zero F1, not missing F1."""

import csv

from core.dataflow.corpus_metrics import Metrics, compute, render
from core.dataflow.label import FP_DEAD_CODE, VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE
from core.dataflow.run_corpus import CSV_HEADER


def test_wrong_predictions_report_zero_f1(tmp_path):
    path = tmp_path / "results.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_HEADER)
        writer.writeheader()
        for finding_id, label, prediction, category in (
            ("a", VERDICT_TRUE_POSITIVE, VERDICT_FALSE_POSITIVE, ""),
            ("b", VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE, FP_DEAD_CODE),
        ):
            writer.writerow({**dict.fromkeys(CSV_HEADER, ""), "finding_id": finding_id,
                             "label_verdict": label, "validator_label": prediction, "fp_category": category})
    metrics = compute(path)
    assert (metrics.tp, metrics.fp, metrics.fn) == (0, 1, 1)
    assert metrics.precision == metrics.recall == 0
    assert metrics.f1 == 0
    assert "F1:        0.000" in render(metrics)
    assert Metrics().f1 is None
    assert Metrics(total=1, uncertain=1).f1 is None
