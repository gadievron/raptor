"""An identified finding contributes at most one corpus measurement row."""

import csv

import pytest

from core.dataflow.corpus_metrics import compute


def test_metrics_refuse_repeated_or_empty_supplied_ids(tmp_path):
    path = tmp_path / "results.csv"

    def write(ids):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["finding_id", "label_verdict", "validator_label", "fp_category"])
            for identity in ids:
                writer.writerow([identity, "true_positive", "true_positive", ""])

    write(["same", "same"])
    with pytest.raises(ValueError, match="duplicate.*finding_id"):
        compute(path)
    for identity in ("", " "):
        write([identity])
        with pytest.raises(ValueError, match="finding_id"):
            compute(path)
    write(["one", "two"])
    assert compute(path).tp == 2
    path.write_text("label_verdict,validator_label,fp_category\ntrue_positive,true_positive,\n", encoding="utf-8")
    assert compute(path).tp == 1


def test_metrics_preserve_quoted_identity_line_endings(tmp_path):
    path = tmp_path / "results.csv"

    def write(ids):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["finding_id", "label_verdict", "validator_label", "fp_category"])
            for identity in ids:
                writer.writerow([identity, "true_positive", "true_positive", ""])

    write(["fixture\rcase", "fixture\ncase", "fixture\r\ncase"])
    metrics = compute(path)
    assert metrics.total == metrics.tp == 3
    write(["fixture\rcase", "fixture\rcase"])
    with pytest.raises(ValueError, match="duplicate.*finding_id"):
        compute(path)
