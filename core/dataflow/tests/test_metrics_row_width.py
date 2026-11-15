"""Corpus CSV rows must have the field count declared by their header."""

import csv

import pytest

from core.dataflow.corpus_metrics import compute
from core.dataflow.run_corpus import CSV_HEADER


def test_metrics_refuse_ragged_rows_without_restricting_headers(tmp_path):
    source = tmp_path / "owned.csv"
    values = {**dict.fromkeys(CSV_HEADER, ""), "finding_id": "owned",
              "label_verdict": "true_positive", "validator_verdict": "exploitable",
              "validator_label": "true_positive", "agreement": "True"}
    full = [values[column] for column in CSV_HEADER]

    def write(header, row):
        with source.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            writer.writerow(row)

    for header, row in ((CSV_HEADER, full),
                        (CSV_HEADER + ["future_metadata"], full + ["owned,quoted\nmetadata"]),
                        (["label_verdict", "validator_label", "fp_category"],
                         ["true_positive", "true_positive", ""])):
        write(header, row)
        result = compute(source)
        assert result.total == result.tp == 1
        assert result.fp == result.fn == result.tn == result.uncertain == 0
    source.write_text("", encoding="utf-8")
    assert compute(source).total == 0
    for header, row in ((CSV_HEADER, full + ["unlabelled field"]),
                        (CSV_HEADER, full[:-1]),
                        (CSV_HEADER + ["future_metadata"], full)):
        write(header, row)
        with pytest.raises(ValueError, match="row width.*CSV line 2"):
            compute(source)
