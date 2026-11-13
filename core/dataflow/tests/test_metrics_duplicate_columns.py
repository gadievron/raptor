"""Conflicting CSV columns cannot silently overwrite corpus labels."""

import csv

import pytest

from core.dataflow.corpus_metrics import compute
from core.dataflow.label import VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE
from core.dataflow.run_corpus import CSV_HEADER


def test_metrics_reject_duplicate_column_names(tmp_path):
    path = tmp_path / "results.csv"
    valid = {**dict.fromkeys(CSV_HEADER, ""), "finding_id": "fixture",
             "label_verdict": VERDICT_TRUE_POSITIVE, "validator_label": VERDICT_TRUE_POSITIVE}

    def write(header, values):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            writer.writerow(values)

    write(CSV_HEADER, [valid[column] for column in CSV_HEADER])
    assert compute(path).tp == 1
    write(CSV_HEADER + ["future_metadata"], [valid[column] for column in CSV_HEADER] + ["fixture"])
    assert compute(path).tp == 1
    path.write_text("", encoding="utf-8")
    assert compute(path).total == 0
    overwritten = {**valid, "label_verdict": VERDICT_FALSE_POSITIVE}
    write(CSV_HEADER + ["label_verdict"], [overwritten[column] for column in CSV_HEADER] + [VERDICT_TRUE_POSITIVE])
    with pytest.raises(ValueError, match="duplicate.*column"):
        compute(path)
