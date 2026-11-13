"""Metrics refuse labels outside the corpus outcome vocabulary."""

import csv

import pytest

from core.dataflow.corpus_metrics import compute
from core.dataflow.label import FP_DEAD_CODE, VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE
from core.dataflow.run_corpus import CSV_HEADER


def test_metrics_label_domains(tmp_path):
    path = tmp_path / "results.csv"

    def write(rows):
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_HEADER)
            writer.writeheader()
            for index, row in enumerate(rows):
                raw = {"true_positive": "exploitable", "false_positive": "not_exploitable", "uncertain": "uncertain"}.get(row.get("validator_label"), "uncertain")
                writer.writerow({**dict.fromkeys(CSV_HEADER, ""), "finding_id": f"fixture-{index}", "validator_verdict": raw, **row})

    valid = [
        {"label_verdict": label, "validator_label": predicted,
         "fp_category": FP_DEAD_CODE if label == VERDICT_FALSE_POSITIVE else ""}
        for label in (VERDICT_TRUE_POSITIVE, VERDICT_FALSE_POSITIVE)
        for predicted in (VERDICT_TRUE_POSITIVE, VERDICT_FALSE_POSITIVE, "uncertain")
    ]
    write(valid)
    metrics = compute(path)
    assert (metrics.total, metrics.tp, metrics.fp, metrics.tn, metrics.fn, metrics.uncertain) == (6, 1, 1, 1, 1, 2)
    for field in ("label_verdict", "validator_label"):
        for value in ("", "typo", "exploitable"):
            write([{**valid[0], field: value}])
            with pytest.raises(ValueError, match=field):
                compute(path)
