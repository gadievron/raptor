"""Missing categories cannot shrink the pivot-gate denominator."""

import csv

import pytest

from core.dataflow.corpus_metrics import check_pivot_gate, compute
from core.dataflow.label import FP_DEAD_CODE, FP_MISSING_SANITIZER_MODEL, VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE
from core.dataflow.run_corpus import CSV_HEADER


def _write(path, categories, label=VERDICT_FALSE_POSITIVE):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_HEADER)
        writer.writeheader()
        for index, category in enumerate(categories):
            writer.writerow({**dict.fromkeys(CSV_HEADER, ""), "finding_id": f"fixture-{index}", "label_verdict": label,
                             "validator_verdict": "exploitable", "validator_label": VERDICT_TRUE_POSITIVE, "fp_category": category})


def test_metrics_category_domains_preserve_pivot_denominator(tmp_path):
    path = tmp_path / "results.csv"
    _write(path, [FP_MISSING_SANITIZER_MODEL] + [FP_DEAD_CODE] * 99)
    assert not check_pivot_gate(compute(path))[0]
    _write(path, [FP_MISSING_SANITIZER_MODEL] * 10 + [FP_DEAD_CODE] * 90)
    assert check_pivot_gate(compute(path))[0]
    _write(path, [FP_MISSING_SANITIZER_MODEL] + [""] * 99)
    with pytest.raises(ValueError, match="fp_category"):
        compute(path)
    _write(path, ["unknown-category"])
    with pytest.raises(ValueError, match="fp_category"):
        compute(path)
    _write(path, [FP_DEAD_CODE], label=VERDICT_TRUE_POSITIVE)
    with pytest.raises(ValueError, match="fp_category"):
        compute(path)
