"""One corpus row cannot describe contradictory validator outcomes."""

import csv

import pytest

from core.dataflow.corpus_metrics import compute
from core.dataflow.run_corpus import CSV_HEADER
from core.dataflow.trust_report import report


def test_csv_raw_and_normalized_verdicts_must_agree(tmp_path):
    path = tmp_path / "results.csv"

    def write(raw, normalized, columns=CSV_HEADER):
        row = {**dict.fromkeys(CSV_HEADER, ""), "finding_id": "fixture",
               "label_verdict": "true_positive", "validator_verdict": raw,
               "validator_label": normalized}
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerow({column: row[column] for column in columns})

    pairs = [("exploitable", "true_positive"), ("not_exploitable", "false_positive"),
             ("uncertain", "uncertain")]
    for raw, expected in pairs:
        for normalized in ("true_positive", "false_positive", "uncertain"):
            write(raw, normalized)
            if normalized != expected:
                for reader in (compute, report):
                    with pytest.raises(ValueError, match="validator_label"):
                        reader(path)
            else:
                metrics, trust = compute(path), report(path)
                assert metrics.total == trust.total == 1
                assert (metrics.tp, metrics.fn, metrics.uncertain) == (
                    int(raw == "exploitable"), int(raw == "not_exploitable"), int(raw == "uncertain"))
                assert trust.false_suppression_n == int(raw == "not_exploitable")
    for raw in ("", "unknown"):
        write(raw, "true_positive")
        for reader in (compute, report):
            with pytest.raises(ValueError, match="validator_verdict"):
                reader(path)
    write("", "true_positive", [column for column in CSV_HEADER if column != "validator_verdict"])
    assert compute(path).tp == 1
    write("exploitable", "", [column for column in CSV_HEADER if column != "validator_label"])
    assert report(path).tp == 1
