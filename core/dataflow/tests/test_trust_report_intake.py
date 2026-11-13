"""Trust measurements cannot report soundness from malformed CSV rows."""

import csv

import pytest

from core.dataflow.trust_report import report


def test_trust_report_refuses_malformed_intake(tmp_path):
    path = tmp_path / "trust.csv"
    header = ["finding_id", "label_verdict", "validator_verdict", "fp_category"]
    tp = {"finding_id": "tp", "label_verdict": "true_positive", "validator_verdict": "uncertain", "fp_category": ""}
    fp = {"finding_id": "fp", "label_verdict": "false_positive", "validator_verdict": "not_exploitable", "fp_category": "missing_sanitizer_model"}

    def write(rows, columns=header):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({column: row.get(column, "") for column in columns})

    for field, values in (("label_verdict", ("", "unknown")),
                          ("validator_verdict", ("", "unknown")),
                          ("fp_category", ("", "unknown"))):
        for value in values:
            write([tp, {**fp, field: value}])
            with pytest.raises(ValueError, match=field):
                report(path)
    write([{**tp, "fp_category": "dead_code"}])
    with pytest.raises(ValueError, match="fp_category"):
        report(path)
    for identity in ("tp", "", " "):
        write([tp, {**fp, "finding_id": identity}])
        with pytest.raises(ValueError, match="finding_id"):
            report(path)
    write([tp], header + ["label_verdict"])
    with pytest.raises(ValueError, match="duplicate.*column"):
        report(path)
    path.write_text(
        "label_verdict,validator_verdict,fp_category\ntrue_positive,uncertain,\"", encoding="utf-8")
    with pytest.raises(csv.Error):
        report(path)
    write([tp, fp])
    measured = report(path)
    assert measured.is_sound and measured.tp == measured.coverage_n == 1
    assert measured.defer_n == 1 and measured.suppressed_total == 1
    narrowed = report(path, trust_categories=frozenset())
    assert narrowed.trust_fp == 0 and narrowed.coverage is None
    write([tp, fp], header + ["future_metadata"])
    assert report(path) == measured
    write([tp, fp], header[1:])
    assert report(path) == measured  # reduced CSV without supplied identities
    write([{**tp, "finding_id": "fixture\rcase"},
           {**tp, "finding_id": "fixture\ncase"},
           {**tp, "finding_id": "fixture\r\ncase"}])
    assert report(path).tp == 3
    write([{**tp, "validator_verdict": "exploitable"}])
    assert report(path).tp == 1  # retain the complete producer verdict domain
    write([tp, {**fp, "fp_category": "dead_code"}])
    outside_trust_scope = report(path)
    assert outside_trust_scope.trust_fp == 0
    assert outside_trust_scope.suppressed_on_fp == 1
