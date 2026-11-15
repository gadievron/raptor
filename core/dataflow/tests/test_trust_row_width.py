"""Trust measurements require complete rows under the supplied CSV header."""

import csv

import pytest

from core.dataflow.trust_report import report


def test_trust_row_width_preserves_complete_legacy_and_extended_rows(tmp_path):
    source = tmp_path / "owned.csv"
    header = ["finding_id", "label_verdict", "validator_verdict", "fp_category"]
    rows = [["tp", "true_positive", "uncertain", ""],
            ["fp", "false_positive", "not_exploitable", "missing_sanitizer_model"]]

    def write(columns, values):
        with source.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(columns)
            writer.writerows(values)

    write(header, rows)
    expected = report(source)
    assert expected.total == 2 and expected.is_sound
    assert expected.tp == expected.coverage_n == expected.defer_n == 1
    write(header[1:], [row[1:] for row in rows])
    assert report(source) == expected
    write(header + ["future_metadata"], [row + ["quoted,field\ncontinued"] for row in rows])
    assert report(source) == expected
    source.write_text("", encoding="utf-8")
    assert report(source).total == 0
    for columns, values in (
        (header, [rows[0] + ["unlabelled"], rows[1]]),
        (header, [rows[0][:-1], rows[1]]),
        (header + ["future_metadata"], rows),
    ):
        write(columns, values)
        with pytest.raises(ValueError, match="row width.*CSV line 2"):
            report(source)
