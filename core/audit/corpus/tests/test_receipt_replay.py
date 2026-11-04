"""Regression replay checks production policy, not cached verdicts."""

from copy import deepcopy
import json

import pytest

from core.audit.corpus import receipt_replay


def test_saved_cases_are_deterministic_and_keep_recall_gap_visible():
    cases = receipt_replay.load_cases(receipt_replay.DEFAULT_CASES)
    before = deepcopy(cases)
    report = receipt_replay.replay(cases)
    assert report == receipt_replay.replay(cases)
    assert cases == before
    assert report["total"] == report["passed"] == 7
    assert report["label_gaps"] == 1
    assert next(row for row in report["cases"] if row["id"] == "remove_waiter")["label_gap"]
    assert next(row for row in report["cases"] if row["id"] == "WriteProgress")["actual"] == {
        "status": "suspicious", "gate": "receipt_corroborated_hypothesis",
    }


def test_removing_supporting_receipt_fails_saved_expectation():
    case = next(case for case in receipt_replay.load_cases(
        receipt_replay.DEFAULT_CASES,
    ) if case["id"] == "WriteProgress")
    case["receipts"] = []
    case["detector_findings"] = []
    report = receipt_replay.replay([case])
    assert report["passed"] == 0
    assert report["cases"][0]["actual"] == {"status": "clean", "gate": None}


def test_cli_selection_report_and_failure_exit(tmp_path, capsys):
    output = tmp_path / "report.json"
    assert receipt_replay.main(["--case", "__waiter_prio", "--output", str(output)]) == 0
    assert json.loads(output.read_text())["total"] == 1
    assert "1/1 passed" in capsys.readouterr().out
    data = json.loads(receipt_replay.DEFAULT_CASES.read_text())
    data["cases"] = [data["cases"][0]]
    data["cases"][0]["expected"] = {"status": "suspicious", "gate": "wrong"}
    fixtures = tmp_path / "cases.json"
    fixtures.write_text(json.dumps(data))
    assert receipt_replay.main(["--fixtures", str(fixtures)]) == 1


@pytest.mark.parametrize("mutation", ["empty", "duplicate", "schema", "expectation"])
def test_malformed_fixtures_fail_closed(tmp_path, mutation):
    data = json.loads(receipt_replay.DEFAULT_CASES.read_text())
    if mutation == "empty":
        data["cases"] = []
    elif mutation == "duplicate":
        data["cases"].append(data["cases"][0])
    elif mutation == "schema":
        data["schema_version"] = 99
    else:
        data["cases"][0]["expected"] = {"status": "clean", "gate": "wrong"}
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        receipt_replay.load_cases(path)


def test_unknown_case_cannot_silently_pass():
    with pytest.raises(SystemExit) as error:
        receipt_replay.main(["--case", "does-not-exist"])
    assert error.value.code == 2
