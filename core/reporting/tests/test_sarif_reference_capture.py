"""Reporting capture preserves the shared SARIF resolver's reference contract."""
import json

import pytest

from core.reporting.adapters import context_from_sarif
from core.sarif.parser import parse_sarif_document


def _captured_run(result):
    return {"tool": {"driver": {"name": "fixture", "rules": [{"id": "same",
            "defaultConfiguration": {"level": "error"}, "properties": {"cwe": "CWE-79"}}]}},
            "artifacts": [{"location": {"uri": "captured-first.c"}},
                          {"location": {"uri": "captured-second.c"}}], "results": [result]}


def _compare_capture(tmp_path, run):
    payload = {"version": "2.1.0", "runs": [run]}
    source = tmp_path / "captured.sarif"
    source.write_text(json.dumps(payload))
    original = source.read_bytes()
    direct = parse_sarif_document(payload, include_occurrences=True)[0]
    captured = context_from_sarif([source], run_id="captured").findings[0]
    assert source.read_bytes() == original
    return direct, captured


def test_indexed_subrule_identity_and_metadata_survive_reporting_capture(tmp_path):
    direct, captured = _compare_capture(tmp_path, _captured_run({
        "rule": {"id": "same/subrule", "index": 0}, "message": {"text": "captured"}}))
    assert direct["rule_id"] == "same/subrule"
    assert captured["rule_id"] == direct["rule_id"]
    assert captured["scanner_level"] == direct["level"] == "error"
    assert captured["cwe_id"] == direct["cwe_id"]


def test_boolean_artifact_index_cannot_borrow_a_location_during_capture(tmp_path):
    direct, captured = _compare_capture(tmp_path, _captured_run({"ruleIndex": 0,
        "message": {"text": "captured"}, "locations": [{"physicalLocation": {
            "artifactLocation": {"index": False}}}]}))
    assert captured["file"] == (direct["file"] or "")
    assert "captured-first.c" not in captured["file"]


@pytest.mark.parametrize("location", [
    {"index": True}, {"index": 0}, {"index": 1}, {"index": -1},
    {"index": "0"}, {"uri": "explicit.c", "index": True},
])
def test_artifact_references_keep_shared_parser_precedence(tmp_path, location):
    direct, captured = _compare_capture(tmp_path, _captured_run({"ruleIndex": 0,
        "message": {"text": "captured"}, "locations": [{"physicalLocation": {
            "artifactLocation": location}}]}))
    assert captured["file"] == (direct["file"] or "")
    assert captured["rule_id"] == direct["rule_id"] == "same"
    assert captured["scanner_level"] == direct["level"] == "error"


def test_extension_subrule_capture_keeps_component_identity(tmp_path):
    run = _captured_run({"rule": {"id": "same/subrule", "index": 0,
        "toolComponent": {"index": 0}}, "message": {"text": "captured"}})
    extension = run["tool"]["driver"]
    run["tool"] = {"driver": {"name": "driver", "rules": [{"id": "unrelated"}]},
                   "extensions": [extension]}
    direct, captured = _compare_capture(tmp_path, run)
    assert captured["rule_id"] == direct["rule_id"] == "same/subrule"
    assert captured["scanner_level"] == direct["level"] == "error"
    assert captured["cwe_id"] == direct["cwe_id"]
