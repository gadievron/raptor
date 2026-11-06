"""Damaged diagnostic fields cannot masquerade as a complete, clean scan."""

import json
import subprocess
from pathlib import Path

import pytest

from core.coverage.record import read_semgrep_outputs
from packages.semgrep import models, runner


def both_consumers(tmp_path, entry):
    payload = {"paths": {"scanned": ["good.py"]}, "errors": [entry], "version": "1.177.0"}
    text = json.dumps(payload)
    path = tmp_path / "metadata.json"
    path.write_text(text)
    return models.parse_json_output(text), read_semgrep_outputs([path])


@pytest.mark.parametrize("path", [True, 7, ["bad.py"], {"path": "bad.py"}, "bad\x00.py"])
def test_invalid_diagnostic_paths_are_visible_without_inventing_failed_filenames(tmp_path, path):
    parsed, coverage = both_consumers(tmp_path, {"path": path, "level": "warn", "message": "partial parse"})
    assert parsed["errors"]
    assert parsed["files_failed"] == coverage.files_failed == []
    assert parsed["files_examined"] == coverage.record["files_examined"] == ["good.py"]
    assert coverage.input_errors == 1


@pytest.mark.parametrize("level", [None, False, [], {}, "unknown", ""])
def test_unusable_severity_is_incomplete_metadata(tmp_path, level):
    parsed, coverage = both_consumers(tmp_path, {"path": "bad.py", "level": level, "message": "partial parse"})
    assert parsed["errors"]
    assert parsed["files_failed"] == coverage.files_failed == [{"path": "bad.py", "reason": "partial parse"}]
    assert coverage.input_errors == 1
    assert not models.SemgrepResult(errors=parsed["errors"]).ok


@pytest.mark.parametrize("level", ["warn", "warning", "info", "debug", "WARN", " info "])
def test_supported_nonfatal_severity_does_not_become_engine_failure(tmp_path, level):
    parsed, coverage = both_consumers(tmp_path, {"path": "bad.py", "level": level, "message": "partial parse"})
    assert not parsed["errors"] and coverage.input_errors == 0
    assert parsed["files_failed"] == coverage.files_failed == [{"path": "bad.py", "reason": "partial parse"}]


@pytest.mark.parametrize("level", ["error", "fatal", "ERROR "])
def test_fatal_diagnostics_are_errors_without_being_malformed_metadata(tmp_path, level):
    parsed, coverage = both_consumers(tmp_path, {"path": "bad.py", "level": level, "message": "tool failed"})
    assert parsed["errors"] and coverage.input_errors == 0


@pytest.mark.parametrize("fields,expected", [
    ({"message": "primary", "long_msg": "detail", "short_msg": "short"}, "primary"),
    ({"message": "", "long_msg": "detail", "short_msg": "short"}, "detail"),
    ({"message": {}, "long_msg": "detail"}, "detail"),
    ({"short_msg": "short"}, "short"),
    ({}, "error"),
    ({"message": "x" * 5000}, "x" * 500),
])
def test_failure_reasons_use_supported_fields_and_stay_bounded(tmp_path, fields, expected):
    parsed, coverage = both_consumers(tmp_path, {"path": "bad.py", "level": "warn", **fields})
    assert parsed["files_failed"] == coverage.files_failed == [{"path": "bad.py", "reason": expected}]
    assert not parsed["errors"] and coverage.input_errors == 0


@pytest.mark.parametrize("entry", [
    {"path": {"path": "bad.py"}, "level": "warn", "message": "parse failure"},
    {"path": "bad.py", "level": None, "long_msg": "unrecognized severity"},
])
def test_runner_retains_findings_but_cannot_claim_success_with_damaged_diagnostics(tmp_path, monkeypatch, entry):
    source = tmp_path / "good.py"
    source.write_text("foo()\n")
    rule = tmp_path / "rule.yml"
    rule.write_text("rules:\n- id: keep\n  languages: [python]\n  pattern: foo()\n"
                    "  message: retained\n  severity: WARNING\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "scope_isolation_available", lambda: True)
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep"}},
              "results": [{"ruleId": "keep", "message": {"text": "retained"},
              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "good.py"},
              "region": {"startLine": 1}}}]}]}]}

    def execute(command, **kwargs):
        output = Path(command[command.index("--json-output") + 1])
        output.write_text(json.dumps({"paths": {"scanned": [str(source)]}, "errors": [entry]}))
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(sarif), stderr="")

    result = runner.run_rule(source, str(rule), subprocess_runner=execute)
    assert result.returncode == 0
    assert result.errors and not result.ok
    assert [(finding.rule_id, finding.file) for finding in result.findings] == [("keep", "good.py")]
    assert result.files_examined == [str(source)]
