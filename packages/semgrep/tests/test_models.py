"""Tests for Semgrep data models and SARIF/JSON parsers."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.semgrep.models import (
    SemgrepFinding,
    SemgrepResult,
    parse_json_output,
    parse_sarif,
)


class TestSemgrepFinding:
    def test_from_sarif_full(self):
        result = {
            "ruleId": "raptor.crypto.weak-hash",
            "message": {"text": "MD5 used for password hashing"},
            "level": "error",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/auth.py"},
                    "region": {
                        "startLine": 42,
                        "startColumn": 5,
                        "endLine": 42,
                        "endColumn": 30,
                    },
                },
            }],
        }
        f = SemgrepFinding.from_sarif_result(result)
        assert f.rule_id == "raptor.crypto.weak-hash"
        assert f.message == "MD5 used for password hashing"
        assert f.level == "error"
        assert f.file == "src/auth.py"
        assert f.line == 42
        assert f.column == 5
        assert f.line_end == 42
        assert f.column_end == 30

    def test_from_sarif_string_message(self):
        result = {"ruleId": "r1", "message": "plain string message"}
        f = SemgrepFinding.from_sarif_result(result)
        assert f.message == "plain string message"

    def test_from_sarif_minimal(self):
        f = SemgrepFinding.from_sarif_result({"ruleId": "r1"})
        assert f.rule_id == "r1"
        assert f.file == ""
        assert f.line == 0
        assert f.level == "warning"

    def test_from_sarif_empty(self):
        f = SemgrepFinding.from_sarif_result({})
        assert f.rule_id == ""

    def test_from_sarif_none(self):
        f = SemgrepFinding.from_sarif_result(None)
        assert f.file == ""

    def test_to_dict(self):
        f = SemgrepFinding(file="a.py", line=1, rule_id="r1", message="m")
        d = f.to_dict()
        assert d["file"] == "a.py"
        assert d["line"] == 1
        assert d["rule_id"] == "r1"


class TestSemgrepResult:
    def test_ok_zero_returncode(self):
        r = SemgrepResult(returncode=0)
        assert r.ok

    def test_ok_one_returncode(self):
        # Semgrep returns 1 when findings exist with --error
        r = SemgrepResult(returncode=1)
        assert r.ok

    def test_ok_false_on_other_returncode(self):
        r = SemgrepResult(returncode=2)
        assert not r.ok

    def test_ok_false_on_errors(self):
        r = SemgrepResult(returncode=0, errors=["something broke"])
        assert not r.ok

    def test_finding_count(self):
        r = SemgrepResult(findings=[
            SemgrepFinding(file="a", line=1),
            SemgrepFinding(file="b", line=2),
        ])
        assert r.finding_count == 2

    def test_to_dict(self):
        r = SemgrepResult(
            name="test",
            config="p/security-audit",
            findings=[SemgrepFinding(file="a.py", line=1)],
            files_examined=["a.py", "b.py"],
            elapsed_ms=100,
        )
        d = r.to_dict()
        assert d["name"] == "test"
        assert d["config"] == "p/security-audit"
        assert len(d["findings"]) == 1
        assert d["files_examined"] == ["a.py", "b.py"]
        assert d["elapsed_ms"] == 100


class TestParseSarif:
    def test_empty_string(self):
        assert parse_sarif("") == []

    def test_whitespace_only(self):
        assert parse_sarif("   \n  ") == []

    def test_invalid_json(self):
        assert parse_sarif("not json") == []

    def test_no_runs(self):
        assert parse_sarif('{"runs": []}') == []

    def test_no_results(self):
        sarif = json.dumps({"runs": [{"results": []}]})
        assert parse_sarif(sarif) == []

    def test_single_finding(self):
        sarif = json.dumps({
            "runs": [{
                "results": [{
                    "ruleId": "r1",
                    "message": {"text": "msg"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.py"},
                            "region": {"startLine": 5},
                        },
                    }],
                }],
            }],
        })
        findings = parse_sarif(sarif)
        assert len(findings) == 1
        assert findings[0].rule_id == "r1"
        assert findings[0].file == "a.py"
        assert findings[0].line == 5

    def test_multiple_runs(self):
        sarif = json.dumps({
            "runs": [
                {"results": [{"ruleId": "r1", "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                          "region": {"startLine": 1}}}
                ]}]},
                {"results": [{"ruleId": "r2", "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "b.py"},
                                          "region": {"startLine": 2}}}
                ]}]},
            ],
        })
        findings = parse_sarif(sarif)
        assert len(findings) == 2
        assert findings[0].rule_id == "r1"
        assert findings[1].rule_id == "r2"


class TestParseJsonOutput:
    def test_empty(self):
        out = parse_json_output("")
        assert out["files_examined"] == []
        assert out["files_failed"] == []
        assert out["semgrep_version"] == ""

    def test_invalid_json(self):
        out = parse_json_output("not json")
        assert out["files_examined"] == []

    def test_paths_scanned(self):
        text = json.dumps({
            "paths": {"scanned": ["c.py", "a.py", "b.py"]},
            "version": "1.79.0",
        })
        out = parse_json_output(text)
        assert out["files_examined"] == ["a.py", "b.py", "c.py"]
        assert out["semgrep_version"] == "1.79.0"

    def test_errors(self):
        text = json.dumps({
            "paths": {"scanned": ["a.py"]},
            "errors": [
                {"path": "broken.py", "message": "parse error"},
                {"path": "", "message": "ignored — no path"},  # filtered out
                {"message": "no path key"},
            ],
        })
        out = parse_json_output(text)
        assert out["files_failed"] == [{"path": "broken.py", "reason": "parse error"}]

    def test_missing_paths_key(self):
        text = json.dumps({"version": "1.0"})
        out = parse_json_output(text)
        assert out["files_examined"] == []
        assert out["semgrep_version"] == "1.0"

    def test_non_dict_root(self):
        out = parse_json_output("[]")
        assert out["files_examined"] == []

    def test_error_level_entries_rendered_into_errors(self):
        # Real payload shape from `semgrep scan --config <invalid rule>`
        # (rc=7): rule-schema entries carry long_msg/short_msg, the
        # summary entry carries message.
        text = json.dumps({
            "errors": [
                {"code": 4, "level": "error",
                 "type": "InvalidRuleSchemaError",
                 "long_msg": "'patterns-oops' is not valid",
                 "short_msg": "Invalid rule schema"},
                {"code": 7, "level": "error", "type": "SemgrepError",
                 "message": "invalid configuration file found "
                            "(1 configs were invalid)"},
            ],
        })
        out = parse_json_output(text)
        assert len(out["errors"]) == 2
        assert "InvalidRuleSchemaError: 'patterns-oops' is not valid" \
            in out["errors"][0]
        assert "SemgrepError: invalid configuration file found" \
            in out["errors"][1]

    def test_warn_level_entries_stay_out_of_errors(self):
        # Per-file parse warnings must not read as engine failure —
        # they land in files_failed (when path-bearing) only.
        text = json.dumps({
            "errors": [
                {"level": "warn", "type": "PartialParsing",
                 "path": "broken.py", "message": "parse skip"},
            ],
        })
        out = parse_json_output(text)
        assert out["errors"] == []
        assert out["files_failed"] == [
            {"path": "broken.py", "reason": "parse skip"},
        ]

    def test_entry_without_level_defaults_to_error(self):
        # Fail-closed default: an errors[] entry with no level field
        # is treated as error-grade.
        text = json.dumps({"errors": [{"message": "boom"}]})
        out = parse_json_output(text)
        assert out["errors"] == ["error: boom"]

    def test_empty_input_has_errors_key(self):
        assert parse_json_output("")["errors"] == []


class TestOutputBudget:
    """Tool output over the byte budget is refused before the parse."""

    _SARIF = json.dumps({
        "runs": [{
            "results": [{
                "ruleId": "r1",
                "message": {"text": "m"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": {"startLine": 1},
                    },
                }],
            }],
        }],
    })

    def test_parse_sarif_under_budget_unchanged(self) -> None:
        findings = parse_sarif(self._SARIF)
        assert [f.rule_id for f in findings] == ["r1"]

    def test_parse_sarif_over_budget_is_refused(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from packages.semgrep import models

        monkeypatch.setattr(
            models, "_MAX_TOOL_OUTPUT_BYTES", len(self._SARIF) - 1,
        )
        assert parse_sarif(self._SARIF) == []

    def test_parse_sarif_non_object_root_is_refused(self) -> None:
        assert parse_sarif("[1, 2, 3]") == []

    def test_parse_json_output_over_budget_is_refused(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from packages.semgrep import models

        payload = json.dumps({
            "version": "1.99.0",
            "paths": {"scanned": ["a.py"]},
            "errors": [],
        })
        out = parse_json_output(payload)
        assert out["files_examined"] == ["a.py"]
        assert out["semgrep_version"] == "1.99.0"

        monkeypatch.setattr(
            models, "_MAX_TOOL_OUTPUT_BYTES", len(payload) - 1,
        )
        out = parse_json_output(payload)
        assert out["files_examined"] == []
        assert out["semgrep_version"] == ""
