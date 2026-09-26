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


class TestSkippedSummary:
    """``paths.skipped`` → bounded per-reason summary."""

    @staticmethod
    def _payload(skipped):
        return json.dumps({
            "version": "1.99.0",
            "paths": {"scanned": [], "skipped": skipped},
            "errors": [],
        })

    def test_basic_grouping(self):
        out = parse_json_output(self._payload([
            {"path": "v/a.js", "reason": "cli_exclude_flags_match"},
            {"path": "big.py", "reason": "exceeded_size_limit"},
            {"path": "v/b.js", "reason": "cli_exclude_flags_match"},
        ]))
        s = out["skipped_summary"]
        assert s["total"] == 3
        assert s["reasons_truncated"] == 0
        assert s["reasons"]["cli_exclude_flags_match"] == {
            "count": 2, "sample": ["v/a.js", "v/b.js"],
        }
        assert s["reasons"]["exceeded_size_limit"]["count"] == 1

    def test_absent_or_empty_skipped_is_empty_summary(self):
        assert parse_json_output(self._payload([]))["skipped_summary"] == {}
        no_key = json.dumps({"paths": {"scanned": []}, "errors": []})
        assert parse_json_output(no_key)["skipped_summary"] == {}
        assert parse_json_output("")["skipped_summary"] == {}

    def test_malformed_entries_ignored_missing_reason_bucketed(self):
        out = parse_json_output(self._payload([
            "bogus", None, 7,
            {"path": "a.py"},          # no reason → "unspecified"
            {"reason": "exceeded_size_limit"},  # no path → counted, no sample
        ]))
        s = out["skipped_summary"]
        assert s["total"] == 2
        assert s["reasons"]["unspecified"] == {"count": 1, "sample": ["a.py"]}
        assert s["reasons"]["exceeded_size_limit"] == {"count": 1, "sample": []}

    # Two-direction coverage for BOTH bounds: the at-limit tests below
    # prove the caps don't over-truncate, the above-limit tests prove
    # they do truncate, and test_cap_values_are_pinned pins the VALUES
    # literally — the behavioural tests derive their fixtures from the
    # constants, so without the literal pin a cap edit would slide
    # through them unnoticed. Changing a cap in either direction must
    # be a conscious edit here (see the models constants for the
    # size/visibility trade-off).

    def test_cap_values_are_pinned(self):
        from packages.semgrep.models import (
            _SKIPPED_PATH_MAXLEN,
            _SKIPPED_REASON_CAP,
            _SKIPPED_REASON_MAXLEN,
            _SKIPPED_SAMPLE_CAP,
        )
        assert _SKIPPED_SAMPLE_CAP == 5
        assert _SKIPPED_REASON_CAP == 12
        assert _SKIPPED_PATH_MAXLEN == 300
        assert _SKIPPED_REASON_MAXLEN == 100

    def test_sample_cap_at_limit_keeps_all(self):
        from packages.semgrep.models import _SKIPPED_SAMPLE_CAP
        entries = [
            {"path": f"p{i:02d}.py", "reason": "r"}
            for i in range(_SKIPPED_SAMPLE_CAP)
        ]
        s = parse_json_output(self._payload(entries))["skipped_summary"]
        assert len(s["reasons"]["r"]["sample"]) == _SKIPPED_SAMPLE_CAP
        assert s["reasons"]["r"]["count"] == _SKIPPED_SAMPLE_CAP

    def test_sample_cap_above_limit_truncates_count_stays_true(self):
        from packages.semgrep.models import _SKIPPED_SAMPLE_CAP
        n = _SKIPPED_SAMPLE_CAP + 7
        entries = [
            {"path": f"p{i:02d}.py", "reason": "r"} for i in range(n)
        ]
        s = parse_json_output(self._payload(entries))["skipped_summary"]
        # Sample bounded, in semgrep output order; total/count uncapped.
        assert s["reasons"]["r"]["sample"] == [
            f"p{i:02d}.py" for i in range(_SKIPPED_SAMPLE_CAP)
        ]
        assert s["reasons"]["r"]["count"] == n
        assert s["total"] == n

    def test_reason_cap_at_limit_keeps_all(self):
        from packages.semgrep.models import _SKIPPED_REASON_CAP
        entries = [
            {"path": "a.py", "reason": f"reason{i:02d}"}
            for i in range(_SKIPPED_REASON_CAP)
        ]
        s = parse_json_output(self._payload(entries))["skipped_summary"]
        assert len(s["reasons"]) == _SKIPPED_REASON_CAP
        assert s["reasons_truncated"] == 0

    def test_reason_cap_above_limit_keeps_highest_counts(self):
        from packages.semgrep.models import _SKIPPED_REASON_CAP
        extra = 4
        entries = []
        # reason00 appears most often, reason01 next, ... — the cap
        # must keep the highest-count reasons and say how many were cut.
        n_reasons = _SKIPPED_REASON_CAP + extra
        for i in range(n_reasons):
            entries.extend(
                {"path": f"f{i}_{j}.py", "reason": f"reason{i:02d}"}
                for j in range(n_reasons - i)
            )
        s = parse_json_output(self._payload(entries))["skipped_summary"]
        assert len(s["reasons"]) == _SKIPPED_REASON_CAP
        assert s["reasons_truncated"] == extra
        assert set(s["reasons"]) == {
            f"reason{i:02d}" for i in range(_SKIPPED_REASON_CAP)
        }
        assert s["total"] == len(entries)

    def test_per_string_length_caps(self):
        from packages.semgrep.models import (
            _SKIPPED_PATH_MAXLEN,
            _SKIPPED_REASON_MAXLEN,
        )
        s = parse_json_output(self._payload([
            {"path": "p" * (_SKIPPED_PATH_MAXLEN * 2),
             "reason": "r" * (_SKIPPED_REASON_MAXLEN * 2)},
        ]))["skipped_summary"]
        (reason,) = s["reasons"]
        assert len(reason) == _SKIPPED_REASON_MAXLEN
        assert len(s["reasons"][reason]["sample"][0]) == _SKIPPED_PATH_MAXLEN

    def test_hostile_bytes_in_paths_escaped(self):
        # Skipped paths are target-chosen file names: terminal escape
        # sequences, OSC titles, BEL and newlines must come out inert.
        hostile = "src/\x1b]0;pwned\x07/a\nb\x1b[31m.py"
        s = parse_json_output(self._payload([
            {"path": hostile, "reason": "cli_exclude_flags_match"},
        ]))["skipped_summary"]
        (sample,) = s["reasons"]["cli_exclude_flags_match"]["sample"]
        assert "\x1b" not in sample
        assert "\x07" not in sample
        assert "\n" not in sample
        assert "\\x1b" in sample and "\\x07" in sample and "\\x0a" in sample

    def test_hostile_bytes_escaped_before_length_cap(self):
        # Escaping happens BEFORE the length cap: a path that fits the
        # cap raw but expands past it escaped must still contain zero
        # raw control bytes in the kept prefix (escape-after-truncate
        # would let hostile bytes ride inside the cap).
        from packages.semgrep.models import _SKIPPED_PATH_MAXLEN
        raw = "\x1b" * (_SKIPPED_PATH_MAXLEN - 1)  # fits raw, 4x escaped
        s = parse_json_output(self._payload([
            {"path": raw, "reason": "r"},
        ]))["skipped_summary"]
        (sample,) = s["reasons"]["r"]["sample"]
        assert len(sample) == _SKIPPED_PATH_MAXLEN
        assert "\x1b" not in sample
        assert sample.startswith("\\x1b")


class TestParseSarifMalformedResults:
    def test_non_dict_results_skipped(self):
        # Non-dict entries in runs[].results previously converted to
        # phantom SemgrepFinding(file='', line=0) records that inflated
        # finding_count downstream.
        import json
        sarif = json.dumps({
            "runs": [{
                "results": [
                    "bogus",
                    None,
                    {
                        "ruleId": "r1",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "a.py"},
                                "region": {"startLine": 3},
                            },
                        }],
                    },
                ],
            }],
        })
        findings = parse_sarif(sarif)
        assert len(findings) == 1
        assert findings[0].file == "a.py"
        assert findings[0].line == 3

    def test_empty_dict_result_skipped(self):
        import json
        sarif = json.dumps({"runs": [{"results": [{}]}]})
        assert parse_sarif(sarif) == []


class TestRegionCoercion:
    def test_bad_field_does_not_discard_rest(self):
        # Per-field coercion: startColumn: null must not wipe out the
        # parseable endLine/endColumn that follow it.
        result = {
            "ruleId": "r1",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {
                        "startLine": "12",
                        "startColumn": None,
                        "endLine": 30,
                        "endColumn": "7",
                    },
                },
            }],
        }
        f = SemgrepFinding.from_sarif_result(result)
        assert f.line == 12
        assert f.column == 0  # unparseable -> 0
        assert f.line_end == 30
        assert f.column_end == 7

    def test_all_fields_valid_unchanged(self):
        # Two-direction: fully valid regions still parse as before.
        result = {
            "ruleId": "r1",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {
                        "startLine": 1, "startColumn": 2,
                        "endLine": 3, "endColumn": 4,
                    },
                },
            }],
        }
        f = SemgrepFinding.from_sarif_result(result)
        assert (f.line, f.column, f.line_end, f.column_end) == (1, 2, 3, 4)


class TestSeverityInheritance:
    """Semgrep's SARIF never sets result.level — severity lives in the
    rules table (defaultConfiguration.level). The parser must inherit
    it; defaulting straight to "warning" flattens every rule-declared
    severity, including HIGH (error) rules."""

    @staticmethod
    def _semgrep_shaped_sarif() -> str:
        def result(rule_id):
            # No "level" key — the shape semgrep 1.172.0 emits.
            return {
                "ruleId": rule_id,
                "message": {"text": "m"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 3},
                    }
                }],
            }

        return json.dumps({
            "runs": [{
                "tool": {"driver": {"name": "semgrep", "rules": [
                    {"id": "high-rule",
                     "defaultConfiguration": {"level": "error"}},
                    {"id": "info-rule",
                     "defaultConfiguration": {"level": "note"}},
                    {"id": "bare-rule"},
                ]}},
                "results": [
                    result("high-rule"),
                    result("info-rule"),
                    result("bare-rule"),
                ],
            }],
        })

    def test_rule_declared_severity_survives(self):
        levels = {f.rule_id: f.level
                  for f in parse_sarif(self._semgrep_shaped_sarif())}
        assert levels["high-rule"] == "error"
        assert levels["info-rule"] == "note"

    def test_rule_without_default_configuration_stays_warning(self):
        levels = {f.rule_id: f.level
                  for f in parse_sarif(self._semgrep_shaped_sarif())}
        assert levels["bare-rule"] == "warning"

    def test_explicit_result_level_wins(self):
        f = SemgrepFinding.from_sarif_result(
            {"ruleId": "high-rule", "level": "note",
             "message": {"text": "m"}},
            rule_levels={"high-rule": "error"},
        )
        assert f.level == "note"
