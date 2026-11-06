"""Damaged diagnostic fields cannot masquerade as a complete, clean scan."""

import json
import subprocess
from pathlib import Path

import pytest

from core.coverage.record import read_semgrep_outputs
from packages.semgrep import models, runner


@pytest.mark.parametrize('state', ['missing', 'empty', 'valid'])
@pytest.mark.parametrize('with_finding', [False, True])
@pytest.mark.parametrize('returncode', [0, 1])
def test_runner_requires_produced_json_metadata_and_retains_recovered_findings(
    tmp_path, monkeypatch, state, with_finding, returncode,
):
    monkeypatch.setattr(runner, 'is_available', lambda: True)
    monkeypatch.setattr(runner, 'scope_isolation_available', lambda: True)
    source = tmp_path / 'good.py'
    source.write_text('foo()\n')
    rule = tmp_path / 'rule.yaml'
    rule.write_text('rules: []\n')
    findings = [{'ruleId': 'keep', 'message': {'text': 'hit'}, 'locations': [{
        'physicalLocation': {'artifactLocation': {'uri': 'good.py'}, 'region': {'startLine': 1}}}]}] if with_finding else []
    sarif = json.dumps({'runs': [{'results': findings}]})

    def execute(command, **kwargs):
        sidecar = Path(command[command.index('--json-output') + 1])
        if state == 'missing':
            sidecar.unlink(missing_ok=True)
        else:
            # A minimal JSON object remains valid for older output shapes.
            sidecar.write_text('{}' if state == 'valid' else '')
        return subprocess.CompletedProcess(command, returncode, stdout=sarif, stderr='')

    result = runner.run_rule(source, str(rule), subprocess_runner=execute)
    assert result.returncode == returncode
    assert len(result.findings) == int(with_finding)
    assert result.ok == (state == 'valid')
    if state != 'valid':
        assert any('metadata missing or empty' in error for error in result.errors)
    else:
        assert result.errors == []


def test_sarif_without_tool_runs_is_not_executed_silence(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, 'is_available', lambda: True)
    monkeypatch.setattr(runner, 'scope_isolation_available', lambda: True)
    source = tmp_path / 'good.py'
    source.write_text('foo()\n')

    def execute(command, **kwargs):
        Path(command[command.index('--json-output') + 1]).write_text('{}')
        return subprocess.CompletedProcess(command, 0, stdout='{"runs": []}', stderr='')

    result = runner.run_rule(source, 'rules.yaml', subprocess_runner=execute)
    assert not result.ok and any('no tool runs' in error for error in result.errors)
    assert models.parse_sarif('{"runs": []}') == []  # Legacy listing callers retain their shape.


def test_process_failure_keeps_its_reason_when_metadata_is_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, 'is_available', lambda: True)
    monkeypatch.setattr(runner, 'scope_isolation_available', lambda: True)

    def execute(command, **kwargs):
        return subprocess.CompletedProcess(command, 7, stdout='{"runs": [{"results": []}]}', stderr='invalid rule')

    result = runner.run_rule(tmp_path, 'rules.yaml', subprocess_runner=execute)
    assert not result.ok
    assert any('code 7' in error and 'invalid rule' in error for error in result.errors)


@pytest.mark.parametrize("channel", ["toolExecutionNotifications", "toolConfigurationNotifications"])
@pytest.mark.parametrize("notification,expected_ok", [
    ({"level": "error"}, False),
    ({"level": "warning"}, True),
    ({"level": "note", "properties": {"coverage_limitation": "query_budget"}}, False),
    ({"level": "note", "properties": {"coverage_limitation": "review_candidates"}}, True),
    (None, False),
])
def test_sarif_invocation_diagnostics_reach_runner(tmp_path, monkeypatch, channel, notification, expected_ok):
    source = tmp_path / "good.py"
    source.write_text("foo()\n")
    rule = tmp_path / "rule.yml"
    rule.write_text("rules: []\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "scope_isolation_available", lambda: True)
    sarif = {"runs": [{"invocations": [{"executionSuccessful": True, channel: [notification]}],
        "results": [{"ruleId": "keep", "message": {"text": "retained"}}]}]}

    def execute(command, **kwargs):
        Path(command[command.index("--json-output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(sarif), stderr="")

    result = runner.run_rule(source, str(rule), subprocess_runner=execute)
    assert result.ok is expected_ok
    assert [finding.rule_id for finding in result.findings] == ["keep"]
    assert bool(result.errors) is not expected_ok


@pytest.mark.parametrize("invocation", [
    {"executionSuccessful": "true"},
    {"toolExecutionNotifications": {}},
    {"toolConfigurationNotifications": None},
])
def test_sarif_damaged_invocation_is_not_successful(invocation):
    errors = []
    findings = models.parse_sarif_data({"runs": [{"invocations": [invocation],
        "results": [{"ruleId": "keep"}]}]}, errors=errors)
    assert [finding.rule_id for finding in findings] == ["keep"]
    assert errors


@pytest.mark.parametrize("unit", ["a", "\x1b", "é\n", "\u202e"])
def test_skip_summary_escapes_only_a_bounded_prefix(monkeypatch, unit):
    reason = unit * 10_000
    path = unit * 20_000
    escape = models.escape_nonprintable
    lengths = []

    def bounded_escape(value):
        lengths.append(len(value))
        assert len(value) <= models._SKIPPED_PATH_MAXLEN
        return escape(value)

    monkeypatch.setattr(models, "escape_nonprintable", bounded_escape)
    summary = models._summarise_skipped([{"reason": reason, "path": path}])
    expected_reason = escape(reason)[:models._SKIPPED_REASON_MAXLEN]
    expected_path = escape(path)[:models._SKIPPED_PATH_MAXLEN]
    assert summary == {
        "total": 1,
        "reasons": {expected_reason: {"count": 1, "sample": [expected_path]}},
        "reasons_truncated": 0,
    }
    assert lengths == [models._SKIPPED_REASON_MAXLEN] * 2 + [models._SKIPPED_PATH_MAXLEN]


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


@pytest.mark.parametrize('field', ['scanned', 'skipped'])
@pytest.mark.parametrize('invalid', [None, False, 7, {}, [], '', 'bad\x00.py'])
def test_invalid_path_rows_are_incomplete_in_both_consumers(tmp_path, field, invalid):
    paths = {'scanned': ['good.py'], 'skipped': [{'path': 'excluded.py', 'reason': 'ignore'}]}
    paths[field].append({'path': invalid} if field == 'skipped' else invalid)
    text = json.dumps({'paths': paths, 'errors': []})
    path = tmp_path / 'metadata.json'
    path.write_text(text)
    parsed = models.parse_json_output(text)
    coverage = read_semgrep_outputs([path])
    assert parsed['errors'] and coverage.input_errors == 1
    assert parsed['files_examined'] == coverage.record['files_examined'] == ['good.py']
    assert coverage.skipped_paths == {'ignore': 1}


@pytest.mark.parametrize('skipped', [None, False, {}, 'bad.py', [None], [7], ['bad.py']])
def test_malformed_skipped_collection_is_not_silent_complete_metadata(tmp_path, skipped):
    text = json.dumps({'paths': {'scanned': ['good.py'], 'skipped': skipped}, 'errors': []})
    path = tmp_path / 'metadata.json'
    path.write_text(text)
    parsed = models.parse_json_output(text)
    coverage = read_semgrep_outputs([path])
    assert parsed['errors'] and coverage.input_errors == 1
    assert parsed['files_examined'] == coverage.record['files_examined'] == ['good.py']


@pytest.mark.parametrize('name', ['space name.py', 'line\nbreak.py', 'snow-λ.py', 'literal%20.py'])
def test_real_filesystem_names_and_optional_skip_fields_remain_supported(tmp_path, name):
    text = json.dumps({'paths': {'scanned': [name], 'skipped': [{'path': name}]}, 'errors': []})
    path = tmp_path / 'metadata.json'
    path.write_text(text)
    parsed = models.parse_json_output(text)
    coverage = read_semgrep_outputs([path])
    assert not parsed['errors'] and coverage.input_errors == 0
    assert parsed['files_examined'] == coverage.record['files_examined'] == [name]
    assert coverage.skipped_paths == {'unspecified': 1}


@pytest.mark.parametrize("damage", ["skipped", "version-type", "version-size"])
def test_malformed_metadata_preserves_runner_findings(tmp_path, monkeypatch, damage):
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "scope_isolation_available", lambda: True)
    source = tmp_path / 'good.py'
    source.write_text('foo()\n')
    rule = tmp_path / 'rule.yaml'
    rule.write_text('rules: []\n')
    sarif = {'runs': [{'results': [{'ruleId': 'keep', 'message': {'text': 'hit'},
        'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'good.py'},
                       'region': {'startLine': 1}}}]}]}]}

    def execute(command, **kwargs):
        output = Path(command[command.index('--json-output') + 1])
        metadata = {'paths': {'scanned': [str(source)]}, 'errors': []}
        if damage == 'skipped':
            metadata['paths']['skipped'] = {}
        else:
            metadata['version'] = {'nested': 'payload'} if damage == 'version-type' else 'x' * 257
        output.write_text(json.dumps(metadata))
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(sarif), stderr='')

    result = runner.run_rule(source, str(rule), subprocess_runner=execute)
    assert result.returncode == 0 and result.errors and not result.ok
    assert [(finding.rule_id, finding.file) for finding in result.findings] == [('keep', 'good.py')]
    assert result.files_examined == [str(source)]


@pytest.mark.parametrize('kind', ['IncompatibleRule', ['IncompatibleRule', {'rule_id': 'new-rule'}]])
@pytest.mark.parametrize('path', [None, 'rules/custom.yml'])
def test_incompatible_rules_limit_coverage_without_inventing_failed_source_files(tmp_path, kind, path):
    notice = {'type': kind, 'level': 'info', 'message': 'Rule requires a newer Semgrep'}
    if path is not None:
        notice['path'] = path
    parsed, coverage = both_consumers(tmp_path, notice)
    assert not parsed['errors'] and coverage.input_errors == 0
    assert len(parsed['skipped_rules']) == coverage.skipped_rules == 1
    assert parsed['files_failed'] == coverage.files_failed == []
    assert coverage.record['files_examined'] == ['good.py']
    assert models.SemgrepResult(skipped_rules=parsed['skipped_rules']).ok


@pytest.mark.parametrize('version', [False, 123, [], {'nested': 'payload'}, 'x' * 257, '1.2.3\x00', '1.2.3\n'])
def test_invalid_version_metadata_is_bounded_and_visible_in_both_consumers(tmp_path, version):
    text = json.dumps({'paths': {'scanned': ['good.py']}, 'version': version})
    path = tmp_path / 'metadata.json'
    path.write_text(text)
    parsed = models.parse_json_output(text)
    coverage = read_semgrep_outputs([path])
    assert parsed['semgrep_version'] == '' and parsed['errors']
    assert coverage.input_errors == 1 and 'version' not in coverage.record
    assert parsed['files_examined'] == coverage.record['files_examined'] == ['good.py']


@pytest.mark.parametrize('version', [None, '', '1.177.0', '1.177.0-rc.1+vendor', 'x' * 256])
def test_supported_version_labels_and_unknown_values_remain_compatible(tmp_path, version):
    text = json.dumps({'paths': {'scanned': ['good.py']}, 'version': version})
    path = tmp_path / 'metadata.json'
    path.write_text(text)
    parsed = models.parse_json_output(text)
    coverage = read_semgrep_outputs([path])
    assert parsed['semgrep_version'] == coverage.record.get('version', '') == (version or '')
    assert not parsed['errors'] and coverage.input_errors == 0


def test_structured_diagnostic_type_never_formats_variant_payload():
    class UnrenderedPayload(dict):
        def __repr__(self):
            pytest.fail('diagnostic summaries must not format variant metadata')

    entry = {'type': ['IncompatibleRule', UnrenderedPayload(rule_id='payload')],
             'message': 'Rule requires a newer Semgrep'}
    assert models._render_error(entry) == 'IncompatibleRule: Rule requires a newer Semgrep'
    entry['type'] = UnrenderedPayload()
    assert models._render_error(entry) == 'error: Rule requires a newer Semgrep'


def test_diagnostic_rendering_is_bounded_and_keeps_actionable_message():
    text = models._render_error({'type': 'x' * 100_000, 'message': 'actionable detail'})
    assert len(text) <= 500 and text.endswith(': actionable detail')
    text = models._render_error({'type': 'bad\x1b[2J', 'message': 'line one\nline two\x07'})
    assert '\x1b' not in text and '\n' not in text and '\x07' not in text
    assert 'line one' in text and 'line two' in text
