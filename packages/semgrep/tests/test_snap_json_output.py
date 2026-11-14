"""Single-scan JSON conversion preserves findings and incomplete coverage."""

from copy import deepcopy
import json

import pytest

from core.sarif.parser import (
    _extract_cwe_from_rule,
    generate_scan_metrics,
    get_run_execution_diagnostics,
)
from packages.semgrep.models import (
    convert_semgrep_json_to_sarif,
    parse_json_output,
    parse_sarif,
)


def _scan():
    return {
        "version": "1.56.0",
        "errors": [],
        "paths": {"scanned": ["src/unsafe.py", "src/safe.py"]},
        "results": [{
            "check_id": "owned-eval",
            "path": "src/unsafe.py",
            "start": {"line": 2, "col": 9, "offset": 30},
            "end": {"line": 2, "col": 25, "offset": 46},
            "extra": {
                "message": "Use of eval on supplied input",
                "severity": "WARNING",
                "metadata": {"cwe": ["CWE-95"], "category": "security"},
                "lines": "value = eval(user_input)",
                "engine_kind": "OSS",
                "metavars": {"$X": {"abstract_content": "user_input"}},
            },
        }],
    }


def _convert(data, budget=100_000):
    return convert_semgrep_json_to_sarif(json.dumps(data), max_output_bytes=budget)


def test_actual_json_shape_retains_finding_metadata_and_conversion_origin():
    original = _scan()
    before = deepcopy(original)
    converted = _convert(original)
    run = json.loads(converted)["runs"][0]
    errors = []
    finding, = parse_sarif(converted, errors=errors)
    assert not errors and original == before
    assert finding.to_dict() == {
        "file": "src/unsafe.py", "line": 2, "column": 9,
        "line_end": 2, "column_end": 25, "rule_id": "owned-eval",
        "message": "Use of eval on supplied input", "level": "warning",
    }
    assert run["properties"]["raptor.outputOrigin"] == "semgrep-json-conversion"
    assert "converted to SARIF by RAPTOR" in run["tool"]["driver"]["fullName"]
    assert run["tool"]["driver"]["version"] == "1.56.0"
    assert run["properties"]["semgrep.paths"] == original["paths"]
    assert run["results"][0]["properties"]["semgrep.extra"] == original["results"][0]["extra"]
    assert run["results"][0]["properties"]["semgrep.metadata"] == original["results"][0]["extra"]["metadata"]
    assert _extract_cwe_from_rule(run["tool"]["driver"]["rules"][0]) == "CWE-95"
    metadata = parse_json_output(json.dumps(original))
    assert metadata["files_examined"] == ["src/safe.py", "src/unsafe.py"]
    assert not metadata["errors"]


@pytest.mark.parametrize(("severity", "level"), [
    ("ERROR", "error"), ("WARNING", "warning"), ("INFO", "note"),
])
def test_known_severities_remain_explicit_per_result(severity, level):
    data = _scan()
    data["results"][0]["extra"]["severity"] = severity
    finding, = parse_sarif(_convert(data))
    assert finding.level == level


def test_same_rule_different_results_keep_their_own_severity_cwe_and_locations():
    data = _scan()
    second = deepcopy(data["results"][0])
    second["path"] = "src/safe.py"
    second["start"]["line"] = second["end"]["line"] = 7
    second["extra"].update(severity="ERROR", metadata={"cwe": ["CWE-79", "CWE-80"]})
    data["results"].append(second)
    converted = _convert(data)
    run = json.loads(converted)["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2
    assert [_extract_cwe_from_rule(result) for result in run["results"]] == ["CWE-95", "CWE-79"]
    assert run["results"][1]["properties"]["cwe"] == ["CWE-79", "CWE-80"]
    assert [(f.file, f.line, f.level) for f in parse_sarif(converted)] == [
        ("src/unsafe.py", 2, "warning"), ("src/safe.py", 7, "error"),
    ]


def test_non_ascii_names_and_messages_round_trip_without_normalisation():
    data = _scan()
    data["paths"]["scanned"][0] = data["results"][0]["path"] = "src/évaluation.py"
    data["results"][0]["extra"]["message"] = "Entrée contrôlée — résultat"
    finding, = parse_sarif(_convert(data))
    assert finding.file == "src/évaluation.py"
    assert finding.message == "Entrée contrôlée — résultat"


def test_rule_metadata_cannot_forge_raptor_control_properties_or_metrics(tmp_path):
    data = _scan()
    metadata = data["results"][0]["extra"]["metadata"]
    metadata.update({
        "nosemgrep": {"suppressed": True},
        "code_flow_kind": "compiler_path_notes",
        "compiler_path_notes": {"verified": True},
        "raptor.outputOrigin": "native-tool-output",
    })
    converted = _convert(data)
    run = json.loads(converted)["runs"][0]
    result = run["results"][0]
    for properties in (result["properties"], run["tool"]["driver"]["rules"][0]["properties"]):
        assert properties["semgrep.metadata"] == metadata
        assert properties["raptor.outputOrigin"] == "semgrep-json-conversion"
        assert not {"nosemgrep", "code_flow_kind", "compiler_path_notes"} & properties.keys()
    assert result["properties"]["semgrep.extra"]["metadata"] == metadata
    path = tmp_path / "converted.sarif"
    path.write_text(converted)
    metrics = generate_scan_metrics([str(path)])
    assert metrics["total_findings"] == 1
    assert metrics["nosemgrep_suppressed_count"] == 0
    assert not get_run_execution_diagnostics(run)["tool_execution_failures"]


@pytest.mark.parametrize(("key", "value"), [
    ("cwe", True), ("cwe", ["CWE-95", {}]),
    ("cwe_id", {"number": 95}), ("tags", "external/cwe/cwe-95"),
    ("tags", ["security", False]),
])
def test_unreviewed_taxonomy_shapes_are_preserved_only_as_raw_metadata(key, value):
    data = _scan()
    data["results"][0]["extra"]["metadata"] = {key: value}
    run = json.loads(_convert(data))["runs"][0]
    for properties in (run["results"][0]["properties"], run["tool"]["driver"]["rules"][0]["properties"]):
        assert key not in properties
        assert properties["semgrep.metadata"] == {key: value}


def test_reviewed_cwe_alias_and_tags_types_are_promoted():
    data = _scan()
    metadata = {"cwe_id": "CWE-95", "tags": ["security", "external/cwe/cwe-95"]}
    data["results"][0]["extra"]["metadata"] = metadata
    run = json.loads(_convert(data))["runs"][0]
    result = run["results"][0]
    assert result["properties"]["cwe_id"] == "CWE-95"
    assert result["properties"]["tags"] == metadata["tags"]
    assert _extract_cwe_from_rule(result) == "CWE-95"


def test_valid_empty_results_keep_only_actual_reported_coverage():
    data = _scan()
    data["results"] = []
    data["paths"] = {"scanned": []}
    converted = _convert(data)
    errors = []
    assert parse_sarif(converted, errors=errors) == [] and errors == []
    assert json.loads(converted)["runs"][0]["properties"]["semgrep.paths"] == {"scanned": []}


def test_tool_reported_ignored_status_retains_sarif_suppression():
    data = _scan()
    data["results"][0]["extra"]["is_ignored"] = True
    result, = json.loads(_convert(data))["runs"][0]["results"]
    assert result["suppressions"] == [{"kind": "inSource"}]
    assert result["properties"]["semgrep.extra"]["is_ignored"] is True


@pytest.mark.parametrize("level", ["error", "fatal"])
def test_real_failure_diagnostics_cannot_become_clean_converted_sarif(level):
    data = _scan()
    data["errors"] = [{"type": "SemgrepError", "level": level, "message": "scan failed"}]
    converted = _convert(data)
    run = json.loads(converted)["runs"][0]
    assert get_run_execution_diagnostics(run)["tool_execution_failures"] == 1
    errors = []
    assert len(parse_sarif(converted, errors=errors)) == 1
    assert errors == ["SARIF reports 1 unsuccessful invocation(s)"]
    assert parse_json_output(json.dumps(data))["errors"] == ["SemgrepError: scan failed"]


def test_path_diagnostic_and_skipped_paths_keep_partial_analysis_visible():
    data = _scan()
    data["errors"] = [{"type": "ParseError", "level": "warn", "path": "src/safe.py", "message": "partial parse"}]
    data["paths"]["skipped"] = [{"path": "vendor/other.py", "reason": "excluded"}]
    converted = _convert(data)
    run = json.loads(converted)["runs"][0]
    assert get_run_execution_diagnostics(run)["tool_coverage_limitations"] == 2
    assert run["properties"]["semgrep.paths"] == data["paths"]
    errors = []
    parse_sarif(converted, errors=errors)
    assert errors == ["SARIF reports 2 coverage limitation(s)"]
    metadata = parse_json_output(json.dumps(data))
    assert metadata["files_failed"] == [{"path": "src/safe.py", "reason": "partial parse"}]
    assert metadata["skipped_summary"]["total"] == 1


def test_skip_only_scope_is_not_reported_as_complete_or_an_engine_failure():
    data = _scan()
    data["results"] = []
    data["paths"]["skipped"] = [{"path": "vendor/other.py", "reason": "excluded"}]
    converted = _convert(data)
    run = json.loads(converted)["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is True
    note, = run["invocations"][0]["toolExecutionNotifications"]
    assert note["level"] == "warning"
    assert note["properties"]["coverage_limitation"] == "semgrep_skipped_scope"
    assert "intentional exclusions" in note["message"]["text"]
    assert "not an engine failure" in note["message"]["text"]
    diagnostics = get_run_execution_diagnostics(run)
    assert diagnostics["tool_coverage_limitations"] == 1
    assert diagnostics["tool_execution_failures"] == 0
    errors = []
    assert parse_sarif(converted, errors=errors) == []
    assert errors == ["SARIF reports 1 coverage limitation(s)"]


@pytest.mark.parametrize("missing", ["results", "errors", "paths", "version"])
def test_required_output_cannot_disappear_into_a_clean_scan(missing):
    data = _scan()
    del data[missing]
    with pytest.raises(ValueError):
        _convert(data)


@pytest.mark.parametrize(("path", "value"), [
    (("results",), {}),
    (("results",), [False]),
    (("errors",), None),
    (("errors",), ["broken"]),
    (("errors",), [{"level": "unknown"}]),
    (("errors",), [{"level": True}]),
    (("errors",), [{"path": []}]),
    (("paths",), []),
    (("paths", "scanned"), None),
    (("paths", "scanned"), [False]),
    (("paths", "skipped"), {}),
    (("paths", "skipped"), [True]),
    (("paths", "skipped"), [{"path": "a.py", "reason": []}]),
    (("version",), {}),
    (("results", 0, "check_id"), False),
    (("results", 0, "path"), "https://example.invalid/a.py"),
    (("results", 0, "path"), "src/unreported.py"),
    (("results", 0, "path"), "src/bad\x00.py"),
    (("results", 0, "start", "line"), True),
    (("results", 0, "start", "col"), 9.0),
    (("results", 0, "end", "line"), 1),
    (("results", 0, "end", "col"), 8),
    (("results", 0, "extra", "message"), []),
    (("results", 0, "extra", "severity"), "CRITICAL"),
    (("results", 0, "extra", "metadata"), []),
    (("results", 0, "extra", "is_ignored"), "false"),
    (("results", 0, "extra", "dataflow_trace"), {"taint_source": ["unmapped"]}),
])
def test_malformed_or_unmapped_data_fails_explicitly(path, value):
    data = _scan()
    cursor = data
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value
    with pytest.raises(ValueError):
        _convert(data)


@pytest.mark.parametrize("text", ["", "null", "[]", "{", '{"results": NaN}'])
def test_invalid_json_is_refused(text):
    with pytest.raises(ValueError):
        convert_semgrep_json_to_sarif(text, max_output_bytes=100_000)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e10000"])
def test_non_finite_nested_metadata_is_refused_independently_of_encoder(token):
    data = _scan()
    data["results"][0]["extra"]["metadata"]["nested"] = {"value": "NUMBER_TOKEN"}
    text = json.dumps(data).replace('"NUMBER_TOKEN"', token)
    with pytest.raises(ValueError):
        convert_semgrep_json_to_sarif(text, max_output_bytes=100_000)


def test_duplicate_error_arrays_cannot_hide_an_earlier_scan_failure():
    text = ('{"version":"1.56.0","results":[],"paths":{"scanned":[]},'
            '"errors":[{"level":"error","message":"failed"}],"errors":[]}')
    with pytest.raises(ValueError, match="duplicate"):
        convert_semgrep_json_to_sarif(text, max_output_bytes=100_000)


def test_duplicate_result_arrays_cannot_hide_an_earlier_finding():
    text = json.dumps(_scan())[:-1] + ', "results": []}'
    with pytest.raises(ValueError, match="duplicate"):
        convert_semgrep_json_to_sarif(text, max_output_bytes=100_000)


@pytest.mark.parametrize(("old", "replacement"), [
    ('"path": "src/unsafe.py"', '"path": "src/unsafe.py", "path": "src/safe.py"'),
    ('"cwe": ["CWE-95"]', '"cwe": ["CWE-95"], "cwe": []'),
    ('"scanned": ["src/unsafe.py", "src/safe.py"]',
     '"scanned": ["src/unsafe.py", "src/safe.py"], "scanned": []'),
])
def test_duplicate_nested_keys_cannot_rewrite_finding_or_coverage(old, replacement):
    text = json.dumps(_scan())
    assert old in text
    text = text.replace(old, replacement, 1)
    with pytest.raises(ValueError, match="duplicate"):
        convert_semgrep_json_to_sarif(text, max_output_bytes=100_000)


@pytest.mark.parametrize("trace", [None, {}, []])
def test_absent_or_empty_trace_does_not_require_a_flow_mapper(trace):
    data = _scan()
    data["results"][0]["extra"]["dataflow_trace"] = trace
    assert len(parse_sarif(_convert(data))) == 1


@pytest.mark.parametrize("budget", [True, 0, -1, 1.5])
def test_budget_requires_a_positive_integer(budget):
    with pytest.raises(ValueError):
        _convert(_scan(), budget)


def test_input_and_generated_utf8_output_are_both_bounded():
    text = json.dumps(_scan())
    with pytest.raises(ValueError, match="input exceeds"):
        convert_semgrep_json_to_sarif(text, max_output_bytes=len(text) - 1)
    converted = convert_semgrep_json_to_sarif(text, max_output_bytes=100_000)
    exact = len(converted.encode("utf-8"))
    assert convert_semgrep_json_to_sarif(text, max_output_bytes=exact) == converted
    with pytest.raises(ValueError, match="SARIF exceeds"):
        convert_semgrep_json_to_sarif(text, max_output_bytes=exact - 1)


def test_input_unicode_byte_budget_is_not_a_character_budget():
    data = _scan()
    data["results"][0]["extra"]["message"] = "é" * 100
    text = json.dumps(data, ensure_ascii=False)
    with pytest.raises(ValueError, match="input exceeds"):
        convert_semgrep_json_to_sarif(text, max_output_bytes=len(text))
