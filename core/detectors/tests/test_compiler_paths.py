"""Compiler paths retain context without inventing edges or taint evidence."""
import copy
import json

import pytest

from core.detectors.compiler_paths import (
    MAX_EVENTS, MAX_PATHS, PATH_KIND, PathBudget, attach_paths, json_paths, normalize_paths,
)


def flow(uri="a.c", line=3, message="following the error branch"):
    return {"threadFlows": [{"locations": [{
        "location": {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}},
                     "logicalLocations": [{"name": "caller"}], "message": {"text": message}},
        "nestingLevel": 2,
    }]}]}


def test_both_gcc_formats_retain_same_event_context():
    old, notes = json_paths([{"location": {"file": "a.c", "line": 3},
                             "function": "caller", "depth": 2, "description": "following the error branch"}])
    modern, modern_notes = normalize_paths([flow()])
    assert old == modern and not notes and not modern_notes


@pytest.mark.parametrize("change", [
    lambda e: e["location"]["physicalLocation"]["region"].update(startLine=True),
    lambda e: e["location"]["physicalLocation"]["region"].update(startLine="3"),
    lambda e: e.update(nestingLevel=-1),
    lambda e: e["location"].update(message={"text": "x" * 2049}),
    lambda e: e["location"].update(logicalLocations=["bad"]),
])
def test_bad_event_omits_whole_path_without_joining_across_gap(change):
    raw = flow()
    events = raw["threadFlows"][0]["locations"]
    events.extend([copy.deepcopy(events[0]), copy.deepcopy(events[0])])
    change(events[1])
    paths, notes = normalize_paths([raw])
    assert not paths and notes


def test_foreign_path_omitted_and_local_file_uri_resolved(tmp_path):
    local = tmp_path / "a.c"
    seen = []
    def locate(uri):
        seen.append(uri)
        return "a.c" if uri == str(local) else None
    paths, notes = normalize_paths([flow(local.as_uri()), flow("/outside/a.c")], locate)
    assert len(paths) == 1 and notes and seen[0] == str(local)
    assert paths[0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"]["artifactLocation"]["uri"] == "a.c"


@pytest.mark.parametrize("uri", ["file://remote/a.c", "https://example/a.c", "file:///a.c?query", "a\x00.c"])
def test_ambiguous_or_nonlocal_uri_cannot_be_reinterpreted_as_local(uri):
    paths, notes = normalize_paths([flow(uri)], lambda value: "a.c")
    assert not paths and notes


def test_caps_and_memory_budget_are_explicit_and_keep_diagnostics():
    raw = flow()
    raw["threadFlows"][0]["locations"] *= MAX_EVENTS + 1
    assert normalize_paths([raw])[1]
    paths, notes = normalize_paths([flow(line=i + 1) for i in range(MAX_PATHS + 1)])
    assert len(paths) == MAX_PATHS and notes
    diagnostic = {"message": "original warning"}
    PathBudget(1).retain(diagnostic, paths, [])
    assert diagnostic["message"] == "original warning" and not diagnostic.get("code_flows")
    assert diagnostic["compiler_path_notes"]


def test_merge_retains_distinct_paths_and_escapes_controls():
    record = {}
    attach_paths(record, {"code_flows": [flow(message="bad\x1b[2J")]})
    attach_paths(record, {"code_flows": [flow(line=9)]})
    attach_paths(record, record)
    assert len(record["code_flows"]) == 2
    assert "\x1b" not in str(record)


@pytest.mark.parametrize("tagged", [False, True])
def test_control_flow_never_enters_taint_pipeline(tmp_path, tagged):
    from core.sarif.parser import parse_sarif_findings
    path = tmp_path / "compiler.sarif"
    raw = {"ruleId": "-Wanalyzer-null-dereference", "message": {"text": "possible null"},
           "locations": [flow()["threadFlows"][0]["locations"][0]["location"]],
           "codeFlows": [flow()], "properties": {"code_flow_kind": PATH_KIND} if tagged else {}}
    events = raw["codeFlows"][0]["threadFlows"][0]["locations"]
    events.append(copy.deepcopy(events[0]))
    events[1]["location"]["physicalLocation"]["region"]["startLine"] = 5
    path.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "compiler"}}, "results": [raw]}]}))
    finding = parse_sarif_findings(path)[0]
    assert finding["has_dataflow"] is False and finding["dataflow_path"] is None
    assert finding["compiler_evidence"]["code_flows"]


def test_json_filesystem_names_and_sarif_uris_round_trip_once():
    paths, notes = json_paths([{"location": {"file": "a%2fb c.c", "line": 3}, "description": "event"}])
    assert not notes
    assert paths[0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"]["artifactLocation"]["uri"] == "a%252fb%20c.c"
    again, notes = normalize_paths(paths)
    assert again == paths and not notes


@pytest.mark.parametrize('name', ['a b.c', 'literal%20.c', 'hash#and?.c', 'snow-λ.c'])
def test_primary_locations_share_filesystem_identity_across_gcc_formats(tmp_path, name):
    from core.audit.compiler_sweep import _parse_gcc_json, _parse_gcc_sarif

    source = tmp_path / name
    result = {'ruleId': '-Wanalyzer-use-after-free', 'message': {'text': 'warning'},
              'locations': [flow(source.as_uri())['threadFlows'][0]['locations'][0]['location']]}
    path = tmp_path / 'gcc.sarif'
    path.write_text(json.dumps({'runs': [{'results': [result]}]}))
    modern = _parse_gcc_sarif(path)
    legacy = _parse_gcc_json(json.dumps([{
        'message': 'warning', 'locations': [{'caret': {'file': str(source), 'line': 3}}],
    }]))
    assert modern[0]['file'] == legacy[0]['file'] == str(source)


@pytest.mark.parametrize('uri', [
    'https://example/a.c', 'file://remote/a.c', 'file:///a.c?x',
    'file:///a.c#x', 'a%00.c', 'a%ff.c', 'a\n.c', ' a.c',
])
def test_bad_primary_uri_is_not_compiler_silence(tmp_path, uri):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    from core.detectors.compiler import CompilerDiagnosticError

    result = {'message': {'text': 'warning'},
              'locations': [flow(uri)['threadFlows'][0]['locations'][0]['location']]}
    path = tmp_path / 'gcc.sarif'
    path.write_text(json.dumps({'runs': [{'results': [result]}]}))
    with pytest.raises(CompilerDiagnosticError, match='diagnostic URI'):
        _parse_gcc_sarif(path)
    assert normalize_paths([flow(uri)])[1]
