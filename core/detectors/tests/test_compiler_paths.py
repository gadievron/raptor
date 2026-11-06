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


@pytest.mark.parametrize("invocations", [
    [{"executionSuccessful": False}],
    [{"executionSuccessful": "true"}],
    [{"toolExecutionNotifications": [{"level": "error"}]}],
    [{"toolConfigurationNotifications": [{"level": "error"}]}],
    [{"toolExecutionNotifications": [{"level": "warning", "properties": {"coverage_limitation": "budget"}}]}],
    [{"toolConfigurationNotifications": None}],
    [None],
    {},
])
@pytest.mark.parametrize("with_result", [False, True])
def test_incomplete_gcc_sarif_cannot_establish_diagnostic_census(tmp_path, invocations, with_result):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    from core.detectors.compiler import CompilerDiagnosticError

    report = tmp_path / "compiler.sarif"
    report.write_text(json.dumps({"runs": [{"invocations": invocations,
        "results": [{"message": {"text": "warning"}}] if with_result else []}]}))
    with pytest.raises(CompilerDiagnosticError, match="execution"):
        _parse_gcc_sarif(report)


@pytest.mark.parametrize("invocation", [
    {}, {"executionSuccessful": True},
    {"toolExecutionNotifications": [{"level": "warning"}]},
    {"toolConfigurationNotifications": [{"level": "warning"}]},
    {"toolExecutionNotifications": [{"properties": {"coverage_limitation": "review_candidates"}}]},
])
def test_ordinary_gcc_notifications_do_not_invalidate_analysis(tmp_path, invocation):
    from core.audit.compiler_sweep import _parse_gcc_sarif

    report = tmp_path / "compiler.sarif"
    report.write_text(json.dumps({"runs": [{"invocations": [invocation], "results": []}]}))
    assert _parse_gcc_sarif(report) == []


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


@pytest.mark.parametrize("uri", [
    "file://remote/a.c", "https://example/a.c", "file:///a.c?query", "a\x00.c",
    "file:////remote/a.c", "%2f%2fremote/a.c", "%5c%5cremote/a.c", "a%7f.c", "a\x7f.c",
])
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


@pytest.mark.parametrize('name', [
    'a b.c', 'literal%20.c', 'hash#and?.c', 'snow-λ.c', '%2f%2fremote.c', '%5c%5cremote.c',
])
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
    'file:////remote/a.c', '%2f%2fremote/a.c', '%5c%5cremote/a.c', 'a%7f.c', 'a\x7f.c',
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


@pytest.mark.parametrize('artifact', [
    {'index': 0}, {'uri': 'space%20name%2520.c', 'uriBaseId': 'ROOT'},
])
def test_compiler_primary_locations_resolve_artifact_tables_and_uri_bases(tmp_path, artifact):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    root = tmp_path / 'sources'
    run = {'originalUriBaseIds': {'ROOT': {'uri': root.as_uri() + '/'}},
           'artifacts': [{'location': {'uri': 'space%20name%2520.c', 'uriBaseId': 'ROOT'}}],
           'results': [{'ruleId': '-Wanalyzer-use-after-free', 'level': 'warning',
                        'message': {'text': 'warning'}, 'locations': [{'physicalLocation': {
                            'artifactLocation': artifact, 'region': {'startLine': 3}}}]}]}
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': [run]}))
    diagnostic = _parse_gcc_sarif(report)[0]
    assert diagnostic['file'] == str(root / 'space name%20.c')
    assert diagnostic['id'] == '-Wanalyzer-use-after-free' and diagnostic['line'] == 3


def test_compiler_artifact_resolution_is_run_local(tmp_path):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    runs = [{'artifacts': [{'location': {'uri': name}}], 'results': [{
        'ruleId': '-Wanalyzer-use-after-free', 'level': 'warning', 'message': {'text': 'warning'},
        'locations': [{'physicalLocation': {'artifactLocation': {'index': 0},
                                          'region': {'startLine': 3}}}]}]}
        for name in ('a.c', 'b.c')]
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': runs}))
    assert [row['file'] for row in _parse_gcc_sarif(report)] == ['a.c', 'b.c']


@pytest.mark.parametrize('artifact, bases', [
    ({'index': True}, {}), ({'index': -1}, {}), ({'index': 99}, {}),
    ({'uri': 'a.c', 'uriBaseId': 'loop'}, {'loop': {'uri': 'nested/', 'uriBaseId': 'loop'}}),
])
def test_invalid_compiler_artifact_references_keep_warning_without_inventing_location(tmp_path, artifact, bases):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': [{'originalUriBaseIds': bases, 'results': [{
        'ruleId': '-Wanalyzer-use-after-free', 'level': 'warning', 'message': {'text': 'keep warning'},
        'locations': [{'physicalLocation': {'artifactLocation': artifact,
                                          'region': {'startLine': 3}}}]}]}]}))
    diagnostic = _parse_gcc_sarif(report)[0]
    assert diagnostic['file'] == ''
    assert diagnostic['message'] == 'keep warning'


@pytest.mark.parametrize('base', ['https://example.test/', 'file://remote/source/'])
def test_indexed_nonlocal_compiler_uri_cannot_become_local(tmp_path, base):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    from core.detectors.compiler import CompilerDiagnosticError
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': [{'originalUriBaseIds': {'ROOT': {'uri': base}},
        'artifacts': [{'location': {'uri': 'a.c', 'uriBaseId': 'ROOT'}}], 'results': [{
        'message': {'text': 'warning'}, 'locations': [{'physicalLocation': {
            'artifactLocation': {'index': 0}, 'region': {'startLine': 3}}}]}]}]}))
    with pytest.raises(CompilerDiagnosticError, match='URI'):
        _parse_gcc_sarif(report)


def test_compiler_uri_resolver_is_lazy_and_reused(tmp_path, monkeypatch):
    from core.audit import compiler_sweep as compiler
    original = compiler.ArtifactUriResolver
    builds = []

    class MeasuredResolver(original):
        def __init__(self, run):
            builds.append(run)
            super().__init__(run)

    monkeypatch.setattr(compiler, 'ArtifactUriResolver', MeasuredResolver)
    report = tmp_path / 'compiler.sarif'
    run = {'artifacts': [{'location': {'uri': 'a.c'}}], 'results': [{
        'ruleId': '-Wanalyzer-use-after-free', 'level': 'warning', 'message': {'text': 'warning'},
        'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'a.c'},
                                          'region': {'startLine': 3}}}]} for _ in range(100)]}
    report.write_text(json.dumps({'runs': [run]}))
    assert len(compiler._parse_gcc_sarif(report)) == 100 and not builds
    for row in run['results']:
        row['locations'][0]['physicalLocation']['artifactLocation'] = {'index': 0}
    report.write_text(json.dumps({'runs': [run]}))
    assert {row['file'] for row in compiler._parse_gcc_sarif(report)} == {'a.c'}
    assert len(builds) == 1


@pytest.mark.parametrize('reference', [{'index': 0}, {'uri': 'space%20name%2520.c', 'uriBaseId': 'ROOT'}])
def test_compiler_event_paths_resolve_artifacts_and_bases(tmp_path, reference):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    code_flow = flow()
    event = code_flow['threadFlows'][0]['locations'][0]
    event['location']['physicalLocation']['artifactLocation'] = reference
    root = tmp_path / 'sources'
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': [{
        'originalUriBaseIds': {'ROOT': {'uri': root.as_uri() + '/'}},
        'artifacts': [{'location': {'uri': 'space%20name%2520.c', 'uriBaseId': 'ROOT'}}],
        'results': [{'ruleId': '-Wanalyzer-use-after-free', 'message': {'text': 'warning'},
                     'codeFlows': [code_flow]}]}]}))
    diagnostic = _parse_gcc_sarif(report)[0]
    retained = diagnostic['code_flows'][0]['threadFlows'][0]['locations'][0]
    uri = retained['location']['physicalLocation']['artifactLocation']['uri']
    assert uri == (root / 'space name%20.c').as_uri().removeprefix('file://')
    assert retained['executionOrder'] == 1 and retained['nestingLevel'] == 2
    assert not diagnostic.get('compiler_path_notes')


@pytest.mark.parametrize('reference, base', [
    ({'index': True}, 'file:///local/'),
    ({'index': False}, 'file:///local/'),
    ({'index': 99}, 'file:///local/'),
    ({'uri': 'a.c', 'uriBaseId': 'ROOT'}, 'https://example.test/'),
    ({'uri': 'a.c', 'uriBaseId': 'ROOT'}, 'file://remote/source/'),
    ({'uri': '%2f%2fremote/a.c'}, 'file:///local/'),
    ({'uri': '%5c%5cremote/a.c'}, 'file:///local/'),
    ({'uri': 'a%7f.c'}, 'file:///local/'),
])
def test_bad_compiler_event_reference_drops_whole_path_but_keeps_warning(tmp_path, reference, base):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    code_flow = flow()
    events = code_flow['threadFlows'][0]['locations']
    events.extend([copy.deepcopy(events[0]), copy.deepcopy(events[0])])
    events[1]['location']['physicalLocation']['artifactLocation'] = reference
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': [{
        'originalUriBaseIds': {'ROOT': {'uri': base}},
        'artifacts': [{'location': {'uri': 'a.c'}}, {'location': {'uri': 'b.c'}}],
        'results': [{'ruleId': '-Wanalyzer-use-after-free', 'message': {'text': 'keep warning'},
                     'codeFlows': [code_flow]}]}]}))
    diagnostic = _parse_gcc_sarif(report)[0]
    assert diagnostic['id'] == '-Wanalyzer-use-after-free' and diagnostic['message'] == 'keep warning'
    assert not diagnostic.get('code_flows') and diagnostic['compiler_path_notes']


def test_primary_and_event_locations_share_one_compiler_uri_resolver(tmp_path, monkeypatch):
    from core.audit import compiler_sweep as compiler
    original = compiler.ArtifactUriResolver
    builds = []

    class MeasuredResolver(original):
        def __init__(self, run):
            builds.append(run)
            super().__init__(run)

    monkeypatch.setattr(compiler, 'ArtifactUriResolver', MeasuredResolver)
    code_flow = flow()
    code_flow['threadFlows'][0]['locations'][0]['location']['physicalLocation']['artifactLocation'] = {'index': 0}
    result = {'ruleId': '-Wanalyzer-use-after-free', 'level': 'warning', 'message': {'text': 'warning'},
              'locations': [{'physicalLocation': {'artifactLocation': {'index': 0}, 'region': {'startLine': 3}}}],
              'codeFlows': [code_flow]}
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': [{'artifacts': [{'location': {'uri': 'a.c'}}],
                                          'results': [result] * 100}]}))
    diagnostics = compiler._parse_gcc_sarif(report)
    assert len(builds) == 1 and len(diagnostics) == 100
    assert all(row['file'] == 'a.c' for row in diagnostics)
    # The separate retained-path budget may omit later paths; the first one
    # must survive and all resolutions still use the same run-owned cache.
    assert diagnostics[0]['code_flows']


def test_compiler_cached_hops_combine_with_inline_events_and_artifact_indexes(tmp_path):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    cached = flow()['threadFlows'][0]['locations'][0]
    cached['location']['physicalLocation']['artifactLocation'] = {'index': 0}
    inline = flow(line=5)['threadFlows'][0]['locations'][0]
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': [{
        'artifacts': [{'location': {'uri': 'cached%20name.c'}}],
        'threadFlowLocations': [cached], 'results': [{
            'ruleId': '-Wanalyzer-use-after-free', 'message': {'text': 'warning'},
            'codeFlows': [{'threadFlows': [{'locations': [{'index': 0}, inline, {'index': 0}]}]}],
        }]}]}))
    diagnostic = _parse_gcc_sarif(report)[0]
    events = diagnostic['code_flows'][0]['threadFlows'][0]['locations']
    assert [event['location']['physicalLocation']['artifactLocation']['uri'] for event in events] == [
        'cached%20name.c', 'a.c', 'cached%20name.c']
    assert [event['executionOrder'] for event in events] == [1, 2, 3]
    assert [event['nestingLevel'] for event in events] == [2, 2, 2]
    assert not diagnostic.get('compiler_path_notes')


@pytest.mark.parametrize('reference, cache', [
    ({'index': False}, 'valid'), ({'index': True}, 'valid'),
    ({'index': 9}, 'valid'), ({'index': 0, 'nestingLevel': 1}, 'valid'),
    ({'index': 0}, None), ({'index': 0}, [None]),
    ({'index': 0}, [{'index': 1}]),
])
def test_bad_cached_hop_drops_whole_path_and_preserves_compiler_warning(tmp_path, reference, cache):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    inline = flow()['threadFlows'][0]['locations'][0]
    if cache == 'valid':
        cache = [inline, copy.deepcopy(inline)]
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': [{'threadFlowLocations': cache, 'results': [{
        'ruleId': '-Wanalyzer-use-after-free', 'message': {'text': 'keep warning'},
        'codeFlows': [{'threadFlows': [{'locations': [inline, reference, inline]}]}],
    }]}]}))
    diagnostic = _parse_gcc_sarif(report)[0]
    assert diagnostic['message'] == 'keep warning'
    assert not diagnostic.get('code_flows') and diagnostic['compiler_path_notes']


def test_compiler_cached_hops_are_run_local(tmp_path):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    runs = []
    for name in ('first.c', 'second.c'):
        event = flow(name)['threadFlows'][0]['locations'][0]
        runs.append({'threadFlowLocations': [event], 'results': [{
            'message': {'text': 'warning'},
            'codeFlows': [{'threadFlows': [{'locations': [{'index': 0}]}]}],
        }]})
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': runs}))
    diagnostics = _parse_gcc_sarif(report)
    assert [row['code_flows'][0]['threadFlows'][0]['locations'][0]['location']['physicalLocation'][
        'artifactLocation']['uri'] for row in diagnostics] == ['first.c', 'second.c']


def test_inline_properties_cannot_stand_in_for_unresolved_cached_hop():
    event = flow()['threadFlows'][0]['locations'][0]
    event['index'] = 0
    paths, notes = normalize_paths([{'threadFlows': [{'locations': [event]}]}])
    assert not paths and notes
    event['index'] = -1  # SARIF's explicit inline sentinel, with no cache reference.
    paths, notes = normalize_paths([{'threadFlows': [{'locations': [event]}]}])
    assert paths and not notes
