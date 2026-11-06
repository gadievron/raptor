"""Run-aware SARIF identity and source coordinates in the package runner."""
import json

import pytest

from packages.semgrep.models import SemgrepFinding, parse_sarif_data


def _result(artifact=None, **fields):
    return {'message': {'text': 'retained'}, 'ruleIndex': 0,
            'locations': [{'physicalLocation': {
                'artifactLocation': artifact if artifact is not None else {'index': 0},
                'region': {'startLine': 7, 'startColumn': 2, 'endLine': 8, 'endColumn': 5},
            }}], **fields}


def _run(result, *, prefix='src/', rule='indexed-rule', level='error'):
    return {'tool': {'driver': {'rules': [{'id': rule, 'defaultConfiguration': {'level': level}}]}},
            'originalUriBaseIds': {'ROOT': {'uri': prefix}},
            'artifacts': [{'location': {'uri': 'app.c', 'uriBaseId': 'ROOT'}}],
            'results': [result]}


def test_indexes_and_uri_bases_resolve_within_each_run():
    findings = parse_sarif_data({'runs': [_run(_result()), _run(_result(), prefix='other/', rule='other', level='note')]})
    assert [(f.rule_id, f.level, f.file) for f in findings] == [
        ('indexed-rule', 'error', 'src/app.c'), ('other', 'note', 'other/app.c'),
    ]
    assert [(f.line, f.column, f.line_end, f.column_end) for f in findings] == [(7, 2, 8, 5)] * 2


@pytest.mark.parametrize('uri,expected', [('file:///build/', '/build/app.c'),
                                       ('file://localhost/build/', '/build/app.c')])
def test_local_file_uri_bases_become_local_paths(uri, expected):
    findings = parse_sarif_data({'runs': [_run(_result(), prefix=uri)]})
    assert findings[0].file == expected


@pytest.mark.parametrize('artifact', [
    {'index': True}, {'index': 99}, {'uri': 'file://remote-host/src/app.c'},
    {'uri': 'https://example.test/app.c'}, {'uri': '//remote-host/app.c'},
])
def test_bad_or_remote_artifacts_do_not_rebind_to_a_local_file(artifact):
    errors = []
    findings = parse_sarif_data({'runs': [_run(_result(artifact))]}, errors=errors)
    assert len(findings) == 1 and findings[0].file == ''
    assert findings[0].rule_id == 'indexed-rule'
    assert errors


def test_invalid_rule_index_does_not_borrow_severity_by_id():
    errors = []
    result = _result(ruleIndex=True, ruleId='indexed-rule')
    finding = parse_sarif_data({'runs': [_run(result)]}, errors=errors)[0]
    assert finding.rule_id == 'indexed-rule'
    assert finding.level == 'warning'
    assert errors


def test_qualified_extension_rule_is_resolved_without_driver_metadata_leak():
    run = _run(_result(rule={'index': 0, 'toolComponent': {'index': 0}}))
    run['tool']['extensions'] = [{'name': 'extension', 'rules': [
        {'id': 'extension-rule', 'defaultConfiguration': {'level': 'note'}},
    ]}]
    finding = parse_sarif_data({'runs': [run]})[0]
    assert finding.rule_id == 'extension-rule' and finding.level == 'note'


@pytest.mark.parametrize('value', [True, False, 2.5, -1, float('inf'), float('nan'), 'not-an-integer'])
def test_invalid_optional_coordinates_do_not_drop_finding_or_other_fields(value):
    result = _result({'uri': 'a.c'}, ruleId='kept')
    result['locations'][0]['physicalLocation']['region']['startColumn'] = value
    finding = SemgrepFinding.from_sarif_result(result)
    assert finding.rule_id == 'kept' and finding.file == 'a.c'
    assert (finding.line, finding.column, finding.line_end, finding.column_end) == (7, 0, 8, 5)


def test_reverse_span_is_not_exported_as_a_valid_endpoint():
    result = _result({'uri': 'a.c'}, ruleId='kept')
    result['locations'][0]['physicalLocation']['region']['endLine'] = 2
    finding = SemgrepFinding.from_sarif_result(result)
    assert finding.line == 7 and finding.line_end == finding.column_end == 0


@pytest.mark.parametrize('locations', [None, 1, [None], [{'physicalLocation': []}]])
def test_damaged_optional_location_retains_rule_identity_and_reports_damage(locations):
    errors = []
    result = _result(ruleId='kept', locations=locations)
    findings = parse_sarif_data({'runs': [_run(result)]}, errors=errors)
    assert len(findings) == 1 and findings[0].rule_id == 'kept'
    assert findings[0].file == '' and findings[0].line == 0
    assert errors


def test_logical_only_location_is_not_an_execution_error():
    result = _result(locations=[{'logicalLocations': [{'name': 'f', 'kind': 'function'}]}])
    errors = []
    finding = parse_sarif_data({'runs': [_run(result)]}, errors=errors)[0]
    assert finding.rule_id == 'indexed-rule' and finding.file == ''
    assert not errors


def test_runner_uses_resolved_source_coordinates(tmp_path, monkeypatch):
    from subprocess import CompletedProcess
    from packages.semgrep.runner import run_rule

    monkeypatch.setattr('packages.semgrep.runner.is_available', lambda: True)
    monkeypatch.setattr('packages.semgrep.runner.scope_isolation_available', lambda **kw: True)
    report = json.dumps({'runs': [_run(_result())]})

    def execute(cmd, **kwargs):
        from pathlib import Path
        Path(cmd[cmd.index('--json-output') + 1]).write_text('{}')
        return CompletedProcess(cmd, 0, stdout=report, stderr='')
    result = run_rule(tmp_path, 'rules.yml', subprocess_runner=execute)
    assert result.ok
    assert result.findings[0].file == 'src/app.c'
    assert result.findings[0].rule_id == 'indexed-rule'


@pytest.mark.parametrize('uri', [r'C:\repo\app.c', 'C:/repo/app.c'])
def test_native_windows_drive_paths_remain_usable(uri):
    errors = []
    findings = parse_sarif_data({'runs': [_run(_result({'uri': uri}))]}, errors=errors)
    assert findings[0].file == uri
    assert not errors


@pytest.mark.parametrize('region', [[], {'startLine': True}, {'startLine': float('inf')}])
def test_unusable_primary_region_preserves_identity_but_records_incompleteness(region):
    result = _result()
    result['locations'][0]['physicalLocation']['region'] = region
    errors = []
    finding = parse_sarif_data({'runs': [_run(result)]}, errors=errors)[0]
    assert finding.rule_id == 'indexed-rule' and finding.file == 'src/app.c'
    assert finding.line == 0
    assert errors



def test_repeated_locations_share_run_resolvers_and_empty_runs_do_not_build_them(monkeypatch):
    from core.sarif import parser
    actual_rule, actual_uri = parser.ResultRuleResolver, parser.ArtifactUriResolver
    calls = {'rule': 0, 'uri': 0}

    def rules(run):
        calls['rule'] += 1
        return actual_rule(run)

    def uris(run):
        calls['uri'] += 1
        return actual_uri(run)
    monkeypatch.setattr(parser, 'ResultRuleResolver', rules)
    monkeypatch.setattr(parser, 'ArtifactUriResolver', uris)
    run = _run(_result())
    run['results'] = [_result() for _ in range(1000)]
    empty = _run(_result())
    empty['results'] = []
    findings = parse_sarif_data({'runs': [run, empty]})
    assert len(findings) == 1000
    assert findings[0].file == findings[-1].file == 'src/app.c'
    assert findings[-1].level == 'error'
    assert calls == {'rule': 1, 'uri': 1}
