"""Coverage facts from all CodeQL reports, without retaining raw reports."""
import gc
import json
import weakref

from core.coverage import record as coverage


def _report(root, name, file, rule, *, version='2.16.0'):
    return {'runs': [{'originalUriBaseIds': {'ROOT': {'uri': root.as_uri() + '/'}},
        'tool': {'driver': {'name': 'CodeQL', 'version': version, 'rules': [{'id': ''}]},
                 'extensions': [{'name': name, 'version': '1', 'rules': [{'id': rule}]}]},
        'artifacts': [None, {'location': {'uri': file, 'uriBaseId': 'ROOT'}}],
        'invocations': [{'toolExecutionNotifications': [{'level': 'warning',
            'message': {'text': 'partial extraction'}, 'locations': [
                {'physicalLocation': {'artifactLocation': {'index': 1}}},
                {'physicalLocation': {'artifactLocation': {'index': True}}},
            ]}]}],
    }]}


def test_language_reports_union_files_packs_rules_and_indexed_failures(tmp_path, monkeypatch):
    paths = []
    for name, file, rule in [('cpp', 'src/a%20b.c', 'cpp/example'), ('java', 'src/App.java', 'java/example')]:
        path = tmp_path / f'{name}.sarif'
        path.write_text(json.dumps(_report(tmp_path, name, file, rule)))
        paths.append(path)
    reads = []
    load = coverage.load_json

    def track(path, **kwargs):
        reads.append(path)
        assert kwargs['max_bytes'] == coverage.RUN_ARTIFACT_MAX_BYTES
        return load(path, **kwargs)
    monkeypatch.setattr(coverage, 'load_json', track)
    result = coverage.build_from_codeql(paths[0], extra_sarif_paths=[paths[0], paths[1]], repo_root=tmp_path)
    assert reads == paths
    assert result['files_examined'] == ['src/App.java', 'src/a b.c']
    assert result['packs'] == ['cpp@1', 'java@1']
    assert result['rules_applied'] == ['cpp/example', 'java/example']
    assert result['files_failed'] == [
        {'path': 'src/a b.c', 'reason': 'partial extraction'},
        {'path': 'src/App.java', 'reason': 'partial extraction'},
    ]
    assert result['version'] == '2.16.0'


def test_failure_notifications_keep_every_affected_local_file(tmp_path):
    data = _report(tmp_path, 'cpp', 'a.c', 'cpp/example')
    run = data['runs'][0]
    run['artifacts'].append({'location': {'uri': 'b.c', 'uriBaseId': 'ROOT'}})
    locations = run['invocations'][0]['toolExecutionNotifications'][0]['locations']
    locations.extend([{'physicalLocation': {'artifactLocation': {'index': 2}}}] * 2)
    accumulator = coverage.CodeQLCoverageAccumulator(tmp_path)
    accumulator.add_report(data)
    assert accumulator.build_record()['files_failed'] == [
        {'path': 'a.c', 'reason': 'partial extraction'}, {'path': 'b.c', 'reason': 'partial extraction'},
    ]


def test_remote_and_outside_root_references_cannot_borrow_a_local_basename(tmp_path):
    data = _report(tmp_path, 'cpp', 'good.c', 'cpp/example')
    data['runs'][0]['artifacts'].extend({'location': {'uri': uri}} for uri in [
        'file://remote-host/good.c', 'https://example.test/good.c', '//remote-host/good.c',
        tmp_path.parent.as_uri() + '/outside.c', '../outside.c', '%2e%2e/outside.c',
        'bad%00name.c',
    ])
    accumulator = coverage.CodeQLCoverageAccumulator(tmp_path)
    accumulator.add_report(data)
    assert accumulator.build_record()['files_examined'] == ['good.c']


def test_decode_once_preserves_literal_percent_and_file_prefix_paths(tmp_path):
    data = {'runs': [{'artifacts': [{'location': {'uri': uri}}]}
                     for uri in ['literal%2520.c', 'file%3A%2F%2Ftoken.c']]}
    accumulator = coverage.CodeQLCoverageAccumulator(tmp_path)
    accumulator.add_report(data)
    assert accumulator.build_record()['files_examined'] == ['file:/token.c', 'literal%20.c']


def test_unreadable_language_report_does_not_erase_valid_coverage(tmp_path):
    path = tmp_path / 'good.sarif'
    path.write_text(json.dumps(_report(tmp_path, 'cpp', 'a.c', 'cpp/example')))
    result = coverage.build_from_codeql(tmp_path / 'missing.sarif', extra_sarif_paths=[path], repo_root=tmp_path)
    assert result['files_examined'] == ['a.c']


def test_mixed_versions_are_not_reported_as_one_arbitrary_version(tmp_path):
    accumulator = coverage.CodeQLCoverageAccumulator(tmp_path)
    accumulator.add_report(_report(tmp_path, 'cpp', 'a.c', 'cpp/example'))
    accumulator.add_report(_report(tmp_path, 'java', 'A.java', 'java/example', version='2.17.0'))
    result = accumulator.build_record()
    assert 'version' not in result
    assert result['versions'] == ['2.16.0', '2.17.0']


def test_decoded_result_payloads_are_not_retained(tmp_path):
    class Payload:
        pass
    payload = Payload()
    reference = weakref.ref(payload)
    data = _report(tmp_path, 'cpp', 'a.c', 'cpp/example')
    data['runs'][0]['results'] = payload
    accumulator = coverage.CodeQLCoverageAccumulator(tmp_path)
    accumulator.add_report(data)
    del data, payload
    gc.collect()
    assert reference() is None
    assert accumulator.build_record()['files_examined'] == ['a.c']


def test_configuration_notification_locations_are_preserved_once_across_channels(tmp_path):
    data = _report(tmp_path, 'cpp', 'a.c', 'cpp/example')
    invocation = data['runs'][0]['invocations'][0]
    invocation['toolConfigurationNotifications'] = list(invocation['toolExecutionNotifications'])
    accumulator = coverage.CodeQLCoverageAccumulator(tmp_path)
    accumulator.add_report(data)
    assert accumulator.build_record()['files_failed'] == [{'path': 'a.c', 'reason': 'partial extraction'}]
    invocation.pop('toolExecutionNotifications')
    accumulator = coverage.CodeQLCoverageAccumulator(tmp_path)
    accumulator.add_report(data)
    assert accumulator.build_record()['files_failed'] == [{'path': 'a.c', 'reason': 'partial extraction'}]
