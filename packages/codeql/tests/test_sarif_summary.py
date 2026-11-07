"""CodeQL report summaries keep usable data and reuse bounded report reads."""

import copy
import gc
import weakref

import pytest

from core.sarif import parser
from packages.codeql.query_runner import QueryRunner


@pytest.fixture
def runner(tmp_path):
    executable = tmp_path / 'codeql'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    return QueryRunner(codeql_cli=str(executable))


def test_inherited_rule_metadata_and_extension_catalogs_are_counted(runner, tmp_path):
    data = {'runs': [{'tool': {'driver': {'rules': [
        {'id': 'java/base', 'defaultConfiguration': {'level': 'error'}},
    ]}, 'extensions': [{'rules': [
        {'id': 'java/custom', 'defaultConfiguration': {'level': 'note'}},
        {'id': 'java/custom', 'defaultConfiguration': {'level': 'note'}},
    ]}]}, 'results': [
        {'ruleIndex': 0},
        {'rule': {'index': 0, 'toolComponent': {'index': 0}}},
        {'ruleId': 'java/custom', 'level': 'error'},
    ]}]}
    original = copy.deepcopy(data)
    summary = runner.get_sarif_summary(tmp_path / 'unused', sarif_data=data)
    assert summary['total_findings'] == 3
    assert summary['by_severity'] == {'error': 2, 'warning': 0, 'note': 1}
    assert summary['by_rule'] == {'java/base': 1, 'java/custom': 2}
    assert summary['queries_executed'] == 2
    assert summary['sarif_input_errors'] == 0
    assert data == original


def test_malformed_neighbors_do_not_discard_findings_or_flow_counts(runner, tmp_path, monkeypatch):
    from packages.codeql import query_runner
    warnings = []
    monkeypatch.setattr(query_runner.logger, 'warning', lambda message, *args: warnings.append(message % args))
    data = {'runs': [None, {'tool': {'driver': {'rules': [None,
        {'id': 'java/valid', 'defaultConfiguration': {'level': 'error'}}, {'id': []},
    ]}, 'extensions': [None, {'rules': 'bad'}]}, 'results': [None, {
        'ruleIndex': 1, 'ruleId': {}, 'level': {},
        'codeFlows': [None, {'threadFlows': [None, {'locations': [None, {}, {}]}, {'locations': 'bad'}]}],
    }, {'ruleId': 'tail', 'level': 'note'}]}, {'results': [{'ruleId': 'last', 'level': 'warning'}]}]}
    summary = runner.get_sarif_summary(tmp_path / 'unused', sarif_data=data)
    assert summary['total_findings'] == 3
    assert summary['by_rule'] == {'java/valid': 1, 'tail': 1, 'last': 1}
    assert summary['by_severity'] == {'error': 1, 'warning': 1, 'note': 1}
    assert summary['dataflow_paths'] == 1
    assert summary['total_dataflow_steps'] == 2
    assert summary['queries_executed'] == 1
    assert summary['sarif_input_errors'] == 12
    assert len(warnings) == 1 and '12 malformed metadata' in warnings[0]


@pytest.mark.parametrize('data', [None, {}, {'runs': None}, {'runs': {}}, [], False],
                         ids=['failed-preload', 'empty-object', 'null-runs', 'object-runs', 'array', 'boolean'])
def test_supplied_unusable_input_is_not_reopened(runner, tmp_path, monkeypatch, data):
    def forbidden(*args):
        pytest.fail('preloaded input must not trigger another report read')
    monkeypatch.setattr(parser, 'load_sarif', forbidden)
    assert runner.get_sarif_summary(tmp_path / 'unused', sarif_data=data) == {}


def test_omitting_preloaded_input_uses_the_shared_reader_once(runner, tmp_path, monkeypatch):
    seen = []
    def load(path):
        seen.append(path)
        return {'runs': []}
    monkeypatch.setattr(parser, 'load_sarif', load)
    report = tmp_path / 'report.sarif'
    summary = runner.get_sarif_summary(report)
    assert seen == [report]
    assert summary['total_findings'] == summary['sarif_input_errors'] == 0


@pytest.mark.parametrize('explicit', [True, False], ids=['explicit-fields', 'inherited-fields'])
def test_rule_resolution_is_lazy_and_shared_within_a_run(runner, tmp_path, monkeypatch, explicit):
    original = parser.ResultRuleResolver
    created = []
    def resolve(run):
        created.append(1)
        return original(run)
    monkeypatch.setattr(parser, 'ResultRuleResolver', resolve)
    row = {'ruleId': 'java/r', 'level': 'error'} if explicit else {'ruleIndex': 0}
    data = {'runs': [{'tool': {'driver': {'rules': [
        {'id': 'java/r', 'defaultConfiguration': {'level': 'error'}},
    ]}}, 'results': [dict(row) for _ in range(100)]}]}
    summary = runner.get_sarif_summary(tmp_path / 'unused', sarif_data=data)
    assert summary['by_severity']['error'] == 100
    assert len(created) == (0 if explicit else 1)


def test_invalid_component_reference_does_not_borrow_driver_severity(runner, tmp_path):
    data = {'runs': [{'tool': {'driver': {'rules': [
        {'id': 'shared', 'defaultConfiguration': {'level': 'error'}},
    ]}, 'extensions': [{'rules': [
        {'id': 'shared', 'defaultConfiguration': {'level': 'note'}},
    ]}]}, 'results': [
        {'ruleId': 'shared', 'rule': {'index': 0, 'toolComponent': {'index': 99}}},
        {'ruleId': 'shared', 'rule': {'index': 0, 'toolComponent': {'index': 0}}},
    ]}]}
    summary = runner.get_sarif_summary(tmp_path / 'unused', sarif_data=data)
    assert summary['by_rule'] == {'shared': 2}
    assert summary['by_severity'] == {'error': 0, 'warning': 1, 'note': 1}
    assert summary['queries_executed'] == 2
    assert summary['sarif_input_errors'] == 1


def test_summary_does_not_retain_unused_finding_payloads(runner, tmp_path):
    class Payload:
        pass
    payload = Payload()
    reference = weakref.ref(payload)
    data = {'runs': [{'results': [{'ruleId': 'r', 'level': 'warning', 'unused': payload}]}]}
    summary = runner.get_sarif_summary(tmp_path / 'unused', sarif_data=data)
    del data, payload
    # These acyclic fixture objects need no scan of unrelated old generations.
    gc.collect(0)
    assert reference() is None
    assert summary['total_findings'] == 1


@pytest.mark.parametrize('findings', [0, 1], ids=['zero-findings', 'retained-finding'])
def test_summary_and_scan_metrics_share_configuration_diagnostics(runner, tmp_path, findings):
    import json
    from core.reporting.scan_coverage import scan_execution_status
    data = {'runs': [{'tool': {'driver': {'name': 'CodeQL'}},
        'results': [{'ruleId': 'r', 'level': 'warning'}] * findings,
        'invocations': [{'executionSuccessful': True,
            'toolExecutionNotifications': [{'level': 'error'}],
            'toolConfigurationNotifications': [{'level': 'error'}, {
                'level': 'warning', 'properties': {'coverage_limitation': 'query_budget'},
            }],
        }],
    }]}
    report = tmp_path / 'report.sarif'
    report.write_text(json.dumps(data))
    summary = runner.get_sarif_summary(report, sarif_data=data)
    metrics = parser.generate_scan_metrics([str(report)])
    for key in ('tool_execution_failures', 'tool_coverage_limitations', 'sarif_input_errors'):
        assert summary[key] == metrics[key]
    assert summary['total_findings'] == metrics['total_findings'] == findings
    assert summary['tool_execution_failures'] == {'codeql': 1}
    assert summary['tool_coverage_limitations'] == {'codeql': 1}
    assert scan_execution_status(summary) == 'partial'
