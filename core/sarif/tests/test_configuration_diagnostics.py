"""Configuration failures remain execution diagnostics, never findings."""

import copy
import gc
import json
import weakref

import pytest

from core.reporting.scan_coverage import scan_execution_status
from core.sarif.parser import generate_scan_metrics, get_run_execution_diagnostics


@pytest.mark.parametrize('tool', ['CodeQL', 'Semgrep', 'Coccinelle'])
@pytest.mark.parametrize('findings', [0, 1], ids=['zero-findings', 'retained-finding'])
def test_configuration_error_marks_execution_partial_without_discarding_findings(tmp_path, tool, findings):
    data = {'runs': [{'tool': {'driver': {'name': tool}},
        'results': [{'ruleId': 'kept'}] * findings,
        'invocations': [{'executionSuccessful': True,
                         'toolConfigurationNotifications': [{'level': 'error'}]}],
    }]}
    path = tmp_path / 'report.sarif'
    path.write_text(json.dumps(data))
    metrics = generate_scan_metrics([str(path)])
    assert metrics['total_findings'] == findings
    assert metrics['tool_execution_failures'] == {tool.lower(): 1}
    assert metrics['sarif_input_errors'] == 0
    assert scan_execution_status(metrics) == 'partial'


@pytest.mark.parametrize('success', [True, False])
def test_one_invocation_counts_once_across_both_error_channels(success):
    run = {'invocations': [{'executionSuccessful': success,
        'toolExecutionNotifications': [{'level': 'error'}] * 3,
        'toolConfigurationNotifications': [{'level': 'error'}] * 4,
    }]}
    original = copy.deepcopy(run)
    assert get_run_execution_diagnostics(run) == {
        'tool_execution_failures': 1, 'tool_coverage_limitations': 0, 'sarif_input_errors': 0,
    }
    assert run == original


@pytest.mark.parametrize('notes,limitations,status', [
    pytest.param([{'level': 'warning'}], 0, 'ok', id='ordinary-warning'),
    pytest.param([{'level': 'note', 'properties': {'coverage_limitation': 'query_budget'}}],
                 1, 'partial', id='explicit-coverage-gap'),
    pytest.param([{'properties': {'coverage_limitation': 'review_candidates'}}],
                 0, 'ok', id='legacy-review-candidates'),
])
def test_configuration_warnings_require_an_explicit_coverage_gap(tmp_path, notes, limitations, status):
    path = tmp_path / 'report.sarif'
    path.write_text(json.dumps({'runs': [{'tool': {'driver': {'name': 'CodeQL'}},
        'invocations': [{'executionSuccessful': True, 'toolConfigurationNotifications': notes}],
    }]}))
    metrics = generate_scan_metrics([str(path)])
    assert metrics['tool_execution_failures'] == {}
    assert metrics['tool_coverage_limitations'] == ({'codeql': limitations} if limitations else {})
    assert scan_execution_status(metrics) == status


@pytest.mark.parametrize('notes', [None, {}, [None], ['bad']],
                         ids=['null-channel', 'object-channel', 'null-note', 'string-note'])
def test_bad_configuration_metadata_cannot_hide_execution_errors(notes):
    run = {'invocations': [{'executionSuccessful': True,
        'toolConfigurationNotifications': notes,
        'toolExecutionNotifications': [{'level': 'error'}],
    }]}
    assert get_run_execution_diagnostics(run) == {
        'tool_execution_failures': 1, 'tool_coverage_limitations': 0, 'sarif_input_errors': 1,
    }


def test_original_configuration_failure_survives_combined_report_metadata_loss(tmp_path):
    original, combined = tmp_path / 'raw.sarif', tmp_path / 'combined.sarif'
    original.write_text(json.dumps({'runs': [{'tool': {'driver': {'name': 'CodeQL'}},
        'results': [{'ruleId': 'raw'}] * 3,
        'invocations': [{'toolConfigurationNotifications': [{'level': 'error'}]}],
    }]}))
    combined.write_text(json.dumps({'runs': [{'results': [{'ruleId': 'combined'}]}]}))
    metrics = generate_scan_metrics([str(combined)], file_count_paths=[str(original)])
    assert metrics['total_findings'] == 1
    assert metrics['tool_execution_failures'] == {'codeql': 1}
    assert scan_execution_status(metrics) == 'partial'


def test_diagnostic_counts_do_not_retain_unused_notification_payloads():
    class Payload:
        pass
    payload = Payload()
    reference = weakref.ref(payload)
    run = {'invocations': [{'toolConfigurationNotifications': [{'level': 'error', 'unused': payload}]}]}
    counts = get_run_execution_diagnostics(run)
    del run, payload
    gc.collect()
    assert reference() is None
    assert counts['tool_execution_failures'] == 1
