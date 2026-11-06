"""Keep execution diagnostics separate from findings and source-file counts."""
import json

import pytest

from core.reporting.scan_coverage import scan_execution_status
from core.sarif.parser import generate_scan_metrics


def _write(tmp_path, name, run):
    path = tmp_path / name
    path.write_text(json.dumps({'version': '2.1.0', 'runs': [run]}))
    return str(path)


@pytest.mark.parametrize('invocation,failures,limitations', [
    ({'executionSuccessful': False}, 1, 0),
    ({'executionSuccessful': True, 'toolExecutionNotifications': [{'level': 'error'}]}, 1, 0),
    ({'executionSuccessful': False, 'toolExecutionNotifications': [{'level': 'error'}] * 3}, 1, 0),
    ({'executionSuccessful': True, 'toolExecutionNotifications': [
        {'level': 'warning', 'properties': {'coverage_limitation': 'compiler_budget'}},
    ]}, 0, 1),
    ({'executionSuccessful': True, 'toolExecutionNotifications': [{'level': 'warning'}]}, 0, 0),
    ({'executionSuccessful': True, 'toolExecutionNotifications': [
        {'properties': {'coverage_limitation': 'review_candidates'}},
    ]}, 0, 0),
    ({}, 0, 0),
])
def test_tool_diagnostics_do_not_change_findings(tmp_path, invocation, failures, limitations):
    report = _write(tmp_path, 'tool.sarif', {
        'tool': {'driver': {'name': 'Coccinelle'}}, 'results': [{'ruleId': 'kept'}],
        'invocations': [invocation],
    })
    metrics = generate_scan_metrics([report])
    assert metrics['total_findings'] == 1
    assert metrics['findings_by_tool'] == {'coccinelle': 1}
    assert metrics['tool_execution_failures'] == ({'coccinelle': failures} if failures else {})
    assert metrics['tool_coverage_limitations'] == ({'coccinelle': limitations} if limitations else {})
    assert scan_execution_status(metrics) == ('partial' if failures or limitations else 'ok')


def test_original_diagnostics_survive_filtered_combined_report_without_double_counting(tmp_path, monkeypatch):
    from core.sarif import parser
    original = _write(tmp_path, 'raw.sarif', {
        'tool': {'driver': {'name': 'CodeQL'}}, 'results': [{'ruleId': 'raw'}] * 3,
        'artifacts': [{'location': {'uri': 'a.c'}}],
        'invocations': [{'executionSuccessful': False}],
    })
    combined = _write(tmp_path, 'combined.sarif', {
        'tool': {'driver': {'name': 'CodeQL'}}, 'results': [{'ruleId': 'filtered'}],
        'invocations': [{'executionSuccessful': False}],
    })
    reads = []
    load = parser.load_sarif

    def track(path):
        reads.append(str(path))
        return load(path)
    monkeypatch.setattr(parser, 'load_sarif', track)
    metrics = generate_scan_metrics([combined], file_count_paths=[original, original])
    assert reads == [combined, original]
    assert metrics['total_findings'] == metrics['total_files_scanned'] == 1
    assert metrics['findings_by_rule'] == {'filtered': 1}
    assert metrics['tool_execution_failures'] == {'codeql': 1}
    reads.clear()
    metrics = generate_scan_metrics([original], file_count_paths=[original])
    assert reads == [original]
    assert metrics['tool_execution_failures'] == {'codeql': 1}


@pytest.mark.parametrize('run', [
    None, {'invocations': None}, {'invocations': [None]},
    {'invocations': [{'executionSuccessful': 'true'}]},
    {'invocations': [{'toolExecutionNotifications': {}}]},
    {'invocations': [{'toolExecutionNotifications': [None]}]},
    {'results': {}}, {'results': [None]}, {'artifacts': 'not-an-array'},
])
def test_malformed_diagnostics_cannot_imply_success(tmp_path, run):
    report = _write(tmp_path, 'damaged.sarif', run)
    metrics = generate_scan_metrics([report])
    assert metrics['sarif_input_errors'] > 0
    assert scan_execution_status(metrics) == 'partial'


def test_missing_and_invalid_reports_are_not_clean_empty_metrics(tmp_path):
    missing = str(tmp_path / 'missing.sarif')
    invalid = tmp_path / 'invalid.sarif'
    invalid.write_text('not-json')
    metrics = generate_scan_metrics([missing, str(invalid)])
    assert metrics['total_findings'] == 0
    assert metrics['sarif_input_errors'] == 2
    assert scan_execution_status(metrics) == 'partial'



def test_coccinelle_partial_producer_retains_findings_and_failure_status(tmp_path):
    from packages.coccinelle.models import SpatchMatch, SpatchResult
    from packages.coccinelle.sarif import results_to_sarif

    result = SpatchResult(rule='partial', matches=[SpatchMatch(file='a.c', line=1)],
                          errors=['rule failed after a match'], returncode=0)
    path = tmp_path / 'cocci.sarif'
    path.write_text(json.dumps(results_to_sarif([result], tmp_path)))
    metrics = generate_scan_metrics([str(path)])
    assert metrics['total_findings'] == 1
    assert metrics['tool_execution_failures'] == {'coccinelle': 1}
    assert scan_execution_status(metrics) == 'partial'



def test_empty_original_file_list_does_not_hide_primary_execution_failure(tmp_path):
    report = _write(tmp_path, 'failed.sarif', {
        'tool': {'driver': {'name': 'CodeQL'}}, 'results': [],
        'artifacts': [{'location': {'uri': 'not-counted.c'}}],
        'invocations': [{'executionSuccessful': False}],
    })
    metrics = generate_scan_metrics([report], file_count_paths=[])
    assert metrics['total_files_scanned'] == 0
    assert metrics['tool_execution_failures'] == {'codeql': 1}
    assert scan_execution_status(metrics) == 'partial'
