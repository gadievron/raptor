"""Semgrep trace paths cannot borrow a different file's source/sink lines."""

import pytest

from core.analysis import finding_resolver as resolver
from core.analysis.sanitizer_cut import evaluate_finding
from core.analysis.tests.test_finding_resolver import _semgrep_finding


def _subject(tmp_path):
    path = tmp_path / 'safe.py'
    path.write_text('import werkzeug.utils\ndef handle(raw):\n    clean=werkzeug.utils.secure_filename(raw)\n    open(clean)\n')
    finding = _semgrep_finding(str(path), 2, 4)
    finding['extra']['metadata']['cwe'] = ['CWE-22']
    return path, finding


def test_cross_file_trace_sink_cannot_borrow_primary_file_sanitizer(tmp_path):
    _, finding = _subject(tmp_path)
    other = tmp_path / 'unsafe.py'
    other.write_text('def handle(raw):\n    copy=raw\n    other=copy\n    open(raw)\n')
    finding['extra']['dataflow_trace']['taint_sink']['location']['path'] = str(other)
    result = resolver.resolve_finding(finding, target_root=tmp_path)
    assert isinstance(result, resolver.ResolutionFailure)
    assert 'different file' in result.reason


@pytest.mark.parametrize('endpoint', ['taint_source', 'taint_sink'])
def test_different_selected_endpoint_path_refuses_before_read(tmp_path, monkeypatch, endpoint):
    _, finding = _subject(tmp_path)
    trace = finding['extra']['dataflow_trace']
    value = trace[endpoint][0] if isinstance(trace[endpoint], list) else trace[endpoint]
    value['location']['path'] = str(tmp_path / 'other.py')

    def forbidden_read(*args, **kwargs):
        raise AssertionError('cross-file metadata reached source reader')

    with monkeypatch.context() as scope:
        scope.setattr(resolver, '_read_finding_source', forbidden_read)
        result = resolver.resolve_finding(finding, target_root=tmp_path)
    assert isinstance(result, resolver.ResolutionFailure)
    assert 'different file' in result.reason


def test_matching_trace_paths_keep_existing_sanitizer_proof(tmp_path):
    _, finding = _subject(tmp_path)
    result = resolver.resolve_finding(finding, target_root=tmp_path)
    assert isinstance(result, resolver.ResolvedFinding)
    verdict = evaluate_finding(result.cfg, [result.source_node], result.sink_node,
                               cwe=result.cwe, language=result.language,
                               source_symbols=result.source_symbols, sink_arg=result.sink_arg)
    assert verdict.suppress is True


def test_missing_endpoint_paths_keep_primary_file_fallback(tmp_path):
    _, finding = _subject(tmp_path)
    trace = finding['extra']['dataflow_trace']
    trace['taint_source'][0]['location'].pop('path')
    trace['taint_sink']['location'].pop('path')
    assert isinstance(resolver.resolve_finding(finding, target_root=tmp_path), resolver.ResolvedFinding)


def test_top_level_trace_path_is_bound_to_its_top_level_line(tmp_path):
    _, finding = _subject(tmp_path)
    finding['extra']['dataflow_trace']['taint_source'] = {
        'path': str(tmp_path / 'other.py'), 'start': {'line': 2}}
    result = resolver.resolve_finding(finding, target_root=tmp_path)
    assert isinstance(result, resolver.ResolutionFailure)
    assert 'different file' in result.reason


def test_path_selection_matches_first_location_line_precedence(tmp_path):
    path, finding = _subject(tmp_path)
    trace = finding['extra']['dataflow_trace']
    trace['taint_source'][0]['path'] = str(tmp_path / 'unused-outer.py')
    trace['taint_source'].append({'location': {'path': str(tmp_path / 'unused-later.py'), 'start': {'line': 99}}})
    trace['taint_source'][0]['location']['path'] = str(path)
    assert isinstance(resolver.resolve_finding(finding, target_root=tmp_path), resolver.ResolvedFinding)


def test_path_without_selected_trace_line_keeps_existing_line_fallback(tmp_path):
    _, finding = _subject(tmp_path)
    finding['extra']['dataflow_trace']['taint_source'] = {'location': {'path': str(tmp_path / 'unused.py')}}
    assert isinstance(resolver.resolve_finding(finding, target_root=tmp_path), resolver.ResolvedFinding)


def test_nested_first_trace_location_keeps_existing_line_and_path_selection(tmp_path):
    _, finding = _subject(tmp_path)
    trace = finding['extra']['dataflow_trace']
    trace['taint_source'] = [[trace['taint_source'][0]]]
    assert isinstance(resolver.resolve_finding(finding, target_root=tmp_path), resolver.ResolvedFinding)
