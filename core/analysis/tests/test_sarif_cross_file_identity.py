"""SARIF endpoints in different files cannot share one file's CFG."""

import pytest

from core.analysis import finding_resolver as resolver
from core.analysis.sanitizer_cut import evaluate_finding
from core.analysis.tests.test_finding_resolver import _sarif_result


def _finding(source, sink):
    finding = _sarif_result(str(source), 2, 4)
    finding['properties']['tags'] = ['external/cwe/cwe-022']
    finding['locations'][0]['physicalLocation']['artifactLocation']['uri'] = str(sink)
    last = finding['codeFlows'][0]['threadFlows'][0]['locations'][-1]
    last['location']['physicalLocation']['artifactLocation']['uri'] = str(sink)
    return finding


def _safe_source(tmp_path):
    path = tmp_path / 'safe.py'
    path.write_text('import werkzeug.utils\ndef handle(raw):\n    clean=werkzeug.utils.secure_filename(raw)\n    open(clean)\n')
    return path


def test_cross_file_sink_cannot_borrow_source_file_sanitizer(tmp_path):
    source = _safe_source(tmp_path)
    sink = tmp_path / 'unsafe.py'
    sink.write_text('def handle(raw):\n    copy=raw\n    other=copy\n    open(raw)\n')
    result = resolver.resolve_finding(_finding(source, sink), target_root=tmp_path)
    assert isinstance(result, resolver.ResolutionFailure)
    assert 'different files' in result.reason


def test_cross_file_refusal_precedes_source_read(tmp_path, monkeypatch):
    source = _safe_source(tmp_path)
    finding = _finding(source, tmp_path / 'other.py')

    def forbidden_read(*args, **kwargs):
        raise AssertionError('cross-file metadata reached source reader')

    with monkeypatch.context() as scope:
        scope.setattr(resolver, '_read_finding_source', forbidden_read)
        result = resolver.resolve_finding(finding, target_root=tmp_path)
    assert isinstance(result, resolver.ResolutionFailure)
    assert 'different files' in result.reason


def test_same_file_endpoints_keep_existing_sanitizer_proof(tmp_path):
    source = _safe_source(tmp_path)
    result = resolver.resolve_finding(_finding(source, source), target_root=tmp_path)
    assert isinstance(result, resolver.ResolvedFinding)
    verdict = evaluate_finding(result.cfg, [result.source_node], result.sink_node,
                               cwe=result.cwe, language=result.language,
                               source_symbols=result.source_symbols, sink_arg=result.sink_arg)
    assert verdict.suppress is True


@pytest.mark.parametrize('endpoint', [0, -1])
def test_one_missing_endpoint_uri_retains_existing_fallback(tmp_path, endpoint):
    source = _safe_source(tmp_path)
    finding = _finding(source, source)
    location = finding['codeFlows'][0]['threadFlows'][0]['locations'][endpoint]
    location['location']['physicalLocation']['artifactLocation'].pop('uri')
    result = resolver.resolve_finding(finding, target_root=tmp_path)
    assert isinstance(result, resolver.ResolvedFinding)


def test_direct_physical_location_shape_keeps_cross_file_refusal(tmp_path):
    source = _safe_source(tmp_path)
    finding = _finding(source, tmp_path / 'other.py')
    flow = finding['codeFlows'][0]['threadFlows'][0]
    flow['locations'] = [location['location'] for location in flow['locations']]
    result = resolver.resolve_finding(finding, target_root=tmp_path)
    assert isinstance(result, resolver.ResolutionFailure)
    assert 'different files' in result.reason
