"""Unhinted Python sinks need an unambiguous argument-value identity."""

import pytest

from core.analysis.finding_resolver import ResolutionFailure, ResolvedFinding, resolve_finding
from core.analysis.sanitizer_cut import evaluate_finding


def _resolve(tmp_path, call, hint=None):
    source = tmp_path / 'subject.py'
    source.write_text('import werkzeug.utils\ndef handle(raw):\n'
                      '    aa=werkzeug.utils.secure_filename(raw)\n'
                      f'    {call}\n')
    finding = {'cwe': 'CWE-22', 'file_path': str(source), 'source_line': 2, 'sink_line': 4}
    if hint is not None:
        finding['sink_arg'] = hint
    return resolve_finding(finding, target_root=tmp_path)


def test_compound_unsafe_sibling_cannot_borrow_sanitized_argument(tmp_path):
    assert isinstance(_resolve(tmp_path, 'rename(aa, raw + ".txt")'), ResolutionFailure)


@pytest.mark.parametrize('call', [
    'rename(aa, raw[0])',
    'rename(aa, raw[0].value)',
    'rename(aa, *raw)',
    'rename(aa, **raw)',
    'rename(aa, (item for item in raw))',
    'rename(aa, lambda: raw)',
    'rename(raw, wrapper(aa))',
    'rename(aa, wrapper(aa))',
])
def test_compound_and_multiple_call_shapes_refuse_without_hint(tmp_path, call):
    assert isinstance(_resolve(tmp_path, call), ResolutionFailure)


@pytest.mark.parametrize('call', ['open(aa)', 'rename(aa, aa)', 'rename(aa, "fixed.txt")'])
def test_direct_arguments_and_constant_siblings_keep_existing_proof(tmp_path, call):
    result = _resolve(tmp_path, call)
    assert isinstance(result, ResolvedFinding)
    verdict = evaluate_finding(result.cfg, [result.source_node], result.sink_node,
                               cwe=result.cwe, language=result.language,
                               source_symbols=result.source_symbols, sink_arg=result.sink_arg)
    assert verdict.suppress is True


def test_matching_explicit_hint_keeps_upstream_argument_authority(tmp_path):
    result = _resolve(tmp_path, 'rename(raw, wrapper(aa))', 'raw')
    assert isinstance(result, ResolvedFinding)
    assert result.sink_arg == 'raw'
    verdict = evaluate_finding(result.cfg, [result.source_node], result.sink_node,
                               cwe=result.cwe, language=result.language,
                               source_symbols=result.source_symbols, sink_arg=result.sink_arg)
    assert verdict.suppress is False


def test_recognised_attribute_root_keeps_existing_resolution(tmp_path):
    result = _resolve(tmp_path, 'open(aa.name)')
    assert isinstance(result, ResolvedFinding)
    assert result.sink_arg == 'aa'


def test_missing_original_call_match_refuses(tmp_path):
    import ast

    from core.analysis.finding_resolver import _resolve_sink

    result = _resolve(tmp_path, 'open(aa)')
    assert isinstance(result, ResolvedFinding)
    unrelated = ast.parse('def handle(raw):\n    pass\n').body[0]
    assert isinstance(unrelated, ast.FunctionDef)
    assert _resolve_sink(result.cfg, 4, None, function_node=unrelated) == (None, '')
