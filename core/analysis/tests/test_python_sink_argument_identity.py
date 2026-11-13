"""Line-only sink metadata cannot choose between distinct Python arguments."""

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


def _verdict(result):
    assert isinstance(result, ResolvedFinding)
    return evaluate_finding(result.cfg, [result.source_node], result.sink_node,
                            cwe=result.cwe, language=result.language,
                            source_symbols=result.source_symbols, sink_arg=result.sink_arg)


def test_unhinted_sanitized_argument_cannot_represent_unsafe_sibling(tmp_path):
    result = _resolve(tmp_path, 'rename(aa, raw)')
    assert isinstance(result, ResolutionFailure)


@pytest.mark.parametrize('call', ['rename(raw, aa)', 'rename(aa, destination=raw)'])
def test_distinct_arguments_refuse_independently_of_order_or_keywords(tmp_path, call):
    assert isinstance(_resolve(tmp_path, call), ResolutionFailure)


def test_invalid_hint_does_not_restore_alphabetical_fallback(tmp_path):
    assert isinstance(_resolve(tmp_path, 'rename(aa, raw)', 'missing'), ResolutionFailure)


def test_explicit_unsafe_argument_hint_preserves_value_binding(tmp_path):
    result = _resolve(tmp_path, 'rename(aa, raw)', 'raw')
    assert isinstance(result, ResolvedFinding)
    assert result.sink_arg == 'raw'
    assert _verdict(result).suppress is False


@pytest.mark.parametrize('call', ['open(aa)', 'rename(aa, aa)'])
def test_single_distinct_name_keeps_existing_sanitizer_proof(tmp_path, call):
    result = _resolve(tmp_path, call)
    assert isinstance(result, ResolvedFinding)
    assert result.sink_arg == 'aa'
    assert _verdict(result).suppress is True
