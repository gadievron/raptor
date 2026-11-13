"""C/C++ line-only findings cannot choose a safe sibling alphabetically."""

import pytest

from core.analysis.finding_resolver import ResolutionFailure, ResolvedFinding, resolve_finding
from core.analysis.sanitizer_cut import evaluate_finding
from core.testing.treesitter import requires_ts


def _resolve(tmp_path, call, language='c', hint=None):
    source = tmp_path / ('subject.cpp' if language == 'cpp' else 'subject.c')
    source.write_text('extern char *g_markup_escape_text(const char *, long);\n'
                      'extern void render(const char *, ...);\n'
                      'void handle(const char *raw) {\n'
                      '    const char *aa = g_markup_escape_text(raw, -1);\n'
                      f'    {call};\n}}\n')
    finding = {'cwe': 'CWE-79', 'file_path': str(source), 'source_line': 3,
               'sink_line': 5, 'language': language}
    if hint is not None:
        finding['sink_arg'] = hint
    return resolve_finding(finding, target_root=tmp_path)


def _verdict(result):
    assert isinstance(result, ResolvedFinding)
    return evaluate_finding(result.cfg, [result.source_node], result.sink_node,
                            cwe=result.cwe, language=result.language,
                            source_symbols=result.source_symbols, sink_arg=result.sink_arg)


@requires_ts('c')
def test_unhinted_safe_argument_cannot_represent_raw_sibling(tmp_path):
    assert isinstance(_resolve(tmp_path, 'render(aa, raw)'), ResolutionFailure)


@requires_ts('c')
@requires_ts('cpp')
@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('call', ['render(aa, raw)', 'render(raw, aa)'])
def test_distinct_arguments_refuse_for_both_languages_and_orders(tmp_path, language, call):
    assert isinstance(_resolve(tmp_path, call, language), ResolutionFailure)


@requires_ts('c')
def test_invalid_hint_does_not_restore_arbitrary_fallback(tmp_path):
    assert isinstance(_resolve(tmp_path, 'render(aa, raw)', hint='missing'), ResolutionFailure)


@requires_ts('c')
def test_explicit_raw_hint_keeps_existing_value_binding(tmp_path):
    result = _resolve(tmp_path, 'render(aa, raw)', hint='raw')
    assert isinstance(result, ResolvedFinding)
    assert result.sink_arg == 'raw'
    assert _verdict(result).suppress is False


@requires_ts('c')
@pytest.mark.parametrize('call', ['render(aa)', 'render(aa, aa)', 'render(aa, "fixed")'])
def test_one_distinct_name_keeps_existing_sanitizer_proof(tmp_path, call):
    result = _resolve(tmp_path, call)
    assert isinstance(result, ResolvedFinding)
    assert result.sink_arg == 'aa'
    assert _verdict(result).suppress is True
