"""Compound C/C++ arguments cannot borrow a neighbouring safe value."""

import pytest

from core.analysis.finding_resolver import ResolutionFailure, ResolvedFinding, resolve_finding
from core.analysis.sanitizer_cut import evaluate_finding
from core.testing.treesitter import requires_ts


def _resolve(tmp_path, call, hint=None, language='c'):
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
def test_pointer_arithmetic_sibling_cannot_borrow_safe_argument(tmp_path):
    assert isinstance(_resolve(tmp_path, 'render(aa, raw + 1)'), ResolutionFailure)


@requires_ts('c')
@pytest.mark.parametrize('call', [
    'render(aa, (raw ? raw : aa))',
    'render(aa, (raw, raw))',
    'render(aa, raw[0])',
    'render(aa, unknown(raw))',
])
def test_unhinted_compound_argument_shapes_refuse(tmp_path, call):
    assert isinstance(_resolve(tmp_path, call), ResolutionFailure)


@requires_ts('c')
@pytest.mark.parametrize('call', [
    'render(aa)', 'render((aa))', 'render((const char *)aa)',
    'render(aa, "fixed")', "render(aa, 'x')", 'render(aa, 1)',
    'render(aa, /* constant sibling */ 1)',
    'L\'é\', render(aa, "fixed")',
])
def test_existing_direct_cast_parenthesis_and_literal_shapes_keep_proof(tmp_path, call):
    assert _verdict(_resolve(tmp_path, call)).suppress is True


@requires_ts('c')
def test_explicit_raw_hint_keeps_existing_authority(tmp_path):
    result = _resolve(tmp_path, 'render(raw, aa + 1)', 'raw')
    assert isinstance(result, ResolvedFinding)
    assert result.sink_arg == 'raw'
    assert _verdict(result).suppress is False


@requires_ts('cpp')
def test_cpp_pointer_arithmetic_sibling_refuses(tmp_path):
    assert isinstance(_resolve(tmp_path, 'render(aa, raw + 1)', language='cpp'), ResolutionFailure)


@requires_ts('c')
def test_missing_original_call_match_refuses(tmp_path):
    from core.analysis.cfg_builder_cpp import _get_parser
    from core.analysis.finding_resolver import _resolve_sink_cpp

    result = _resolve(tmp_path, 'render(aa)')
    assert isinstance(result, ResolvedFinding)
    parser = _get_parser('c')
    assert parser is not None
    other = parser.parse(b'void other(void) {}').root_node
    assert _resolve_sink_cpp(result.cfg, 5, None, source_root=other) == (None, '')
