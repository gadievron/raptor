"""Sink absence does not prove pure arithmetic free of quality defects."""

import pytest

from core.audit import prefilter


@pytest.mark.parametrize('operator', ['/', '%', '*', '-', '+', '<<', '>>'])
@pytest.mark.parametrize('extension', ['c', 'cpp'])
def test_arithmetic_reaches_review_without_a_security_sink(tmp_path, operator, extension):
    pytest.importorskip('tree_sitter_c' if extension == 'c' else 'tree_sitter_cpp')
    source = f'int Calculate(int Left,int Right){{return Left{operator}Right;}}'
    result = prefilter.run_prefilter(
        target_path=tmp_path, file_path=f'quality.{extension}', function_name='Calculate',
        source=source, sink_unreachable=True,
    )
    assert not result.skip_llm, (operator, result.skip_reason)


@pytest.mark.parametrize('expression', ['-Value', 'Value++', '--Value', 'Value/=2', 'Value%=2', 'Value*=2'])
def test_other_integer_operations_also_retain_review(tmp_path, expression):
    pytest.importorskip('tree_sitter_c')
    result = prefilter.run_prefilter(
        target_path=tmp_path, file_path='quality.c', function_name='Calculate',
        source=f'int Calculate(int Value){{return {expression};}}', sink_unreachable=True,
    )
    assert not result.skip_llm, result.skip_reason


def test_member_access_and_arithmetic_prose_do_not_disable_the_existing_skip(tmp_path):
    pytest.importorskip('tree_sitter_c')
    source = ('void Note(struct ctx *c){int Local=c->count;'
              '/* Left/Right Left%Right Left*Right */'
              'const char *Message="Left-Right";c->total=Local;c->logged=1;}')
    result = prefilter.run_prefilter(
        target_path=tmp_path, file_path='quality.c', function_name='Note',
        source=source, sink_unreachable=True,
    )
    assert result.skip_llm
    assert result.skip_reason == 'no sink path + no logic-class signals'


def test_missing_parser_never_certifies_arithmetic_clean(monkeypatch):
    from core.audit import condition_extraction
    from core.testing.module_views import scoped_function_imports

    with scoped_function_imports(
        prefilter, ('_has_integer_arithmetic',),
        {'core.audit.condition_extraction': condition_extraction},
    ) as imports:
        parser_module = getattr(imports, 'core.audit.condition_extraction')
        monkeypatch.setattr(parser_module, '_get_parser', lambda language: None)
        assert prefilter._has_integer_arithmetic('int Read(int A,int B){return A/B;}', language='c')
