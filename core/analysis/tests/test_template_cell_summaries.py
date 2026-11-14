"""Template interpolation AST reads retain cells without parsing source-text fields."""

import ast

import pytest

from core.analysis import taint_summaries as module
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph


HAS_TEMPLATE_AST = hasattr(ast, "TemplateStr") and hasattr(ast, "Interpolation")


def summaries(source):
    compile(source, "<template-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return module.build_taint_summaries(graph, source)


@pytest.mark.skipif(not HAS_TEMPLATE_AST, reason="template AST requires Python 3.14")
@pytest.mark.parametrize(
    "expression", ['t"{raw}"', 't"{raw!r}"', 't"{0:{raw}}"'],
    ids=["value", "conversion", "format-spec"],
)
def test_template_cell_helper_keeps_caller_raw_flow(expression):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested():\n        return {expression}\n"
        "    return nested()\ndef handle(raw):\n"
        "    return html.escape(raw) + helper(raw).interpolations[0].value\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.skipif(not HAS_TEMPLATE_AST, reason="template AST requires Python 3.14")
def test_interpolation_source_text_is_not_an_expression_read():
    expression = ast.parse('t"{0}"', mode="eval").body
    interpolation = next(n for n in ast.walk(expression) if type(n).__name__ == "Interpolation")
    interpolation.str = "raw"
    assert not module._scope_free_expression_loads(expression)


@pytest.mark.skipif(not HAS_TEMPLATE_AST, reason="template AST requires Python 3.14")
def test_nested_default_parameter_shadow_keeps_existing_admission():
    result = summaries(
        'def handle(raw):\n    def nested(raw=0):\n        return t"{raw}"\n    return nested()\n'
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


@pytest.mark.skipif(not HAS_TEMPLATE_AST, reason="template AST requires Python 3.14")
def test_nested_lambda_scope_remains_outside_the_read_grammar():
    expression = ast.parse('t"{(lambda raw: raw)(0)}"', mode="eval").body
    assert not module._scope_free_expression_loads(expression)


def test_missing_optional_ast_classes_keep_existing_expression_support(monkeypatch):
    class LegacyAstFacade:
        def __getattr__(self, name):
            if name in {"TemplateStr", "Interpolation"}:
                raise AttributeError(name)
            return getattr(ast, name)

    expression = ast.parse('f"{raw}"', mode="eval").body
    monkeypatch.setattr(module, "ast", LegacyAstFacade())
    assert module._scope_free_expression_loads(expression) == frozenset({"raw"})
