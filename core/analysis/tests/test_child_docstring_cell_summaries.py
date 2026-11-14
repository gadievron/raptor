"""One plain child docstring preserves the supported lexical capture grammar."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<child-docstring-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("prefix", ["", "from __future__ import annotations\n"],
                         ids=["ordinary", "future"])
@pytest.mark.parametrize("kind", ["", "async "], ids=["ordinary-child", "async-child"])
def test_documented_child_retains_body_cell(prefix, kind):
    result = summaries(
        prefix + f"def handle(raw):\n    def nested():\n        {kind}def child():\n"
        '            "child docs"\n            return raw\n        return child\n    return nested\n'
    )["handle"]
    assert result.summary_unknown


def test_documented_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        '            "child docs"\n            return raw\n        return child\n    return nested()\n'
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_documented_child_parameter_still_masks_outer_cell():
    result = summaries(
        'def handle(raw):\n    def nested():\n        def child(raw):\n            "docs"\n'
        "            return raw\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


def test_docstring_text_is_not_reparsed_as_source():
    body = ast.parse('def child():\n "raw.member + lambda: raw"\n return 0').body
    before = ast.dump(ast.Module(body=body, type_ignores=[]))
    assert _bounded_body_expression_loads(body) == frozenset()
    assert ast.dump(ast.Module(body=body, type_ignores=[])) == before


def test_bare_return_after_docstring_contributes_no_reads():
    assert _bounded_body_expression_loads(ast.parse('def child():\n "docs"\n return').body) == frozenset()


@pytest.mark.parametrize("body", ['"docs"\n "second"\n return raw',
                                  'b"docs"\n return raw', 'f"{raw}"\n return 0',
                                  't"{raw}"\n return 0'],
                         ids=["second-string", "bytes", "formatted", "template"])
def test_other_child_expressions_keep_their_reads(body):
    if body.startswith('t"') and not hasattr(ast, "TemplateStr"):
        pytest.skip("Template string syntax requires Python 3.14")
    source = "def child():\n " + body
    assert _bounded_body_expression_loads(ast.parse(source).body) == frozenset({"raw"})


def test_documented_child_annotations_remain_excluded():
    assert _bounded_body_expression_loads(ast.parse('def child(value: raw):\n "docs"\n return 0').body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        'def handle(raw):\n    def nested(**unused):\n        def child():\n            "docs"\n'
        "            return raw\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"


def test_docstring_only_child_stays_excluded():
    assert _bounded_body_expression_loads(ast.parse('def child():\n "docs"').body) is None
