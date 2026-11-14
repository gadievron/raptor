"""Child comprehensions expose lexical cells without iteration or target execution."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<comprehension-child-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("expression", ["[raw for item in ()]", "{raw for item in ()}",
                                       "{item: raw for item in ()}", "(raw for item in ())",
                                       "[raw for raw in raw]", "[item for slots[raw] in ()]",
                                       "[raw for first, second in ()]",
                                       "lambda: [raw for item in ()]"],
                         ids=["list", "set", "dict", "generator", "first-iterable", "indirect-target",
                              "unpacking", "lambda-body"])
def test_returned_function_retains_child_comprehension_cell(expression):
    result = summaries(
        f"def handle(raw, slots):\n    def nested():\n        def child():\n"
        f"            return {expression}\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_comprehension_child_default_retains_enclosing_cell():
    result = summaries(
        "def handle(raw):\n    def nested():\n        def child(value=[raw for item in ()]):\n"
        "            return value\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_comprehension_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            return [raw for item in ()]\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("parameters,expression", [
    ("", "[raw for raw in ()]"), ("", "[raw for item in () for raw in ()]"),
    ("raw", "[raw for item in ()]"), ("", "[raw for raw, other in ()]"),
    ("", "lambda raw: [raw for item in ()]"),
], ids=["target", "later-target", "child-parameter", "unpacked-target", "lambda-parameter"])
def test_child_and_comprehension_bindings_mask_outer_cell(parameters, expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({parameters}):\n"
        f"            return {expression}\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("expression", ["[raw for slots[[(lambda: (yield raw))() for item in ()]] in ()]",
                                       "lambda: [raw for slots[[(lambda: (yield raw))() for item in ()]] in ()]",
                                       "lambda: (yield [raw for box[[(lambda: (yield raw))() for item in ()]] in ()])"],
                         ids=["scoped-target", "nested-scoped-target", "generator-output"])
def test_incomplete_target_or_unsupported_node_invalidates_complete_body(expression):
    assert _bounded_body_expression_loads(ast.parse(f"raw\ndef child():\n return {expression}").body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            return [raw for item in ()]\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
