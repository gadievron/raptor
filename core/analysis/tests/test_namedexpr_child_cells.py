"""Child assignment expressions preserve enclosing and lambda binding ownership."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<namedexpr-child>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("expression", ["(value := raw)", "lambda: (value := raw)",
                                       "[(value := raw) for item in ()]",
                                       "lambda: (lambda value=(other := raw): value)"],
                         ids=["rhs", "lambda-rhs", "comprehension-rhs", "nested-lambda-default"])
def test_returned_function_retains_assignment_rhs_cell(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child():\n"
        f"            return {expression}\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


@pytest.mark.parametrize("header", ["value=(other := raw)", "raw=(other := raw)",
                                    "value=lambda: (other := raw)"],
                         ids=["default-rhs", "child-parameter-shadow", "lambda-default-rhs"])
def test_default_assignments_keep_enclosing_rhs_cell(header):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n"
        "            return 0\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_namedexpr_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            return (value := raw)\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,expression", [("", "(raw := 0)"), ("", "lambda: (raw := 0)"),
                                              ("", "[(raw := item) for item in ()]"),
                                              ("value=(raw := 0)", "value"),
                                              ("raw", "(value := raw)")],
                         ids=["child-local", "lambda-local", "comprehension-local", "enclosing-default-local",
                              "child-parameter"])
def test_assignment_owners_mask_outer_cell(header, expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n"
        f"            return {expression}\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


def test_namedexpr_in_comprehension_target_index_stays_excluded():
    source = "def child():\n return [item for slots[(index := 0)] in ()]"
    # The parser produces an AST for this shape; target completeness is still
    # rejected and is not evidence that compilation or execution succeeds.
    assert _bounded_body_expression_loads(ast.parse(source).body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            return (value := raw)\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
