"""Unnamed exception-group blocks expose lexical cells without payload proof."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


BODIES = [
    "try:\n raw\nexcept* Exception:\n pass",
    "try:\n pass\nexcept* raw:\n pass",
    "try:\n pass\nexcept* Exception:\n raw",
    "try:\n pass\nexcept* Exception:\n pass\nelse:\n raw",
    "try:\n pass\nexcept* Exception:\n pass\nfinally:\n raw",
    "try:\n pass\nexcept* ValueError:\n pass\nexcept* raw:\n pass",
]


def summaries(source):
    compile(source, "<trystar-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(body, child=False, header=""):
    body += "\nreturn 0\n"
    if child:
        body = f"def child({header}):\n" + indent(body, " ") + "return child\n"
        header = ""
    return f"def handle(raw):\n    def nested({header}):\n" + indent(body, "        ") + "    return nested\n"


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("body", BODIES, ids=["try", "handler-type", "handler-body", "else", "finally", "multiple"])
def test_trystar_retains_enclosing_cell(body, child):
    assert summaries(source_for(body, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_trystar_keeps_caller_raw_flow(child):
    source = source_for(BODIES[1], child).replace("def handle(raw):", "def helper(raw):").replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_trystar_parameter_masks_outer_cell(child):
    assert not summaries(source_for(BODIES[1], child, "raw"))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_unreachable_binding_masks_group_reads(child):
    body = "try:\n raw\nexcept* Exception:\n pass\nfinally:\n if False:\n  raw = 0"
    assert not summaries(source_for(body, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("body", ["try:\n pass\nexcept* Exception as error:\n raw",
                                  "try:\n pass\nexcept* raw:\n global other"],
                         ids=["named-payload", "unsupported-body"])
def test_unsupported_group_tree_invalidates_complete_scan(body, child):
    tree = ast.parse(source_for(body, child))
    assert _bounded_body_expression_loads(tree.body[0].body[0].body) is None


def test_own_caught_payload_keeps_prior_reason():
    source = source_for(BODIES[1]).replace("    def nested():", "    try:\n        pass\n    except* Exception as error:\n        pass\n    def nested():")
    assert summaries(source)["handle"].summary_unknown_reason == "caught exception payload is not modelled"
