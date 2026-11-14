"""Child deletion targets retain lexical cells without executing deletion."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<delete-child-body>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["del raw.member", "del slots[raw]", "del raw.member, slots[raw]",
                                  "del (raw.member, [slots[raw]])"],
                         ids=["member", "index", "multiple", "nested-targets"])
def test_returned_function_retains_deletion_child_cell(body):
    result = summaries(
        f"def handle(raw, slots):\n    def nested():\n        def child():\n            {body}\n"
        "            return 0\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_delete_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            del raw.member\n            return 0\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [("", "del raw"), ("raw", "del raw.member"),
                                       ("", "raw\n            if False:\n                del raw"),
                                       ("", "del raw.member\n            del raw"),
                                       ("", "del (raw, [other])")],
                         ids=["bare-local", "parameter", "unreachable-delete", "later-delete", "nested-bindings"])
def test_whole_child_bindings_mask_deletion_reads(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n            {body}\n"
        "            return 0\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", ["del slots[(lambda: (yield raw))()]", "del slots[(index := 0)]",
                                  "del raw.member\n global unsupported"],
                         ids=["lambda-index", "assignment-index", "later-declaration"])
def test_unsupported_deletion_target_invalidates_complete_child(body):
    assert _bounded_body_expression_loads(ast.parse("raw\ndef child():\n " + body).body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            del raw.member\n            return 0\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
