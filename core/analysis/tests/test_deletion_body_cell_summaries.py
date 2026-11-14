"""Deletion syntax retains cells without executing any target operations."""


from core.analysis.tests.target_ast_helpers import parse_target_refusal_fixture

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<deletion-body-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["del raw.member", "del slots[raw]",
                                  "del raw.member, slots[raw]", "del (raw.member, [slots[raw]])"],
                         ids=["member", "index", "multiple", "nested-targets"])
def test_returned_function_retains_deletion_target_cell(body):
    result = summaries(
        f"def handle(raw, slots):\n    def nested():\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_deletion_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        del raw.member\n"
        "        return 0\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [
    ("", "del raw"), ("", "del (raw, [other])"),
    ("raw=0", "del raw.member"),
    ("", "raw\n        if False:\n            del raw"),
    ("", "del raw.member\n        del raw"),
], ids=["bare-local", "nested-bindings", "parameter", "unreachable-delete", "later-delete"])
def test_own_bindings_mask_deletion_cells(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested({header}):\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", ["del slots[_raptor_unsupported_target]", "del slots[(raw := 0)]",
                                  "del raw.member\nglobal unsupported"],
                         ids=["synthetic-target", "walrus-target", "later-declaration"])
def test_unsupported_deletion_tree_invalidates_earlier_capture(body):
    assert _bounded_body_expression_loads(parse_target_refusal_fixture(f"raw\n{body}").body) is None


def test_nested_scope_unsupported_delete_stays_excluded():
    assert _bounded_body_expression_loads(parse_target_refusal_fixture("def child():\n del slots[_raptor_unsupported_target]").body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        del raw.member\n"
        "        return 0\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
