"""Augmented child targets retain lexical cells without operator execution."""


from core.analysis.tests.target_ast_helpers import parse_target_refusal_fixture

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<augassign-child-body>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["raw.member += 1", "slots[raw] += 1",
                                  "value = 0\n            value += raw"],
                         ids=["member", "index", "rhs"])
def test_returned_function_retains_augmented_child_cell(body):
    result = summaries(
        f"def handle(raw, slots):\n    def nested():\n        def child():\n            {body}\n"
        "            return 0\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_augmented_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            raw.member += 1\n            return 0\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [("", "raw += 1"), ("raw", "raw.member += 1"),
                                       ("", "raw.member += 1\n            if False:\n                raw = 0")],
                         ids=["bare-local", "parameter", "unreachable-binding"])
def test_whole_child_bindings_mask_augmented_reads(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n            {body}\n"
        "            return 0\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("target", ["slots[_raptor_unsupported_target]", "slots[(index := 0)]"],
                         ids=["lambda-index", "assignment-index"])
def test_unsupported_augmented_target_invalidates_complete_child(target):
    source = f"raw\ndef child():\n {target} += 1"
    assert _bounded_body_expression_loads(parse_target_refusal_fixture(source).body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            raw.member += 1\n            return 0\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
