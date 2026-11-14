"""Narrow local annotations distinguish retained cells from annotation text."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<annotated-body-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("prefix", ["", "from __future__ import annotations\n"],
                         ids=["ordinary", "future"])
@pytest.mark.parametrize("body", ["value: object = raw", "raw.member: object",
                                  "slots[raw]: object", "raw.member: object = 0",
                                  "slots[raw]: object = 0"],
                         ids=["rhs", "member", "index", "member-value", "index-value"])
def test_returned_function_retains_annotated_target_or_value(prefix, body):
    result = summaries(
        prefix + f"def handle(raw, slots):\n    def nested():\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_annotated_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        value: object = raw\n"
        "        return value\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("body", ["value: raw", "value: 'raw'", "(raw): object",
                                  "raw: object = 0", "raw.member: object\n        raw = 0"],
                         ids=["bare-annotation", "string-annotation", "parenthesised-name",
                              "own-value", "own-later-binding"])
def test_annotation_text_or_own_binding_does_not_capture(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


def test_parameter_masks_annotated_target():
    result = summaries(
        "def handle(raw):\n    def nested(raw=0):\n        raw.member: object\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("statement", ["value: (lambda: raw)", "value: [raw for item in ()]",
                                       "slots[(lambda: (yield raw))()]: object = 0"],
                         ids=["lambda-annotation", "comprehension-annotation", "scoped-target"])
def test_unsupported_annotation_or_target_invalidates_earlier_capture(statement):
    assert _bounded_body_expression_loads(ast.parse(f"raw\n{statement}").body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        value: object = raw\n"
        "        return value\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
