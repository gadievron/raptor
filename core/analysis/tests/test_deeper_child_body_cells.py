"""Deeper lexical frames preserve default ownership and whole-frame binding masks."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<deeper-child-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(body="return raw", child_header="", grand_header="", asynchronous=False):
    grand = "async def" if asynchronous else "def"
    return (f"def handle(raw):\n    def nested():\n        def child({child_header}):\n"
            f"            {grand} grandchild({grand_header}):\n" + indent(body, "                ")
            + "\n            return grandchild\n        return child\n    return nested\n")


@pytest.mark.parametrize("body", ["return raw", "box[raw] = 0\nreturn 0", "del box[raw]\nreturn 0",
                                  "with manager as box[raw]:\n pass\nreturn 0",
                                  "for box[raw] in ():\n pass\nreturn 0",
                                  "match 0:\n case raw():\n  pass\nreturn 0",
                                  "match 0:\n case {raw.key: _}:\n  pass\nreturn 0",
                                  "try:\n pass\nexcept* raw:\n pass\nreturn 0"],
                         ids=["value", "store-index", "delete-index", "context-target", "loop-target", "class-pattern", "mapping-key", "handler-type"])
def test_deeper_reads_retain_enclosing_cell(body):
    assert summaries(source_for(body))["handle"].summary_unknown


def test_deeper_cell_keeps_caller_raw_flow():
    source = source_for().replace("def handle(raw):", "def helper(raw):").replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("child_header,grand_header,body", [
    ("raw", "", "return raw"), ("", "raw", "return raw"), ("", "raw=0", "return raw"),
    ("", "", "raw\nif False:\n raw = 0\nreturn 0"),
    ("", "", "import math as raw\nreturn raw"), ("", "", "del raw\nreturn 0"),
], ids=["intermediate-parameter", "deep-parameter", "deep-default-mask", "unreachable-store", "import", "delete"])
def test_complete_frame_bindings_mask_deeper_reads(child_header, grand_header, body):
    assert not summaries(source_for(body, child_header, grand_header))["handle"].summary_unknown


@pytest.mark.parametrize("header", ["value=raw", "*, value=raw", "value=(lambda: raw)", "value=(tmp := raw)"],
                         ids=["positional", "keyword", "lambda", "default-walrus-read"])
def test_deeper_defaults_read_defining_frame(header):
    assert summaries(source_for("return value", grand_header=header))["handle"].summary_unknown


def test_default_walrus_binds_defining_frame():
    assert not summaries(source_for("return raw", grand_header="value=(raw := source)"))["handle"].summary_unknown


def test_sibling_frame_bindings_do_not_leak():
    source = "def handle(raw):\n    def nested():\n        def first(raw):\n            def inside():\n                return raw\n            return inside\n        def second():\n            def inside():\n                return raw\n            return inside\n        return second\n    return nested\n"
    assert summaries(source)["handle"].summary_unknown


def test_deeper_async_function_keeps_lexical_cell():
    assert summaries(source_for(asynchronous=True))["handle"].summary_unknown


@pytest.mark.parametrize("definition", ["def deeper(value: raw):\n return 0", "@raw\ndef deeper():\n return 0",
                                        "def deeper():\n global raw\n return raw", "def deeper():\n 'docs'"],
                         ids=["annotation", "decorator", "unsupported-body", "docstring-only"])
def test_unsupported_deeper_tree_invalidates_complete_scan(definition):
    source = "raw\ndef child():\n " + definition.replace("\n", "\n ")
    tree = ast.parse(source)
    before = ast.dump(tree)
    assert _bounded_body_expression_loads(tree.body) is None
    assert ast.dump(tree) == before


def test_deeper_nonlocal_keeps_prior_reason():
    source = source_for("nonlocal raw\nreturn raw")
    assert summaries(source)["handle"].summary_unknown_reason == "declares nonlocal raw"
