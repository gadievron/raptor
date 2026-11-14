"""Unnamed child exception blocks expose lexical cells without handler execution."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<try-child-body>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["try:\n                raw\n            finally:\n                pass",
                                  "try:\n                pass\n            finally:\n                raw",
                                  "try:\n                pass\n            except raw:\n                pass",
                                  "try:\n                pass\n            except Exception:\n                raw",
                                  "try:\n                pass\n            except Exception:\n                pass\n            else:\n                raw",
                                  "try:\n                raw\n            except:\n                pass",
                                  "try:\n                pass\n            except ValueError:\n                pass\n            except raw:\n                pass"],
                         ids=["try", "finally", "handler-type", "handler-body", "else", "bare", "multiple"])
def test_returned_function_retains_try_child_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child():\n            {body}\n"
        "            return 0\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_try_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            try:\n                return raw\n            finally:\n                pass\n"
        "        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [("", "try:\n                pass\n            finally:\n                pass"),
                                       ("raw", "try:\n                raw\n            finally:\n                pass"),
                                       ("", "try:\n                raw\n            finally:\n                if False:\n                    raw = 0")],
                         ids=["constant", "parameter", "unreachable-binding"])
def test_whole_child_bindings_mask_try_reads(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n            {body}\n"
        "            return 0\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", ["try:\n  pass\n except Exception as error:\n  pass",
                                  "try:\n  pass\n except* Exception:\n  raw",
                                  "try:\n  pass\n finally:\n  import module"],
                         ids=["named-handler", "group", "later-import"])
def test_unsupported_child_exception_tree_invalidates_complete_body(body):
    assert _bounded_body_expression_loads(ast.parse("raw\ndef child():\n " + body).body) is None


def test_outer_caught_payload_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    try:\n        pass\n    except Exception as error:\n        pass\n"
        "    def nested():\n        def child():\n            try:\n                raw\n"
        "            finally:\n                pass\n        return child\n    return nested()\n"
    )["handle"]
    assert result.summary_unknown_reason == "caught exception payload is not modelled"


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            try:\n                return raw\n            finally:\n                pass\n"
        "        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
