"""Exception-block cells are lexical facts rather than handler execution proofs."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<exception-block-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", [
    "try:\n            raw\n        finally:\n            pass",
    "try:\n            pass\n        finally:\n            raw",
    "try:\n            pass\n        except raw:\n            pass",
    "try:\n            pass\n        except Exception:\n            raw",
    "try:\n            pass\n        except Exception:\n            pass\n        else:\n            raw",
    "try:\n            raw\n        except:\n            pass",
    "try:\n            pass\n        except ValueError:\n            pass\n        except raw:\n            pass",
], ids=["try-body", "finally", "handler-type", "handler-body", "else", "bare-handler", "multiple"])
def test_returned_function_retains_exception_block_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_exception_block_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        try:\n"
        "            return raw\n        finally:\n            pass\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [
    ("", "try:\n            pass\n        finally:\n            pass"),
    ("raw=0", "try:\n            raw\n        finally:\n            pass"),
    ("", "try:\n            raw\n        finally:\n            if False:\n                raw = 0"),
], ids=["constant", "parameter", "unreachable-binding"])
def test_own_bindings_mask_exception_block_cells(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested({header}):\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", [
    "try:\n pass\nexcept Exception as error:\n pass",
    "try:\n pass\nexcept* Exception:\n raw",
    "try:\n pass\nfinally:\n global unsupported",
], ids=["bound-handler", "exception-group", "later-declaration"])
def test_unsupported_exception_tree_invalidates_earlier_capture(body):
    assert _bounded_body_expression_loads(ast.parse(f"raw\n{body}").body) is None


def test_caught_payload_keeps_outer_scope_prior_reason():
    result = summaries(
        "def handle(raw):\n    try:\n        pass\n    except Exception as error:\n        pass\n"
        "    def nested():\n        try:\n            raw\n        finally:\n            pass\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown_reason == "caught exception payload is not modelled"


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        try:\n            return raw\n"
        "        finally:\n            pass\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
