"""Body imports bind names without granting authority about import effects."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<import-body>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("statement", ["import math", "import math as other",
                                       "import os.path", "from math import pi",
                                       "from .module import value"],
                         ids=["module", "alias", "dotted", "from", "relative"])
def test_import_body_retains_enclosing_cell(statement):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {statement}\n"
        "        return raw\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_import_body_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n"
        "        import math\n        return raw\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("statement", ["import math as raw", "from math import pi as raw",
                                       "import raw.member", "from module import raw",
                                       "if False:\n            import math as raw"],
                         ids=["module-alias", "from-alias", "dotted-root", "from-name", "unreachable"])
def test_whole_function_import_bindings_mask_outer_cell(statement):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {statement}\n"
        "        return raw\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", ["import math\n global raw\n return raw",
                                  "from module import *\n return raw",
                                  "from __future__ import annotations\n return raw"],
                         ids=["declaration", "star", "future"])
def test_unsupported_import_body_tree_stays_excluded(body):
    # Parser-only refusal controls: function star/future imports cannot compile.
    assert _bounded_body_expression_loads(ast.parse("def nested():\n " + body).body[0].body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n"
        "        import math\n        return raw\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
