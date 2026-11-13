"""Skipped expression writes cannot kill incoming taint in known summaries."""

import pytest

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summary(expression):
    source = (
        "def handle(raw, flag):\n"
        "    tmp = raw\n"
        f"    unused = {expression}\n"
        "    return tmp\n"
    )
    compile(source, "<optional-write-fixture>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)["handle"]


@pytest.mark.parametrize("expression", [
    "[(tmp := 0) for item in []]",
    "{(tmp := 0) for item in []}",
    "{item: (tmp := 0) for item in []}",
    "{(tmp := 0): item for item in []}",
    "[(tmp := 0) for item in [1] if False]",
    "[item for item in [] if (tmp := 0)]",
    "(tmp := 0) if flag else None",
    "None if flag else (tmp := 0)",
    "flag and (tmp := 0)",
    "flag or (tmp := 0)",
    "0 > 1 > (tmp := 0)",
    "[(lambda value=(tmp := 0): value) for item in []]",
])
def test_optional_outer_writes_refuse_a_known_summary(expression):
    result = summary(expression)
    assert result.summary_unknown
    assert "conditionally assigns an enclosing-frame name" in result.summary_unknown_reason


@pytest.mark.parametrize("expression", [
    "(tmp := raw)",
    "(tmp := raw) and flag",
    "0 < (tmp := raw)",
    "flag if (tmp := raw) else None",
    "[(lambda: (tmp := 0)) for item in []]",
])
def test_unconditional_writes_and_lambda_local_writes_keep_existing_flow(expression):
    result = summary(expression)
    assert not result.summary_unknown
    assert result.param_taints_return(0)
