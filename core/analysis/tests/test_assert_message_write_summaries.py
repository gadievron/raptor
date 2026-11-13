"""Assertion messages cannot establish an unconditional local overwrite."""

import pytest

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summary(body):
    source = "def handle(raw, flag):\n" + "".join(
        f"    {line}\n" for line in body.splitlines()
    )
    compile(source, "<assert-message-fixture>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)["handle"]


@pytest.mark.parametrize("message", ["(tmp := 0)", "(lambda value=(tmp := 0): value)"])
def test_passing_assert_message_write_refuses_a_known_summary(message):
    result = summary(f"tmp = raw\nassert True, {message}\nreturn tmp")
    assert result.summary_unknown
    assert result.summary_unknown_reason == "assertion message conditionally assigns an enclosing-frame name"


def test_caught_assertion_message_write_also_refuses():
    result = summary(
        "tmp = raw\ntry:\n    assert flag, (tmp := 0)\n"
        "except AssertionError:\n    pass\nreturn tmp"
    )
    assert result.summary_unknown


@pytest.mark.parametrize("statement", [
    "assert flag",
    "assert flag, 'message'",
    "assert (tmp := raw)",
    "assert flag, (lambda: (tmp := 0))",
])
def test_assert_test_and_lambda_local_message_writes_keep_existing_flow(statement):
    result = summary(f"tmp = raw\n{statement}\nreturn tmp")
    assert not result.summary_unknown
    assert result.param_taints_return(0)
