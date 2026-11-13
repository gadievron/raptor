"""Deferred generator writes cannot certify a local-value taint summary."""

import pytest

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summary(body):
    source = "def handle(raw, rows):\n" + "".join(
        f"    {line}\n" for line in body.splitlines()
    )
    compile(source, "<summary-fixture>", "exec")  # Validate syntax without execution.
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)["handle"]


@pytest.mark.parametrize("body", [
    "tmp = raw\ndelayed = ((tmp := 0) for item in rows)\nreturn tmp",
    "tmp = 0\ndelayed = ((tmp := raw) for item in rows)\nnext(delayed)\nreturn tmp",
    "tmp = raw\ndelayed = (item for item in rows if (tmp := 0))\nreturn tmp",
    "tmp = raw\ndelayed = (item for row in rows for item in row if (tmp := item))\nreturn tmp",
    "tmp = raw\ndelayed = ((lambda value=(tmp := 0): value) for item in rows)\nreturn tmp",
])
def test_deferred_enclosing_writes_refuse_a_known_summary(body):
    result = summary(body)
    assert result.summary_unknown
    assert result.summary_unknown_reason == "generator defers an enclosing-frame assignment"


@pytest.mark.parametrize("expression", [
    "(item for item in rows)",
    "((lambda: (tmp := 0)) for item in rows)",
    "[(tmp := item) for item in rows]",
])
def test_other_generator_and_eager_comprehension_forms_keep_existing_summary(expression):
    result = summary(f"tmp = raw\ndelayed = {expression}\nreturn raw")
    assert not result.summary_unknown
    assert (0, "", -1) in result.return_effects


def test_nested_function_generator_does_not_poison_its_enclosing_summary():
    result = summary(
        "def nested():\n"
        "    delayed = ((local := 0) for item in rows)\n"
        "    return delayed\n"
        "return raw"
    )
    assert not result.summary_unknown
    assert (0, "", -1) in result.return_effects
