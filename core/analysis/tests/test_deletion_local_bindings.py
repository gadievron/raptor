"""Deletion targets establish local identity without executing the deletion."""

import ast
import symtable

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import (
    build_python_module_callgraph,
    function_scope_bindings,
    local_binding_names,
)
from core.analysis.taint_summaries import build_taint_summaries


@pytest.mark.parametrize("body,expected", [
    ("del raw", {"raw"}), ("del raw, other", {"raw", "other"}),
    ("del (raw, [other])", {"raw", "other"}),
    ("if False:\n        del raw", {"raw"}),
    ("del raw.member, slots[raw]", set()),
    ("def child():\n        del raw", {"child"}),
], ids=["bare", "multiple", "nested-target", "unreachable", "indirect", "nested-function"])
def test_deletion_bindings_match_compiler_scope(body, expected):
    source = f"def handle():\n    {body}\n"
    compile(source, "<delete-binding>", "exec", dont_inherit=True)
    table = next(child for child in symtable.symtable(
        source, "<delete-binding>", "exec"
    ).get_children() if child.get_name() == "handle")
    actual = {symbol.get_name() for symbol in table.get_symbols() if symbol.is_local()}
    assert actual == expected
    assert local_binding_names(ast.parse(source).body[0]) == frozenset(expected)


def test_unreachable_delete_refuses_imported_sanitizer_identity():
    source = (
        "import html\ndef handle(raw):\n    if False:\n        del html\n"
        "    return html.escape(raw)\n"
    )
    compile(source, "<delete-sanitizer-shadow>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summary = build_taint_summaries(graph, source)["handle"]
    assert summary.param_taints_return(0)
    assert not _param_cleanly_sanitized(summary, 0, {"html.escape"})
    assert all(effect[1] != "html.escape" for effect in summary.return_effects)


def test_nested_delete_does_not_shadow_enclosing_import():
    source = (
        "import html\ndef handle(raw):\n    def child():\n        del html\n"
        "    return html.escape(raw)\n"
    )
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summary = build_taint_summaries(graph, source)["handle"]
    assert _param_cleanly_sanitized(summary, 0, {"html.escape"})


def test_explicit_global_stays_outside_visible_function_bindings():
    tree = ast.parse("def handle():\n    global raw\n    del raw\n")
    fn = tree.body[0]
    # The helper retains its conservative declaration policy; visible scopes
    # apply the explicit global exclusion as they do for assignment targets.
    assert "raw" in local_binding_names(fn)
    assert "raw" not in function_scope_bindings(tree)[fn]


def test_nonlocal_delete_preserves_existing_summary_refusal():
    source = (
        "def outer(raw):\n    def handle():\n        nonlocal raw\n        del raw\n"
        "        return 0\n    return handle\n"
    )
    compile(source, "<nonlocal-delete>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    result = build_taint_summaries(graph, source)
    assert result["outer"].summary_unknown
    assert "nonlocal" in result["outer"].summary_unknown_reason
