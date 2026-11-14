"""Module deletion invalidates written identities without executing source."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import (
    _module_rebound_names,
    build_python_module_callgraph,
    module_distrusted_roots,
)
from core.analysis.taint_summaries import build_taint_summaries


@pytest.mark.parametrize("statement", ["del name", "del name, other", "del (name, [other])",
                                       "if False:\n    del name"],
                         ids=["bare", "multiple", "nested-targets", "unreachable"])
def test_module_delete_targets_invalidate_both_identity_collectors(statement):
    tree = ast.parse(statement)
    expected = {"name", "other"} if "other" in statement else {"name"}
    assert _module_rebound_names(tree) == frozenset(expected)
    assert module_distrusted_roots(tree) == frozenset(expected)


@pytest.mark.parametrize("before", [False, True], ids=["after-def", "before-def"])
def test_deleted_function_refuses_clean_summary_join(before):
    definition = "def escape(raw):\n    return html.escape(raw)\n"
    source = "import html\n" + ("del escape\n" + definition if before else definition + "del escape\n")
    source += "def handle(raw):\n    return escape(raw)\n"
    compile(source, "<module-delete-function>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert "escape" in graph.rebound_names
    summary = build_taint_summaries(graph, source)["handle"]
    assert summary.param_taints_return(0)
    assert not _param_cleanly_sanitized(summary, 0, {"html.escape"})


def test_deleted_import_refuses_written_sanitizer_identity():
    source = "import html\ndel html\ndef handle(raw):\n    return html.escape(raw)\n"
    compile(source, "<module-delete-import>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert "html" in graph.distrusted_roots
    summary = build_taint_summaries(graph, source)["handle"]
    assert summary.param_taints_return(0)
    assert not _param_cleanly_sanitized(summary, 0, {"html.escape"})
    assert all(effect[1] != "html.escape" for effect in summary.return_effects)


@pytest.mark.parametrize("body", ["def child():\n    del html", "class Child:\n    del html"],
                         ids=["function", "class"])
def test_nested_body_deletion_does_not_invalidate_module_import(body):
    source = f"import html\n{body}\ndef handle(raw):\n    return html.escape(raw)\n"
    tree = ast.parse(source)
    assert _module_rebound_names(tree) == _module_rebound_names(ast.parse("import html"))
    assert "html" not in module_distrusted_roots(tree)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert _param_cleanly_sanitized(build_taint_summaries(graph, source)["handle"], 0, {"html.escape"})


def test_indirect_deletion_does_not_bind_target_base_or_index():
    tree = ast.parse("del obj.member, slots[index]")
    assert not _module_rebound_names(tree)
    assert not module_distrusted_roots(tree)


def test_imported_member_deletion_keeps_existing_whole_namespace_refusal():
    source = "import html\ndel html.escape\ndef handle(raw):\n    return html.escape(raw)\n"
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summary = build_taint_summaries(graph, source)["handle"]
    assert summary.summary_unknown
    assert summary.summary_unknown_reason.startswith("module namespace dynamically rebindable")
    assert not _param_cleanly_sanitized(summary, 0, {"html.escape"})


def test_plain_import_keeps_existing_sanitizer_identity():
    source = "import html\ndef handle(raw):\n    return html.escape(raw)\n"
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert _param_cleanly_sanitized(build_taint_summaries(graph, source)["handle"], 0, {"html.escape"})
