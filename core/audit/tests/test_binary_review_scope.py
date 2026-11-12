"""Owned binary bytes bind dispatch; no decoder or provider executes."""
from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.binary_context import assemble_binary_context
from core.audit.knowledge_calls import KnowledgeCallRefused
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig
from core.inventory.binary_builder import binary_path_key
from core.llm.providers import StructuredResponse
from packages.ghidra.model import REDatabase, REFunction


def test_changed_binary_after_context_assembly_cannot_reach_reviewer(tmp_path):
    target = tmp_path / "owned.bin"
    target.write_bytes(b"first owned module, not executable")
    db = REDatabase(source_tool="ghidra", binary_path=str(target), functions=[
        REFunction(name="f", address=4096, size=32, source_tool="ghidra",
                   decompilation="unsigned f(unsigned n) { return n + 1; }")])
    context = assemble_binary_context(target_path=target, file_path=binary_path_key(target),
                                      function_name="f", db=db)
    calls = []
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            return StructuredResponse(result={"status": "clean", "body": "Captured judgment."},
                                      raw="", cost=.1, model="captured")
    review = make_review_fn(Client(), system_prompt="Review supplied implementation.",
        schema={"type": "object", "properties": {"status": {"type": "string"},
            "body": {"type": "string"}}, "required": ["status", "body"]}, escalate_clean=False)
    target.write_bytes(b"other owned module, not executable")
    failure = None
    try:
        review(context, OrchestratorConfig(target_path=target, out_dir=tmp_path / "out"))
    except KnowledgeCallRefused as exc:
        failure = exc
    assert calls == [], "reviewer consumed an implementation view after module bytes changed"
    assert failure is not None and failure.reason == "binary_module_changed_or_unavailable"


@pytest.mark.parametrize("change", ["replace", "restored_mtime", "restore_bytes", "remove"])
def test_original_module_stamp_cannot_be_refreshed_after_change(tmp_path, change):
    import os
    from core.audit.binary_review_scope import capture_binary_module

    target = tmp_path / "owned.bin"
    original = b"owned first bytes"
    target.write_bytes(original)
    snapshot = capture_binary_module(target)
    assert snapshot is not None and snapshot.current()
    before = target.stat()
    if change == "replace":
        replacement = tmp_path / "replacement"
        replacement.write_bytes(original)
        replacement.replace(target)
    elif change == "remove":
        target.unlink()
    else:
        target.write_bytes(b"owned other bytes")
        if change == "restore_bytes":
            target.write_bytes(original)
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert not snapshot.current()


def test_module_change_during_context_assembly_is_not_recaptured(tmp_path, monkeypatch):
    import core.audit.binary_context as binary_context
    from core.audit.review_availability import require_binary_implementation

    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned original module")
    db = REDatabase(source_tool="ghidra", binary_path=str(target), functions=[
        REFunction(name="f", address=4096, size=32, source_tool="ghidra",
                   decompilation="unsigned f(unsigned n) { return n + 1; }")])
    read_source = binary_context._read_binary_source
    def changing_source(*args, **kwargs):
        source = read_source(*args, **kwargs)
        target.write_bytes(b"owned replacement module")
        return source
    monkeypatch.setattr(binary_context, "_read_binary_source", changing_source)
    context = assemble_binary_context(target_path=target, file_path=binary_path_key(target),
                                      function_name="f", db=db)
    assert context["representation"] == "decompilation"
    assert context["_binary_module_snapshot"] is None
    with pytest.raises(KnowledgeCallRefused, match="binary_module_changed_or_unavailable"):
        require_binary_implementation(context)


def test_relative_module_path_keeps_its_original_owned_binding(tmp_path, monkeypatch):
    from core.audit.binary_review_scope import capture_binary_module
    from core.audit.review_availability import require_binary_implementation

    monkeypatch.chdir(tmp_path)
    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned bytes")
    snapshot = capture_binary_module("owned.bin")
    assert snapshot is not None
    db = REDatabase(source_tool="ghidra", binary_path=str(target), functions=[
        REFunction(name="f", address=4096, size=32, source_tool="ghidra",
                   decompilation="unsigned f(unsigned n) { return n + 1; }")])
    context = assemble_binary_context(target_path=Path("owned.bin"), file_path=binary_path_key(target),
                                      function_name="f", db=db)
    assert context["target_path"] == "owned.bin"
    require_binary_implementation(context)
    from core.audit.tests.test_binary_review_availability import _reviewer
    review, calls = _reviewer()
    outcome = review(context, OrchestratorConfig(target_path=target, out_dir=tmp_path / "out"))
    assert len(calls) == 1 and outcome.status == "clean"
    context["_binary_module_snapshot"] = dict(snapshot.__dict__)
    with pytest.raises(KnowledgeCallRefused, match="binary_module_changed_or_unavailable"):
        require_binary_implementation(context)
    context["_binary_module_snapshot"] = snapshot
    context["target_path"] = "other.bin"
    with pytest.raises(KnowledgeCallRefused, match="binary_module_changed_or_unavailable"):
        require_binary_implementation(context)


@pytest.mark.parametrize("kind", ["missing", "directory", "project"])
def test_unselected_or_unavailable_module_remains_unknown(tmp_path, kind):
    from core.audit.binary_review_scope import capture_binary_module

    path = tmp_path / ("owned.gpr" if kind == "project" else "owned")
    if kind == "directory":
        path.mkdir()
    elif kind == "project":
        path.write_bytes(b"project metadata is not a selected module")
    assert capture_binary_module(path) is None
