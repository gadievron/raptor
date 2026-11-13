"""Initial binary views keep source-language and representation limits explicit."""

import pytest

from core.audit.binary_context import assemble_binary_context
from core.audit.context import format_context_for_prompt
from packages.ghidra.model import REDatabase, REFunction


@pytest.mark.parametrize("bucket", [None, "glance"])
def test_initial_pseudocode_discloses_approximation_in_full_and_glance(tmp_path, bucket):
    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned inert pseudocode fixture")
    body = "int f(int n) { return n + 1; }"
    function = REFunction(name="f", address=4096, size=32, source_tool="fixture", decompilation=body)
    db = REDatabase(source_tool="fixture", binary_path=str(target), functions=[function])
    checklist = {"files": [{"path": "binary:owned", "items": [
        {"name": "f", "kind": "function", "address": 4096, "size": 32}]}]}
    ctx = assemble_binary_context(target_path=target, file_path="binary:owned",
        function_name="f", checklist=checklist, db=db, out_dir=tmp_path / "out", cached_only=True)
    if bucket is not None:
        ctx["triage_bucket"] = bucket
    prompt = format_context_for_prompt(ctx)
    assert "### Source (decompilation at 0x1000)" in prompt
    assert "Recovered pseudocode is an approximate analysis view, not original source" in prompt
    assert "Source-language rules alone do not establish binary execution consequences" in prompt
    assert body in prompt


def test_actual_source_heading_does_not_acquire_binary_approximation():
    ctx = {"file": "f.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": "int f(int n) { return n + 1; }", "metadata": {},
           "callers": [], "callees": [], "sinks": [], "trust_surface": {}}
    prompt = format_context_for_prompt(ctx)
    assert "### Source (lines 1-1)" in prompt
    assert "Recovered pseudocode" not in prompt
