"""Initial recovered-type context keeps its representation limits visible."""

from core.audit.binary_context import assemble_binary_context
from core.audit.context import format_context_for_prompt
from packages.ghidra.model import REDatabase, REFunction, REType


def test_initial_binary_types_are_labelled_recovered_not_source_declarations(tmp_path):
    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned inert recovered-type fixture")
    function = REFunction(name="f", address=4096, size=32, source_tool="fixture",
        signature="unsigned f(Packet *p)", decompilation="unsigned f(Packet *p) { return p->length; }")
    db = REDatabase(source_tool="fixture", binary_path=str(target), functions=[function],
        types=[REType(name="Packet", kind="struct", source_tool="fixture", fields=[
            {"name": "length", "type": "unsigned int", "offset": None}])])
    checklist = {"files": [{"path": "binary:owned", "items": [
        {"name": "f", "kind": "function", "address": 4096, "size": 32}]}]}
    ctx = assemble_binary_context(target_path=target, file_path="binary:owned",
        function_name="f", checklist=checklist, db=db, out_dir=tmp_path / "out", cached_only=True)
    assert ctx["type_definitions"][0]["name"] == "Packet"
    prompt = format_context_for_prompt(ctx)
    assert "### Recovered binary type definitions" in prompt
    assert "not source declarations or verification evidence" in prompt
    assert "Missing offsets, sizes, packing and signedness remain unknown" in prompt
    assert "unsigned int length" in prompt
    assert "\n### Type definitions\n" not in prompt
    assert "ghidra-types:0" not in prompt


def test_source_type_definitions_retain_source_provenance():
    ctx = {"file": "handler.c", "function": "f", "line_start": 1,
        "source": "unsigned f(Packet *p) { return p->length; }", "metadata": {},
        "callers": [], "callees": [], "sinks": [], "trust_surface": {},
        "type_definitions": [{"name": "Packet", "file": "packet.h", "line": 7,
                              "source": "struct Packet { unsigned length; };"}]}
    prompt = format_context_for_prompt(ctx)
    assert "\n### Type definitions\n" in prompt
    assert "packet.h:7" in prompt
    assert "Recovered binary type definitions" not in prompt
