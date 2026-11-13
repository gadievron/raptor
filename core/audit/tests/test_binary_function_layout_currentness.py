"""Audit contexts must select functions from their current parsed snapshot."""

import hashlib

from core.audit.binary_context import (
    _binary_callees, _prepare_function_layout, assemble_binary_context, database_projection_digest,
)
from packages.ghidra.model import REDatabase, REFunction, REXref


def test_same_length_function_replacement_supplies_current_body(tmp_path):
    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned inert function-layout fixture")
    old = REFunction(name="f", address=4096, size=32, source_tool="fixture",
                     decompilation="unsigned f(void) { return 1; }")
    db = REDatabase(source_tool="fixture", binary_path=str(target), functions=[old],
                    metadata={"binary_sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    assert db.function_by_address(4096) is old
    fresh = REFunction(name="f", address=4096, size=32, source_tool="fixture",
                       decompilation="unsigned f(void) { return 9; }")
    db.functions[0] = fresh
    checklist = {"files": [{"path": "binary:owned", "items": [
        {"name": "f", "kind": "function", "address": 4096, "size": 32}]}]}
    ctx = assemble_binary_context(target_path=target, file_path="binary:owned",
        function_name="f", checklist=checklist, db=db, out_dir=tmp_path / "out", cached_only=True)
    assert ctx["source"] == fresh.decompilation
    assert ctx["source"] != old.decompilation
    assert ctx["_binary_analysis_projection_sha256"] == database_projection_digest(db, 64 * 1024 * 1024)


def test_extent_change_invalidates_outgoing_call_ownership():
    caller = REFunction(name="caller", address=4096, size=32, source_tool="fixture")
    callee = REFunction(name="callee", address=8192, size=32, source_tool="fixture")
    db = REDatabase(source_tool="fixture", binary_path="owned.bin", functions=[caller, callee],
                    xrefs=[REXref(from_addr=4100, to_addr=8192, kind="call")])
    assert [row["name"] for row in _binary_callees(db, caller)] == ["callee"]
    old_adjacency = db._audit_xref_adjacency
    caller.size = 2
    assert _binary_callees(db, caller) == []
    assert db._audit_xref_adjacency is not old_adjacency


def test_unchanged_layout_reuses_index_and_body_edits_remain_live(monkeypatch):
    function = REFunction(name="f", address=4096, size=32, source_tool="fixture",
                          decompilation="old body")
    db = REDatabase(source_tool="fixture", binary_path="owned.bin", functions=[function])
    refreshes = []
    original = db.refresh_address_index

    def refresh():
        refreshes.append(True)
        original()

    monkeypatch.setattr(db, "refresh_address_index", refresh)
    version = _prepare_function_layout(db)
    index = db._addr_index_cache
    function.decompilation = "new body"
    assert _prepare_function_layout(db) == version
    assert db._addr_index_cache is index
    for address in range(4096, 4128):
        assert db.function_containing_address(address) is function
    assert db.function_by_address(4096).decompilation == "new body"
    assert refreshes == [True]
    function.address = 8192
    assert _prepare_function_layout(db) != version
    assert db.function_by_address(4096) is None
    assert db.function_by_address(8192) is function
    assert refreshes == [True, True]


def test_same_length_reordering_preserves_exact_lookup_first_entry_policy():
    first = REFunction(name="first", address=4096, size=32, source_tool="fixture")
    second = REFunction(name="second", address=4096, size=32, source_tool="fixture")
    db = REDatabase(source_tool="fixture", binary_path="owned.bin", functions=[first, second])
    _prepare_function_layout(db)
    assert db.function_by_address(4096) is first
    db.functions.reverse()
    _prepare_function_layout(db)
    assert db.function_by_address(4096) is second
