"""Ambiguous legacy inventory names cannot choose a binary occurrence."""
import hashlib

import pytest

from core.audit.binary_context import assemble_binary_context
from core.audit.knowledge_calls import KnowledgeCallRefused
from core.audit.review_availability import require_binary_implementation
from core.inventory.binary_builder import binary_path_key
from packages.ghidra.model import REDatabase, REFunction


def test_duplicate_inventory_name_cannot_select_the_first_address(tmp_path):
    target = tmp_path / "owned.bin"
    contents = b"owned ambiguous occurrence fixture, not executable"
    target.write_bytes(contents)
    key = binary_path_key(target)
    db = REDatabase(source_tool="fixture", binary_path=str(target),
        metadata={"binary_sha256": hashlib.sha256(contents).hexdigest()},
        functions=[REFunction(name="shared", address=address, size=32, source_tool="fixture",
                              decompilation=f"return {address};") for address in (4096, 8192)])
    checklist = {"files": [{"path": key, "items": [
        {"name": "shared", "address": address, "size": 32} for address in (4096, 8192)]}]}
    ctx = assemble_binary_context(target_path=target, file_path=key,
                                  function_name="shared", checklist=checklist, db=db)
    assert ctx["representation"] == "unknown", "ambiguous inventory borrowed the first occurrence"
    assert ctx["address"] is None
    with pytest.raises(KnowledgeCallRefused, match="binary_implementation_unavailable"):
        require_binary_implementation(ctx)
