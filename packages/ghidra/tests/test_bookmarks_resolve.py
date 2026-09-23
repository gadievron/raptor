"""bookmarks_bridge._resolve_function rides the model's address index.

The per-bookmark linear scan it replaces was O(bookmarks x functions)
against a hostile-sized cache — the class the model's bisect index
(function_containing_address) was built for, twice.
"""

from __future__ import annotations

from unittest.mock import patch

from packages.ghidra.bookmarks_bridge import _resolve_function
from packages.ghidra.model import REDatabase, REFunction


def _db() -> REDatabase:
    return REDatabase(source_tool="ghidra", functions=[
        REFunction(name="alpha", address=0x1000, size=0x100),
        REFunction(name="beta", address=0x2000, size=0x80),
    ])


def test_body_address_resolves_via_the_index():
    db = _db()
    with patch.object(
        REDatabase, "function_containing_address",
        wraps=db.function_containing_address,
    ) as idx:
        assert _resolve_function(0x1040, {}, db) == "alpha"
    idx.assert_called_once_with(0x1040)


def test_entry_map_short_circuits():
    db = _db()
    assert _resolve_function(0x2000, {0x2000: "beta"}, db) == "beta"


def test_unmapped_address_falls_back_to_synthetic_name():
    assert _resolve_function(0x9999, {}, _db()) == "sub_9999"


def test_non_int_address_is_empty():
    assert _resolve_function("0x1000", {}, _db()) == ""
