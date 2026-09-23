"""Checklist items carry the name-provenance minted at the import seam.

Downstream consumers (journal keys, name-keyed joins, hypothesis
matching) read checklist items, not the REDatabase — the tag must
survive onto the item and into its metadata (the only bag the gap
loop carries through to context assembly and the journal), and the
run-level ``binary_stats`` must report an honest auto-named ratio
plus the per-binary provenance block.
"""

from __future__ import annotations

from pathlib import Path

from core.inventory.binary_builder import build_binary_checklist
from packages.ghidra.model import REDatabase, REFunction


def _db(functions, imports=None, binary_path="/nonexistent/demo"):
    return REDatabase(
        source_tool="r2",
        binary_path=binary_path,
        architecture="x86 64-bit",
        functions=functions,
        imports=imports or [],
    )


def _items(checklist):
    return checklist["files"][0]["items"]


class TestItemProvenance:
    def test_tags_ride_on_item_and_metadata(self):
        db = _db([
            REFunction(name="main", address=0x1000, size=64,
                       source_tool="r2", name_provenance="dwarf"),
            REFunction(name="fcn.00402000", address=0x2000, size=64,
                       is_auto_named=True, source_tool="r2",
                       name_provenance="tool_synthetic"),
        ])
        checklist = build_binary_checklist(db, include_auto_named=True)
        by_name = {i["name"]: i for i in _items(checklist)}

        assert by_name["main"]["name_provenance"] == "dwarf"
        assert by_name["main"]["metadata"]["name_provenance"] == "dwarf"
        assert (
            by_name["fcn.00402000"]["name_provenance"] == "tool_synthetic"
        )

    def test_legacy_auto_named_without_tag_reads_tool_synthetic(self):
        """A database predating the provenance field: auto-named
        functions are tool placeholders by construction."""
        db = _db([
            REFunction(name="fcn.00402000", address=0x2000, size=64,
                       is_auto_named=True, source_tool="r2"),
        ])
        checklist = build_binary_checklist(db, include_auto_named=True)
        assert (
            _items(checklist)[0]["name_provenance"] == "tool_synthetic"
        )

    def test_unknown_provenance_stays_empty_not_invented(self):
        db = _db([
            REFunction(name="handler", address=0x3000, size=64,
                       source_tool="r2"),
        ])
        checklist = build_binary_checklist(db, include_auto_named=True)
        assert _items(checklist)[0]["name_provenance"] == ""


class TestBinaryStatsHonesty:
    def test_auto_named_ratio_honest_on_stripped_import(self):
        """With every function tool-synthetic the ratio must read
        1.0 — a fully stripped import must not report 0.00."""
        db = _db([
            REFunction(name=f"fcn.0040{i}000", address=0x400000 + i,
                       size=64, is_auto_named=True, source_tool="r2",
                       name_provenance="tool_synthetic")
            for i in range(4)
        ])
        checklist = build_binary_checklist(db, include_auto_named=True)
        stats = checklist["binary_stats"]
        assert stats["auto_named_ratio"] == 1.0
        assert stats["name_provenance_counts"] == {"tool_synthetic": 4}

    def test_provenance_census_counts_every_class(self):
        db = _db([
            REFunction(name="a", address=0x1000, size=64,
                       name_provenance="dwarf"),
            REFunction(name="b", address=0x2000, size=64,
                       name_provenance="dwarf"),
            REFunction(name="c", address=0x3000, size=64,
                       name_provenance="symtab"),
            REFunction(name="d", address=0x4000, size=64),
        ])
        checklist = build_binary_checklist(db, include_auto_named=True)
        assert checklist["binary_stats"]["name_provenance_counts"] == {
            "dwarf": 2, "symtab": 1, "unknown": 1,
        }

    def test_fortification_read_from_imports_without_tools(self):
        """__*_chk imports prove fortification from the already-
        imported symbol list — no readelf needed, so the fact
        survives on tool-less runners."""
        db = _db(
            [REFunction(name="main", address=0x1000, size=64)],
            imports=[{"name": "__strcpy_chk"}, {"name": "printf"}],
        )
        checklist = build_binary_checklist(db, include_auto_named=True)
        block = checklist["binary_stats"]["provenance"]
        assert block["fortified"] is True
        assert block["fortified_imports"] == ["__strcpy_chk"]

    def test_missing_binary_degrades_probe_honestly(self):
        db = _db([REFunction(name="main", address=0x1000, size=64)],
                 binary_path="/nonexistent/demo")
        checklist = build_binary_checklist(db, include_auto_named=True)
        block = checklist["binary_stats"]["provenance"]
        assert block["probe"] == "unavailable"
        assert block["has_dwarf"] is None
        assert block["stripped"] is None

    def test_probe_populates_block_for_real_binary(
            self, monkeypatch, tmp_path):
        import core.analysis.binary_provenance as bp

        binary = tmp_path / "demo"
        binary.write_bytes(b"\x7fELF" + b"\0" * 12)
        monkeypatch.setattr(bp, "probe_binary", lambda p: {
            "probe": "readelf", "build_id": "abcd1234",
            "has_dwarf": True, "has_symtab": True,
            "has_dynsym": True, "stripped": False,
        })
        db = _db([REFunction(name="main", address=0x1000, size=64)],
                 binary_path=str(binary))
        checklist = build_binary_checklist(
            db, binary_path=Path(binary), include_auto_named=True,
        )
        block = checklist["binary_stats"]["provenance"]
        assert block["build_id"] == "abcd1234"
        assert block["stripped"] is False


class TestDuplicateNameDisambiguation:
    def test_forged_symtab_literal_at_suffix_does_not_collide(self):
        # A symtab entry literally named "dup@0x2000" collides with the
        # minted disambiguation of a duplicate "dup" at 0x2000 — the
        # journal/coverage key namespace must stay collision-free even
        # against a forged symbol table.
        db = _db([
            REFunction(name="dup", address=0x1000, size=64,
                       source_tool="r2"),
            REFunction(name="dup@0x2000", address=0x3000, size=64,
                       source_tool="r2"),
            REFunction(name="dup", address=0x2000, size=64,
                       source_tool="r2"),
        ])
        checklist = build_binary_checklist(db, include_auto_named=True)
        names = [i["name"] for i in _items(checklist)]
        assert len(names) == len(set(names)), names

    def test_ordinary_duplicates_get_address_suffix(self):
        db = _db([
            REFunction(name="local_init", address=0x1000, size=64,
                       source_tool="r2"),
            REFunction(name="local_init", address=0x2000, size=64,
                       source_tool="r2"),
        ])
        checklist = build_binary_checklist(db, include_auto_named=True)
        names = sorted(i["name"] for i in _items(checklist))
        assert names == ["local_init", "local_init@0x2000"]
