"""Tests for packages.ghidra.model — REDatabase and its components."""

from __future__ import annotations

import json

from packages.ghidra.model import (
    REComment,
    REDatabase,
    REFunction,
    RESegment,
    REType,
    REXref,
)


# --- REFunction -----------------------------------------------------------

class TestREFunction:
    def test_round_trip(self):
        f = REFunction(
            name="main", address=0x401000, size=128,
            signature="int (int, char **)",
            calling_convention="cdecl",
            is_auto_named=False, is_thunk=False, is_external=False,
            decompilation="int main(int argc, char **argv) { return 0; }",
            source_tool="ghidra",
        )
        d = f.to_dict()
        f2 = REFunction.from_dict(d)
        assert f2.name == "main"
        assert f2.address == 0x401000
        assert f2.size == 128
        assert f2.signature == "int (int, char **)"
        assert f2.decompilation is not None
        assert f2.source_tool == "ghidra"

    def test_optional_fields_absent(self):
        f = REFunction(name="f", address=0x1000, size=16, source_tool="r2")
        d = f.to_dict()
        assert "signature" not in d
        assert "decompilation" not in d
        assert "is_auto_named" not in d

    def test_auto_named_serialised(self):
        f = REFunction(
            name="FUN_00401000", address=0x401000, size=32,
            is_auto_named=True, source_tool="ghidra",
        )
        d = f.to_dict()
        assert d["is_auto_named"] is True


# --- REXref ----------------------------------------------------------------

class TestREXref:
    def test_round_trip(self):
        x = REXref(from_addr=0x1000, to_addr=0x2000, kind="call", source_tool="ghidra")
        d = x.to_dict()
        x2 = REXref.from_dict(d)
        assert x2.from_addr == 0x1000
        assert x2.to_addr == 0x2000
        assert x2.kind == "call"


# --- REType ----------------------------------------------------------------

class TestREType:
    def test_struct_round_trip(self):
        t = REType(
            name="packet_header",
            kind="struct",
            size=24,
            fields=[
                {"name": "length", "offset": 0, "type": "uint32_t"},
                {"name": "type", "offset": 4, "type": "uint16_t"},
                {"name": "data", "offset": 8, "type": "char[16]"},
            ],
            source_tool="ghidra",
        )
        d = t.to_dict()
        t2 = REType.from_dict(d)
        assert t2.name == "packet_header"
        assert len(t2.fields) == 3
        assert t2.size == 24

    def test_optional_fields(self):
        t = REType(name="my_enum", kind="enum", source_tool="ghidra")
        d = t.to_dict()
        assert "size" not in d
        assert "fields" not in d


# --- REComment -------------------------------------------------------------

class TestREComment:
    def test_round_trip(self):
        c = REComment(
            address=0x401050, function="parse_header",
            kind="plate", text="Vulnerable: unchecked memcpy length",
            source_tool="ghidra",
        )
        d = c.to_dict()
        c2 = REComment.from_dict(d)
        assert c2.function == "parse_header"
        assert c2.kind == "plate"
        assert "unchecked" in c2.text

    def test_no_function(self):
        c = REComment(
            address=0x1000, function=None, kind="eol",
            text="data ref", source_tool="r2",
        )
        d = c.to_dict()
        assert "function" not in d


# --- REDatabase ------------------------------------------------------------

def _make_db(tool: str, funcs=None, xrefs=None, types=None,
             comments=None, imports=None, strings=None) -> REDatabase:
    return REDatabase(
        source_tool=tool,
        architecture="x86_64",
        functions=funcs or [],
        xrefs=xrefs or [],
        types=types or [],
        comments=comments or [],
        imports=imports or [],
        strings=strings or [],
    )


class TestREDatabase:
    def test_round_trip_json(self):
        db = _make_db(
            "ghidra",
            funcs=[REFunction(name="main", address=0x1000, size=64, source_tool="ghidra")],
            xrefs=[REXref(from_addr=0x1000, to_addr=0x2000, kind="call", source_tool="ghidra")],
        )
        d = db.to_dict()
        raw = json.dumps(d)
        db2 = REDatabase.from_dict(json.loads(raw))
        assert db2.source_tool == "ghidra"
        assert len(db2.functions) == 1
        assert db2.functions[0].name == "main"
        assert len(db2.xrefs) == 1

    def test_auto_named_ratio(self):
        db = _make_db("ghidra", funcs=[
            REFunction(name="main", address=0x1000, size=16, is_auto_named=False, source_tool="ghidra"),
            REFunction(name="FUN_00402000", address=0x2000, size=16, is_auto_named=True, source_tool="ghidra"),
            REFunction(name="FUN_00403000", address=0x3000, size=16, is_auto_named=True, source_tool="ghidra"),
        ])
        assert abs(db.auto_named_ratio - 2 / 3) < 0.01

    def test_auto_named_ratio_empty(self):
        db = _make_db("ghidra")
        assert db.auto_named_ratio == 0.0

    def test_function_by_address(self):
        f1 = REFunction(name="a", address=0x1000, size=8, source_tool="ghidra")
        f2 = REFunction(name="b", address=0x2000, size=8, source_tool="ghidra")
        db = _make_db("ghidra", funcs=[f1, f2])
        assert db.function_by_address(0x1000).name == "a"
        assert db.function_by_address(0x2000).name == "b"
        assert db.function_by_address(0x9999) is None


class TestREDatabaseMerge:
    def test_functions_union_by_address_primary_wins(self):
        primary = _make_db("ghidra", funcs=[
            REFunction(name="parse_pkt", address=0x1000, size=64,
                       decompilation="void parse_pkt() { ... }",
                       source_tool="ghidra"),
        ])
        secondary = _make_db("r2", funcs=[
            REFunction(name="fcn.00001000", address=0x1000, size=60,
                       decompilation="void fcn_1000() { ... }",
                       source_tool="r2"),
            REFunction(name="fcn.00002000", address=0x2000, size=32,
                       source_tool="r2"),
        ])
        merged = primary.merge(secondary)
        assert len(merged.functions) == 2
        at_1000 = merged.function_by_address(0x1000)
        assert at_1000.name == "parse_pkt"
        assert at_1000.decompilation == "void parse_pkt() { ... }"
        at_2000 = merged.function_by_address(0x2000)
        assert at_2000.name == "fcn.00002000"
        assert at_2000.source_tool == "r2"

    def test_functions_sorted_by_address(self):
        primary = _make_db("ghidra", funcs=[
            REFunction(name="b", address=0x3000, size=8, source_tool="ghidra"),
        ])
        secondary = _make_db("r2", funcs=[
            REFunction(name="a", address=0x1000, size=8, source_tool="r2"),
        ])
        merged = primary.merge(secondary)
        assert [f.address for f in merged.functions] == [0x1000, 0x3000]

    def test_xrefs_deduped(self):
        primary = _make_db("ghidra", xrefs=[
            REXref(from_addr=0x1000, to_addr=0x2000, kind="call", source_tool="ghidra"),
        ])
        secondary = _make_db("r2", xrefs=[
            REXref(from_addr=0x1000, to_addr=0x2000, kind="call", source_tool="r2"),
            REXref(from_addr=0x1000, to_addr=0x3000, kind="data", source_tool="r2"),
        ])
        merged = primary.merge(secondary)
        assert len(merged.xrefs) == 2
        kinds = {(x.from_addr, x.to_addr, x.kind) for x in merged.xrefs}
        assert (0x1000, 0x2000, "call") in kinds
        assert (0x1000, 0x3000, "data") in kinds

    def test_types_primary_wins_on_conflict(self):
        ghidra_type = REType(name="header_t", kind="struct", size=24,
                             fields=[{"name": "len", "offset": 0, "type": "int"}],
                             source_tool="ghidra")
        r2_type = REType(name="header_t", kind="struct", size=16,
                         source_tool="r2")
        primary = _make_db("ghidra", types=[ghidra_type])
        secondary = _make_db("r2", types=[r2_type])
        merged = primary.merge(secondary)
        assert len(merged.types) == 1
        assert merged.types[0].size == 24
        assert merged.types[0].source_tool == "ghidra"

    def test_comments_both_kept(self):
        primary = _make_db("ghidra", comments=[
            REComment(address=0x1000, function="f", kind="plate",
                      text="vuln here", source_tool="ghidra"),
        ])
        secondary = _make_db("r2", comments=[
            REComment(address=0x1000, function="f", kind="eol",
                      text="r2 note", source_tool="r2"),
        ])
        merged = primary.merge(secondary)
        assert len(merged.comments) == 2

    def test_imports_union_by_address(self):
        primary = _make_db("ghidra", imports=[
            {"name": "recv", "address": 0x5000, "library": "libc.so"},
        ])
        secondary = _make_db("r2", imports=[
            {"name": "recv", "address": 0x5000, "library": "libc.so"},
            {"name": "send", "address": 0x5008, "library": "libc.so"},
        ])
        merged = primary.merge(secondary)
        assert len(merged.imports) == 2

    def test_metadata_primary_wins(self):
        primary = _make_db("ghidra")
        primary.metadata = {"ghidra_version": "11.1.2", "project": "test"}
        secondary = _make_db("r2")
        secondary.metadata = {"r2_version": "5.9.0", "project": "other"}
        merged = primary.merge(secondary)
        assert merged.metadata["ghidra_version"] == "11.1.2"
        assert merged.metadata["r2_version"] == "5.9.0"
        assert merged.metadata["project"] == "test"

    def test_binary_path_fallback(self):
        primary = _make_db("ghidra")
        primary.binary_path = None
        secondary = _make_db("r2")
        secondary.binary_path = "/path/to/binary"
        merged = primary.merge(secondary)
        assert merged.binary_path == "/path/to/binary"

    def test_empty_merge(self):
        a = _make_db("ghidra")
        b = _make_db("r2")
        merged = a.merge(b)
        assert merged.source_tool == "ghidra"
        assert len(merged.functions) == 0

    @staticmethod
    def _rebase_pair() -> tuple[REDatabase, REDatabase]:
        """Primary based at 0x100000, secondary at 0x0 — three shared
        non-auto names earn a rebase delta of 0x100000."""
        primary = _make_db("ghidra", funcs=[
            REFunction(name="anchor%d" % i, address=0x101000 + i * 0x100,
                       size=64, source_tool="ghidra")
            for i in range(3)
        ])
        secondary = _make_db("r2", funcs=[
            REFunction(name="anchor%d" % i, address=0x1000 + i * 0x100,
                       size=64, source_tool="r2")
            for i in range(3)
        ])
        secondary.xrefs = [
            REXref(from_addr=0x1010, to_addr=0x2000, kind="call",
                   source_tool="r2"),
        ]
        secondary.comments = [
            REComment(address=0x1010, function=None, kind="eol",
                      text="note", source_tool="r2"),
        ]
        secondary.imports = [{"name": "read", "address": 0x4000}]
        secondary.exports = [{"name": "handler", "address": 0x4100}]
        secondary.strings = [{"value": "s3cr3t", "address": 0x3000}]
        secondary.bookmarks = [{"address": 0x5000, "category": "Analysis",
                                "comment": "check"}]
        secondary.segments = [
            RESegment(name=".text", start=0x1000, end=0x1fff,
                      permissions="r-x"),
        ]
        return primary, secondary

    def test_merge_rebases_every_address_record(self):
        """A secondary-engine xref/comment/string/import/bookmark left
        in its own address space dangles (or lands inside an unrelated
        function) in the merged database — every address-carrying
        record must move by the same delta as the functions."""
        primary, secondary = self._rebase_pair()
        merged = primary.merge(secondary)

        # functions rebased (pre-existing behaviour)
        assert merged.function_by_address(0x101000) is not None
        # xrefs follow
        assert [(x.from_addr, x.to_addr) for x in merged.xrefs] == [
            (0x101010, 0x102000)]
        # and the from-address now resolves inside the rebased anchor
        assert merged.function_containing_address(0x101010).name == "anchor0"
        assert [c.address for c in merged.comments] == [0x101010]
        assert merged.imports[0]["address"] == 0x104000
        assert merged.exports[0]["address"] == 0x104100
        assert merged.strings[0]["address"] == 0x103000
        assert merged.bookmarks[0]["address"] == 0x105000
        # segments come from the secondary here (primary has none)
        assert (merged.segments[0].start, merged.segments[0].end) == (
            0x101000, 0x101fff)
        # the secondary database itself is never mutated
        assert secondary.xrefs[0].from_addr == 0x1010
        assert secondary.imports[0]["address"] == 0x4000
        assert secondary.bookmarks[0]["address"] == 0x5000

    def test_merge_zero_delta_leaves_addresses_alone(self):
        """Same address space on both sides → no rebase evidence, and
        no record moves."""
        primary, secondary = self._rebase_pair()
        for i, f in enumerate(secondary.functions):
            f.address = 0x101000 + i * 0x100
        merged = primary.merge(secondary)
        assert [(x.from_addr, x.to_addr) for x in merged.xrefs] == [
            (0x1010, 0x2000)]
        assert [c.address for c in merged.comments] == [0x1010]
        assert merged.imports[0]["address"] == 0x4000
        assert merged.strings[0]["address"] == 0x3000
        assert merged.bookmarks[0]["address"] == 0x5000

    def test_merge_rebase_tolerates_junk_addresses(self):
        """Free-form dict records without a usable int address pass
        through the rebase untouched instead of raising."""
        primary, secondary = self._rebase_pair()
        secondary.imports = [{"name": "no_addr"}]
        secondary.strings = [{"value": "s", "address": "junk"}]
        secondary.bookmarks = [{"address": True, "comment": "bool"}]
        merged = primary.merge(secondary)
        assert merged.imports[0] == {"name": "no_addr"}
        assert merged.strings[0]["address"] == "junk"
        assert merged.bookmarks[0]["address"] is True
