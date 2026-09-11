"""Tests for packages.ghidra.parser — Ghidra export → REDatabase."""

from __future__ import annotations

import json

from packages.ghidra.parser import parse_dict, parse_export, _looks_auto_named


FIXTURE = {
    "source_tool": "ghidra",
    "binary_path": "/opt/sap/saprouter",
    "architecture": "x86/64",
    "metadata": {
        "program_name": "saprouter",
        "ghidra_version": "11.1.2",
        "language_id": "x86:LE:64:default",
        "compiler_spec": "gcc",
        "image_base": 4194304,
    },
    "functions": [
        {
            "name": "main",
            "address": 4198400,
            "size": 256,
            "signature": "int main(int argc, char **argv)",
            "calling_convention": "__stdcall",
            "is_auto_named": False,
            "is_thunk": False,
            "is_external": False,
            "decompilation": "int main(int argc, char **argv) {\n  return 0;\n}",
            "source_tool": "ghidra",
        },
        {
            "name": "parse_route_string",
            "address": 4199000,
            "size": 512,
            "signature": "int parse_route_string(char *buf, int len)",
            "is_auto_named": False,
            "is_thunk": False,
            "is_external": False,
            "decompilation": "int parse_route_string(char *buf, int len) {\n  memcpy(local, buf, len);\n}",
            "source_tool": "ghidra",
        },
        {
            "name": "FUN_00401500",
            "address": 4199680,
            "size": 64,
            "is_auto_named": True,
            "is_thunk": False,
            "is_external": False,
            "source_tool": "ghidra",
        },
        {
            "name": "recv",
            "address": 0,
            "size": 0,
            "is_auto_named": False,
            "is_thunk": True,
            "is_external": True,
            "source_tool": "ghidra",
        },
    ],
    "xrefs": [
        {"from_addr": 4198400, "to_addr": 4199000, "kind": "call", "source_tool": "ghidra"},
        {"from_addr": 4199000, "to_addr": 4199680, "kind": "call", "source_tool": "ghidra"},
        {"from_addr": 4199050, "to_addr": 4210000, "kind": "data", "source_tool": "ghidra"},
    ],
    "types": [
        {
            "name": "route_entry",
            "kind": "struct",
            "size": 48,
            "fields": [
                {"name": "host", "offset": 0, "type": "char[32]", "size": 32},
                {"name": "port", "offset": 32, "type": "uint16_t", "size": 2},
                {"name": "flags", "offset": 34, "type": "uint16_t", "size": 2},
                {"name": "next", "offset": 40, "type": "route_entry *", "size": 8},
            ],
            "source_tool": "ghidra",
        },
    ],
    "comments": [
        {
            "address": 4199050,
            "function": "parse_route_string",
            "kind": "eol",
            "text": "CVE-2013-6817: unchecked length in memcpy",
            "source_tool": "ghidra",
        },
        {
            "address": 4199000,
            "function": "parse_route_string",
            "kind": "plate",
            "text": "Parses SAP route strings from NI protocol packets",
            "source_tool": "ghidra",
        },
    ],
    "segments": [
        {"name": ".text", "start": 4194304, "end": 4259840, "permissions": "r-x"},
        {"name": ".data", "start": 4259840, "end": 4263936, "permissions": "rw-"},
        {"name": ".rodata", "start": 4263936, "end": 4268032, "permissions": "r--"},
    ],
    "imports": [
        {"name": "recv", "address": 4210000, "library": "libc.so.6"},
        {"name": "memcpy", "address": 4210008, "library": "libc.so.6"},
        {"name": "connect", "address": 4210016, "library": "libc.so.6"},
    ],
    "exports": [
        {"name": "main", "address": 4198400},
    ],
    "strings": [
        {"address": 4264000, "value": "\"SAProuter %s\""},
        {"address": 4264020, "value": "\"Connection refused\""},
    ],
    "bookmarks": [
        {
            "address": 4199050,
            "category": "Vulnerability",
            "comment": "heap overflow via route string",
            "type": "Analysis",
        },
    ],
}


class TestParseDict:
    def test_basic_structure(self):
        db = parse_dict(FIXTURE)
        assert db.source_tool == "ghidra"
        assert db.binary_path == "/opt/sap/saprouter"
        assert db.architecture == "x86/64"

    def test_functions(self):
        db = parse_dict(FIXTURE)
        assert len(db.functions) == 4
        main = db.function_by_address(4198400)
        assert main.name == "main"
        assert main.signature == "int main(int argc, char **argv)"
        assert main.decompilation is not None
        assert not main.is_auto_named

    def test_auto_named_detection(self):
        db = parse_dict(FIXTURE)
        auto = db.function_by_address(4199680)
        assert auto.is_auto_named is True
        assert auto.name == "FUN_00401500"

    def test_external_thunk(self):
        db = parse_dict(FIXTURE)
        recv = [f for f in db.functions if f.name == "recv"][0]
        assert recv.is_thunk
        assert recv.is_external

    def test_auto_named_ratio(self):
        db = parse_dict(FIXTURE)
        assert abs(db.auto_named_ratio - 0.25) < 0.01

    def test_xrefs(self):
        db = parse_dict(FIXTURE)
        assert len(db.xrefs) == 3
        calls = [x for x in db.xrefs if x.kind == "call"]
        assert len(calls) == 2

    def test_types(self):
        db = parse_dict(FIXTURE)
        assert len(db.types) == 1
        rt = db.types[0]
        assert rt.name == "route_entry"
        assert rt.size == 48
        assert len(rt.fields) == 4

    def test_comments(self):
        db = parse_dict(FIXTURE)
        assert len(db.comments) == 2
        eol = [c for c in db.comments if c.kind == "eol"][0]
        assert "CVE-2013-6817" in eol.text
        assert eol.function == "parse_route_string"

    def test_segments(self):
        db = parse_dict(FIXTURE)
        assert len(db.segments) == 3
        text = [s for s in db.segments if s.name == ".text"][0]
        assert text.permissions == "r-x"

    def test_imports(self):
        db = parse_dict(FIXTURE)
        assert len(db.imports) == 3
        recv = [i for i in db.imports if i["name"] == "recv"][0]
        assert recv["library"] == "libc.so.6"

    def test_exports(self):
        db = parse_dict(FIXTURE)
        assert len(db.exports) == 1
        assert db.exports[0]["name"] == "main"

    def test_strings(self):
        db = parse_dict(FIXTURE)
        assert len(db.strings) == 2

    def test_bookmarks(self):
        db = parse_dict(FIXTURE)
        assert len(db.bookmarks) == 1
        assert db.bookmarks[0]["category"] == "Vulnerability"

    def test_metadata(self):
        db = parse_dict(FIXTURE)
        assert db.metadata["ghidra_version"] == "11.1.2"
        assert db.metadata["program_name"] == "saprouter"

    def test_round_trip(self):
        db = parse_dict(FIXTURE)
        d = db.to_dict()
        db2 = parse_dict(d)
        assert len(db2.functions) == len(db.functions)
        assert len(db2.xrefs) == len(db.xrefs)
        assert db2.metadata == db.metadata


class TestParseExport:
    def test_from_file(self, tmp_path):
        p = tmp_path / "export.json"
        p.write_text(json.dumps(FIXTURE), encoding="utf-8")
        db = parse_export(p)
        assert len(db.functions) == 4

    def test_bad_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        try:
            parse_export(p)
            assert False, "should have raised"
        except ValueError as e:
            assert "failed to read" in str(e)

    def test_not_dict(self, tmp_path):
        p = tmp_path / "list.json"
        p.write_text("[]", encoding="utf-8")
        try:
            parse_export(p)
            assert False, "should have raised"
        except ValueError as e:
            assert "must be a JSON object" in str(e)

    def test_empty_dict(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("{}", encoding="utf-8")
        db = parse_export(p)
        assert len(db.functions) == 0
        assert db.source_tool == "ghidra"


class TestLooksAutoNamed:
    def test_ghidra_pattern(self):
        assert _looks_auto_named("FUN_00401000") is True

    def test_r2_pattern(self):
        assert _looks_auto_named("fcn.00401000") is True

    def test_ida_pattern(self):
        assert _looks_auto_named("sub_401000") is True

    def test_thunk_pattern(self):
        assert _looks_auto_named("thunk_FUN_00401000") is True

    def test_real_name(self):
        assert _looks_auto_named("parse_route_string") is False
        assert _looks_auto_named("main") is False

    def test_empty(self):
        assert _looks_auto_named("") is True
