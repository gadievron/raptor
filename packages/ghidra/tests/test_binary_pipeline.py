"""Tests for Phase 2 binary pipeline and quick wins.

Covers: binary_builder, binary_context, r2_import, objdump_import,
bookmarks_bridge, SCA binary_imports.
"""

import json
from pathlib import Path

from packages.ghidra.model import (
    REDatabase,
    REFunction,
    REXref,
)


def _make_db(functions=None, xrefs=None, types=None, comments=None,
             imports=None, exports=None, bookmarks=None):
    return REDatabase(
        source_tool="ghidra",
        binary_path="/usr/bin/target",
        architecture="x86-64",
        functions=functions or [],
        xrefs=xrefs or [],
        types=types or [],
        comments=comments or [],
        imports=imports or [],
        exports=exports or [],
        bookmarks=bookmarks or [],
    )


def _make_func(name, addr=0x1000, size=100, sig=None, decomp=None,
               auto=False, thunk=False, external=False):
    return REFunction(
        name=name, address=addr, size=size,
        signature=sig, decompilation=decomp,
        is_auto_named=auto, is_thunk=thunk, is_external=external,
        source_tool="ghidra",
    )


# ── Signature Parsing ─────────────────────────────────────────────────

class TestSignatureParsing:
    def test_basic_signature(self):
        from core.inventory.binary_builder import _parse_c_signature

        ret, params = _parse_c_signature("int main(int argc, char **argv)")
        assert ret == "int"
        assert len(params) == 2
        assert params[0] == ("argc", "int")
        assert params[1] == ("argv", "char **")

    def test_pointer_return(self):
        from core.inventory.binary_builder import _parse_c_signature

        ret, params = _parse_c_signature("void *malloc(size_t size)")
        assert ret == "void *"
        assert params[0] == ("size", "size_t")

    def test_no_params(self):
        from core.inventory.binary_builder import _parse_c_signature

        ret, params = _parse_c_signature("int getpid(void)")
        assert ret == "int"
        assert params == []

    def test_ghidra_undefined(self):
        from core.inventory.binary_builder import _parse_c_signature

        ret, params = _parse_c_signature(
            "undefined processPacket(byte *param_1, int param_2)")
        assert ret == "undefined"
        assert len(params) == 2
        assert params[0][1] == "byte *"

    def test_no_parens(self):
        from core.inventory.binary_builder import _parse_c_signature

        ret, params = _parse_c_signature("just_a_name")
        assert ret is None
        assert params == []


# ── Binary Checklist Metadata ────────────────────────────────────────

class TestBinaryChecklistMetadata:
    def test_metadata_includes_signature_params(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(
            functions=[_make_func(
                "parse_input", 0x1000, 200,
                sig="int parse_input(char *buf, size_t len)",
            )],
            exports=[{"name": "parse_input"}],
        )
        cl = build_binary_checklist(db)
        item = cl["files"][0]["items"][0]
        meta = item.get("metadata", {})
        assert meta.get("return_type") == "int"
        assert meta.get("visibility") == "exported"
        params = meta.get("parameters", [])
        assert len(params) == 2
        assert params[0]["type"] == "char *"

    def test_metadata_empty_without_signature(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(functions=[_make_func("bare", 0x2000, 100)])
        cl = build_binary_checklist(db)
        item = cl["files"][0]["items"][0]
        meta = item.get("metadata", {})
        assert "parameters" not in meta
        assert "return_type" not in meta


# ── Binary Checklist Builder ──────────────────────────────────────────

class TestBinaryChecklist:
    def test_basic_checklist(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(functions=[
            _make_func("main", 0x1000, 200),
            _make_func("helper", 0x2000, 50),
        ])
        cl = build_binary_checklist(db)
        assert cl["target_kind"] == "binary"
        assert cl["total_functions"] == 2
        assert len(cl["files"]) == 1
        assert cl["files"][0]["path"] == "binary:target"
        assert cl["files"][0]["language"] == "binary"

        items = cl["files"][0]["items"]
        assert len(items) == 2
        assert items[0]["address"] == 0x1000
        assert items[0]["name"] == "main"

    def test_skips_thunks_and_externals(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(functions=[
            _make_func("real_func", 0x1000, 100),
            _make_func("thunk_memcpy", 0x2000, 8, thunk=True),
            _make_func("printf", 0x0, 0, external=True),
        ])
        cl = build_binary_checklist(db)
        items = cl["files"][0]["items"]
        assert len(items) == 1
        assert items[0]["name"] == "real_func"

    def test_skips_auto_named_by_default(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(functions=[
            _make_func("FUN_00401000", 0x401000, 100, auto=True),
            _make_func("real", 0x1000, 100),
        ])
        cl = build_binary_checklist(db)
        items = cl["files"][0]["items"]
        assert len(items) == 1
        assert items[0]["name"] == "real"

    def test_includes_auto_named_when_requested(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(functions=[
            _make_func("FUN_00401000", 0x401000, 100, auto=True),
        ])
        cl = build_binary_checklist(db, include_auto_named=True)
        assert cl["total_functions"] == 1

    def test_skips_small_functions(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(functions=[
            _make_func("tiny", 0x1000, 8),
            _make_func("normal", 0x2000, 100),
        ])
        cl = build_binary_checklist(db, min_size=16)
        items = cl["files"][0]["items"]
        assert len(items) == 1
        assert items[0]["name"] == "normal"

    def test_exported_functions_get_high_priority(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(
            functions=[
                _make_func("exported_api", 0x1000, 100),
                _make_func("internal", 0x2000, 100),
            ],
            exports=[{"name": "exported_api", "address": 0x1000}],
        )
        cl = build_binary_checklist(db)
        items = cl["files"][0]["items"]
        exported = next(i for i in items if i["name"] == "exported_api")
        assert exported.get("priority") == "high"
        assert "exported" in exported.get("priority_reason", "").lower()

    def test_dangerous_callers_get_high_priority(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(
            functions=[
                _make_func("parse_input", 0x1000, 200),
                _make_func("strcpy", 0x2000, 50),
            ],
            xrefs=[REXref(from_addr=0x1050, to_addr=0x2000, kind="call")],
        )
        cl = build_binary_checklist(db)
        items = cl["files"][0]["items"]
        parser = next(i for i in items if i["name"] == "parse_input")
        assert parser.get("priority") == "high"
        assert "strcpy" in parser.get("priority_reason", "")

    def test_high_priority_sorted_first(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(
            functions=[
                _make_func("low_prio", 0x3000, 500),
                _make_func("high_prio", 0x1000, 50),
            ],
            exports=[{"name": "high_prio"}],
        )
        cl = build_binary_checklist(db)
        items = cl["files"][0]["items"]
        assert items[0]["name"] == "high_prio"

    def test_binary_stats(self):
        from core.inventory.binary_builder import build_binary_checklist

        db = _make_db(functions=[
            _make_func("named", 0x1000, 100),
            _make_func("FUN_00402000", 0x402000, 100, auto=True),
        ])
        cl = build_binary_checklist(db)
        stats = cl["binary_stats"]
        assert stats["total_functions"] == 2
        assert stats["named_functions"] == 1
        assert stats["auto_named"] == 1


# ── Binary Context Assembler ──────────────────────────────────────────
class TestR2Import:
    def test_context_map_to_redb_dict(self):
        from packages.ghidra.r2_import import context_map_to_redb
        from pathlib import Path

        ctx_dict = {
            "binary": "/usr/bin/test",
            "arch": "x86",
            "bits": 64,
            "binary_format": "elf",
            "interesting_functions": [
                {"name": "main", "address": "0x1000", "size": 200,
                 "is_imported": False},
                {"name": "helper", "address": "0x2000", "size": 100,
                 "is_imported": False},
            ],
            "imported_functions": [
                {"name": "printf", "address": "0x3000", "size": 0,
                 "is_imported": True},
            ],
            "imports": ["printf", "malloc"],
            "exports": ["main"],
            "strings_sample": ["Hello"],
        }

        db = context_map_to_redb(ctx_dict, Path("/usr/bin/test"))
        assert db.source_tool == "r2"
        assert len(db.functions) == 3
        assert db.functions[0].name == "main"
        assert db.functions[0].address == 0x1000
        assert db.functions[2].is_external is True
        assert len(db.imports) == 2
        assert len(db.exports) == 1

    def test_dedup_by_address(self):
        from packages.ghidra.r2_import import context_map_to_redb
        from pathlib import Path

        ctx_dict = {
            "interesting_functions": [
                {"name": "f", "address": "0x1000", "size": 100},
            ],
            "imported_functions": [
                {"name": "f_imp", "address": "0x1000", "size": 0,
                 "is_imported": True},
            ],
        }
        db = context_map_to_redb(ctx_dict, Path("/test"))
        assert len(db.functions) == 1


# ── objdump Import ────────────────────────────────────────────────────

class TestObjdumpImport:
    def test_parse_nm_line_four_fields(self):
        from packages.ghidra.objdump_import import _parse_nm_line

        result = _parse_nm_line("0000000000401000 00000064 T main")
        assert result == (0x401000, 0x64, "T", "main")

    def test_parse_nm_line_three_fields(self):
        from packages.ghidra.objdump_import import _parse_nm_line

        result = _parse_nm_line("0000000000401000 T main")
        assert result == (0x401000, 0, "T", "main")

    def test_parse_nm_line_invalid(self):
        from packages.ghidra.objdump_import import _parse_nm_line

        assert _parse_nm_line("not a valid line") is None
        assert _parse_nm_line("") is None

    def test_availability_check(self):
        from packages.ghidra.objdump_import import objdump_available
        result = objdump_available()
        assert isinstance(result, bool)


# ── Bookmarks Bridge ─────────────────────────────────────────────────

class TestBookmarksBridge:
    def test_bookmarks_to_findings(self):
        from packages.ghidra.bookmarks_bridge import bookmarks_to_findings

        db = _make_db(
            functions=[_make_func("vuln", 0x1000, 200)],
            bookmarks=[
                {
                    "address": 0x1000,
                    "type": "Analysis",
                    "category": "Warning",
                    "comment": "CVE-2023-1234: heap overflow in parser",
                },
            ],
        )
        findings = bookmarks_to_findings(db)
        assert len(findings) == 1
        assert findings[0]["function"] == "vuln"
        assert findings[0]["cve"] == "CVE-2023-1234"
        assert findings[0]["severity"] == "High"
        assert findings[0]["source"] == "ghidra-bookmark"

    def test_no_bookmarks_returns_empty(self):
        from packages.ghidra.bookmarks_bridge import bookmarks_to_findings

        db = _make_db()
        assert bookmarks_to_findings(db) == []

    def test_bookmark_without_address_skipped(self):
        from packages.ghidra.bookmarks_bridge import bookmarks_to_findings

        db = _make_db(bookmarks=[
            {"comment": "no address", "category": "Note"},
        ])
        assert bookmarks_to_findings(db) == []

    def test_write_attack_surface(self, tmp_path):
        from packages.ghidra.bookmarks_bridge import (
            write_attack_surface_from_bookmarks,
        )

        db = _make_db(
            functions=[_make_func("target_func", 0x2000, 100)],
            bookmarks=[
                {
                    "address": 0x2000,
                    "category": "Analysis",
                    "comment": "suspicious buffer handling",
                },
            ],
        )
        n = write_attack_surface_from_bookmarks(db, tmp_path)
        assert n == 1

        surface = json.loads((tmp_path / "attack-surface.json").read_text())
        assert len(surface["sources"]) == 1
        assert surface["sources"][0]["entry"] == "target_func"

    def test_write_checklist(self, tmp_path):
        from packages.ghidra.bookmarks_bridge import (
            write_checklist_from_bookmarks,
        )

        db = _make_db(
            functions=[
                _make_func("f1", 0x1000, 100),
                _make_func("f2", 0x2000, 100),
            ],
            bookmarks=[
                {"address": 0x1000, "comment": "CVE-2024-5678", "category": "Error"},
                {"address": 0x2000, "comment": "check this", "category": "Analysis"},
            ],
        )
        n = write_checklist_from_bookmarks(db, tmp_path)
        assert n == 2

        cl = json.loads((tmp_path / "checklist.json").read_text())
        assert cl["total_functions"] == 2
        items = cl["files"][0]["items"]
        assert all(i["priority"] == "high" for i in items)
        cve_item = next(i for i in items if i["name"] == "f1")
        assert cve_item["cve"] == "CVE-2024-5678"

    def test_dedup_by_function(self, tmp_path):
        from packages.ghidra.bookmarks_bridge import (
            write_checklist_from_bookmarks,
        )

        db = _make_db(
            functions=[_make_func("same_func", 0x1000, 100)],
            bookmarks=[
                {"address": 0x1000, "comment": "note 1", "category": "A"},
                {"address": 0x1000, "comment": "note 2", "category": "B"},
            ],
        )
        n = write_checklist_from_bookmarks(db, tmp_path)
        assert n == 1


# ── SCA Binary Imports ────────────────────────────────────────────────

class TestSCABinaryImports:
    def test_detects_openssl(self):
        from packages.sca.parsers.binary_imports import parse_binary_imports

        db = _make_db(imports=[
            {"name": "SSL_read"},
            {"name": "SSL_write"},
            {"name": "SSL_CTX_new"},
        ])
        deps = parse_binary_imports(db)
        assert len(deps) == 1
        assert deps[0].name == "openssl"
        assert deps[0].ecosystem == "native"
        assert deps[0].source_kind == "binary_import_table"
        assert deps[0].source_extra["match_count"] == 3

    def test_detects_zlib(self):
        from packages.sca.parsers.binary_imports import parse_binary_imports

        db = _make_db(imports=[
            {"name": "deflate"},
            {"name": "inflate"},
            {"name": "deflateInit"},
        ])
        deps = parse_binary_imports(db)
        names = [d.name for d in deps]
        assert "zlib" in names

    def test_ignores_insufficient_matches(self):
        from packages.sca.parsers.binary_imports import parse_binary_imports

        db = _make_db(imports=[
            {"name": "SSL_read"},
        ])
        deps = parse_binary_imports(db)
        assert len(deps) == 0

    def test_multiple_libraries(self):
        from packages.sca.parsers.binary_imports import parse_binary_imports

        db = _make_db(imports=[
            {"name": "SSL_read"},
            {"name": "SSL_write"},
            {"name": "SSL_CTX_new"},
            {"name": "deflate"},
            {"name": "inflate"},
            {"name": "deflateInit"},
            {"name": "curl_easy_init"},
            {"name": "curl_easy_perform"},
            {"name": "curl_easy_setopt"},
        ])
        deps = parse_binary_imports(db)
        names = {d.name for d in deps}
        assert names == {"openssl", "zlib", "libcurl"}

    def test_empty_imports(self):
        from packages.sca.parsers.binary_imports import parse_binary_imports

        db = _make_db()
        assert parse_binary_imports(db) == []

    def test_purl_format(self):
        from packages.sca.parsers.binary_imports import parse_binary_imports

        db = _make_db(imports=[
            {"name": "sqlite3_open"},
            {"name": "sqlite3_close"},
            {"name": "sqlite3_exec"},
        ])
        deps = parse_binary_imports(db)
        assert len(deps) == 1
        assert deps[0].purl.startswith("pkg:native/sqlite3")


# ── Bookmark Finding Import (validate integration) ──────────────────

class TestBookmarkFindingImport:
    """Tests for converting bookmarks into /validate Stage A finding shapes."""

    def test_findings_have_required_fields(self, tmp_path):
        from packages.ghidra.bookmarks_bridge import bookmarks_to_findings

        db = _make_db(
            functions=[_make_func("vuln_func", 0x4000, 300)],
            bookmarks=[{
                "address": 0x4000,
                "category": "Analysis",
                "comment": "CVE-2024-9999: heap overflow via crafted input",
            }],
        )
        findings = bookmarks_to_findings(db)
        assert len(findings) == 1
        f = findings[0]
        assert f["function"] == "vuln_func"
        assert f["address"] == 0x4000
        assert f["cve"] == "CVE-2024-9999"
        assert f["severity"] == "High"
        assert f["source"] == "ghidra-bookmark"

    def test_attack_surface_and_checklist_written(self, tmp_path):
        from packages.ghidra.bookmarks_bridge import (
            write_attack_surface_from_bookmarks,
            write_checklist_from_bookmarks,
        )

        db = _make_db(
            functions=[
                _make_func("recv_data", 0x1000, 150),
                _make_func("parse_header", 0x2000, 200),
            ],
            bookmarks=[
                {"address": 0x1000, "comment": "network input", "category": "Analysis"},
                {"address": 0x2000, "comment": "CVE-2024-1111", "category": "Error"},
            ],
        )

        n_as = write_attack_surface_from_bookmarks(db, tmp_path)
        n_cl = write_checklist_from_bookmarks(db, tmp_path)

        assert n_as == 2
        assert n_cl == 2
        assert (tmp_path / "attack-surface.json").exists()
        assert (tmp_path / "checklist.json").exists()

        cl = json.loads((tmp_path / "checklist.json").read_text())
        items = cl["files"][0]["items"]
        cve_item = next(i for i in items if i["name"] == "parse_header")
        assert cve_item["cve"] == "CVE-2024-1111"
        assert cve_item["priority"] == "high"

    def test_multiple_bookmarks_same_function_deduped(self, tmp_path):
        from packages.ghidra.bookmarks_bridge import (
            write_checklist_from_bookmarks,
        )

        db = _make_db(
            functions=[_make_func("handler", 0x3000, 100)],
            bookmarks=[
                {"address": 0x3000, "comment": "note A", "category": "Analysis"},
                {"address": 0x3000, "comment": "note B", "category": "Warning"},
            ],
        )
        n = write_checklist_from_bookmarks(db, tmp_path)
        assert n == 1

    def test_bookmark_severity_mapping(self):
        from packages.ghidra.bookmarks_bridge import bookmarks_to_findings

        high_db = _make_db(
            functions=[_make_func("f", 0x1000)],
            bookmarks=[{"address": 0x1000, "comment": "CVE-2024-0001",
                         "category": "Error"}],
        )
        low_db = _make_db(
            functions=[_make_func("g", 0x2000)],
            bookmarks=[{"address": 0x2000, "comment": "check this",
                         "category": "Note"}],
        )
        assert bookmarks_to_findings(high_db)[0]["severity"] == "High"
        assert bookmarks_to_findings(low_db)[0]["severity"] in ("Medium", "Low", "Info")


# ── /audit Binary Context Routing ────────────────────────────────────

class TestSonameVersionNoCaptureGroup:
    def test_no_capture_group_pattern_no_crash(self):
        # sqlite3/libpng/libjpeg identity patterns have no version
        # capture group — version detection must decline, not raise.
        from packages.ghidra.model import REDatabase
        from packages.sca.parsers.binary_imports import parse_binary_imports
        db = REDatabase(
            source_tool="r2",
            binary_path="/x",
            metadata={"needed": ["libsqlite3.so.0"]},
            imports=[{"name": "sqlite3_open"}, {"name": "sqlite3_exec"}],
        )
        deps = parse_binary_imports(db)
        by_name = {d.name: d for d in deps}
        assert "sqlite3" in by_name
        assert by_name["sqlite3"].version is None


# ── Bookmarks bridge: checklist merge robustness ──────────────────────

class TestChecklistMergeRobustness:
    def _db(self):
        return _make_db(
            functions=[_make_func("merge_target", 0x3000, 100)],
            bookmarks=[
                {"address": 0x3000, "comment": "check bounds",
                 "category": "Warning"},
            ],
        )

    def test_existing_entry_without_items_merges(self, tmp_path):
        """A hand-edited checklist file entry may lack "items" — the
        merge must add to it, not raise KeyError out of the bridge."""
        from core.inventory.binary_builder import binary_path_key
        from packages.ghidra.bookmarks_bridge import (
            write_checklist_from_bookmarks,
        )

        path_key = binary_path_key(Path("/usr/bin/target"))
        (tmp_path / "checklist.json").write_text(json.dumps({
            "files": [{"path": path_key}],
        }))
        n = write_checklist_from_bookmarks(self._db(), tmp_path)
        assert n == 1
        cl = json.loads((tmp_path / "checklist.json").read_text())
        (fe,) = cl["files"]
        assert [i["name"] for i in fe["items"]] == ["merge_target"]

    def test_existing_entry_with_items_extends(self, tmp_path):
        from core.inventory.binary_builder import binary_path_key
        from packages.ghidra.bookmarks_bridge import (
            write_checklist_from_bookmarks,
        )

        path_key = binary_path_key(Path("/usr/bin/target"))
        (tmp_path / "checklist.json").write_text(json.dumps({
            "files": [{"path": path_key, "items": [
                {"name": "already_there", "kind": "function"},
            ]}],
        }))
        n = write_checklist_from_bookmarks(self._db(), tmp_path)
        assert n == 1
        cl = json.loads((tmp_path / "checklist.json").read_text())
        names = [i["name"] for i in cl["files"][0]["items"]]
        assert names == ["already_there", "merge_target"]
        assert cl["total_items"] == 2
