"""Tests for ghidra context injection into LLM prompts."""

from unittest.mock import patch

import pytest

from packages.ghidra.context_inject import (
    _build_func_index,
    _render_function_context,
    ghidra_blocks_for_finding,
    prepare_ghidra_context,
)
from packages.ghidra.model import (
    REComment,
    REDatabase,
    REFunction,
    REType,
    REXref,
)


@pytest.fixture(autouse=True)
def _clear_cache(monkeypatch):
    from packages.ghidra import context_inject
    from core.testing.module_state import isolated_module_state

    with isolated_module_state(context_inject, {
        "_GHIDRA_CACHE": {}, "_GHIDRA_FUNC_INDEX": {},
    }, lock=context_inject._GHIDRA_LOCK):
        try:
            yield
        finally:
            monkeypatch.undo()


def _make_db(functions=None, xrefs=None, types=None, comments=None):
    return REDatabase(
        source_tool="ghidra",
        binary_path="/test/binary",
        functions=functions or [],
        xrefs=xrefs or [],
        types=types or [],
        comments=comments or [],
    )


def _make_func(name, addr=0x1000, size=100, sig=None, decomp=None):
    return REFunction(
        name=name,
        address=addr,
        size=size,
        signature=sig,
        decompilation=decomp,
        source_tool="ghidra",
    )


class TestBuildFuncIndex:
    def test_indexes_named_functions(self):
        f1 = _make_func("parse_input", 0x1000)
        f2 = _make_func("handle_request", 0x2000)
        db = _make_db(functions=[f1, f2])
        idx = _build_func_index([db])
        assert "parse_input" in idx
        assert "handle_request" in idx
        assert idx["parse_input"] == [f1]

    def test_skips_auto_named(self):
        f = REFunction(
            name="FUN_00401000", address=0x401000, size=50,
            is_auto_named=True, source_tool="ghidra",
        )
        db = _make_db(functions=[f])
        idx = _build_func_index([db])
        assert "FUN_00401000" not in idx

    def test_skips_thunks(self):
        f = REFunction(
            name="thunk_memcpy", address=0x1000, size=10,
            is_thunk=True, source_tool="ghidra",
        )
        db = _make_db(functions=[f])
        idx = _build_func_index([db])
        assert "thunk_memcpy" not in idx

    def test_skips_externals(self):
        f = REFunction(
            name="printf", address=0x0, size=0,
            is_external=True, source_tool="ghidra",
        )
        db = _make_db(functions=[f])
        idx = _build_func_index([db])
        assert "printf" not in idx

    def test_multiple_databases(self):
        f1 = _make_func("func_a", 0x1000)
        f2 = _make_func("func_b", 0x2000)
        db1 = _make_db(functions=[f1])
        db2 = _make_db(functions=[f2])
        idx = _build_func_index([db1, db2])
        assert "func_a" in idx
        assert "func_b" in idx


class TestRenderFunctionContext:
    def test_decompilation(self):
        func = _make_func("vuln", decomp="void vuln(char *s) { strcpy(buf, s); }")
        db = _make_db(functions=[func])
        parts = _render_function_context(func, db)
        assert any("Ghidra Decompilation" in p for p in parts)
        assert any("strcpy" in p for p in parts)

    def test_signature(self):
        func = _make_func("foo", sig="int foo(char *, size_t)")
        db = _make_db(functions=[func])
        parts = _render_function_context(func, db)
        assert any("Function Signature" in p for p in parts)

    def test_xrefs_callers_callees(self):
        main_f = _make_func("main", 0x1000)
        vuln_f = _make_func("vuln", 0x2000)
        helper_f = _make_func("helper", 0x3000)
        xrefs = [
            REXref(from_addr=0x1000, to_addr=0x2000, kind="call"),
            REXref(from_addr=0x2000, to_addr=0x3000, kind="call"),
        ]
        db = _make_db(functions=[main_f, vuln_f, helper_f], xrefs=xrefs)
        parts = _render_function_context(vuln_f, db)
        xref_parts = [p for p in parts if "Cross-References" in p]
        assert len(xref_parts) == 1
        assert "main" in xref_parts[0]
        assert "helper" in xref_parts[0]

    def test_related_types(self):
        func = _make_func(
            "process",
            sig="void process(struct Buffer *buf)",
            decomp="void process(Buffer *buf) { buf->data[buf->len] = 0; }",
        )
        buf_type = REType(
            name="Buffer", kind="struct", size=32,
            fields=[
                {"offset": 0, "name": "data", "type": "char *", "size": 8},
                {"offset": 8, "name": "len", "type": "int", "size": 4},
            ],
            source_tool="ghidra",
        )
        db = _make_db(functions=[func], types=[buf_type])
        parts = _render_function_context(func, db)
        type_parts = [p for p in parts if "Related Types" in p]
        assert len(type_parts) == 1
        assert "Buffer" in type_parts[0]
        assert "data" in type_parts[0]

    def test_comments(self):
        func = _make_func("handler", 0x1000)
        comment = REComment(
            address=0x1000, function="handler",
            kind="plate", text="VULNERABLE: buffer overflow",
            source_tool="ghidra",
        )
        db = _make_db(functions=[func], comments=[comment])
        parts = _render_function_context(func, db)
        assert any("Ghidra project comments (untrusted)" in p for p in parts)
        assert any("VULNERABLE" in p for p in parts)

    def test_empty_function_returns_nothing(self):
        func = _make_func("stub", 0x1000)
        db = _make_db(functions=[func])
        parts = _render_function_context(func, db)
        assert parts == []


class TestPrepareAndLookup:
    def test_prepare_then_lookup(self, tmp_path):
        func = _make_func(
            "vulnerable_func", 0x1000,
            decomp="void vulnerable_func() { gets(buf); }",
        )
        db = _make_db(functions=[func])

        redb_path = tmp_path / "test.gpr"
        redb_path.write_text("")
        redb_json = tmp_path / "re-database.json"
        import json
        with open(redb_json, "w") as f:
            json.dump(db.to_dict(), f)

        with (
            patch(
                "packages.ghidra.context_inject._resolve_ghidra_projects",
                return_value=[str(redb_path)],
            ),
            # The .gpr's own directory is no longer a cache candidate
            # (attacker territory) — point the lookup at the fixture's
            # RAPTOR-owned location explicitly.
            patch(
                "packages.ghidra.roundtrip.redb_cache_candidates",
                return_value=[redb_json],
            ),
        ):
            prepare_ghidra_context(tmp_path)

        blocks = ghidra_blocks_for_finding({
            "repo_path": str(tmp_path),
            "function": "vulnerable_func",
            "metadata": {},
        })
        assert len(blocks) == 1
        assert "ghidra-context" == blocks[0].kind
        assert "gets(buf)" in blocks[0].content

    def test_no_match_returns_empty(self, tmp_path):
        func = _make_func("other_func", 0x1000, decomp="void other_func() {}")
        db = _make_db(functions=[func])

        redb_path = tmp_path / "test.gpr"
        redb_path.write_text("")
        redb_json = tmp_path / "re-database.json"
        import json
        with open(redb_json, "w") as f:
            json.dump(db.to_dict(), f)

        with (
            patch(
                "packages.ghidra.context_inject._resolve_ghidra_projects",
                return_value=[str(redb_path)],
            ),
            # The .gpr's own directory is no longer a cache candidate
            # (attacker territory) — point the lookup at the fixture's
            # RAPTOR-owned location explicitly.
            patch(
                "packages.ghidra.roundtrip.redb_cache_candidates",
                return_value=[redb_json],
            ),
        ):
            prepare_ghidra_context(tmp_path)

        blocks = ghidra_blocks_for_finding({
            "repo_path": str(tmp_path),
            "function": "nonexistent_func",
        })
        assert blocks == ()

    def test_no_project_returns_empty(self, tmp_path):
        blocks = ghidra_blocks_for_finding({
            "repo_path": str(tmp_path),
            "function": "some_func",
        })
        assert blocks == ()

    def test_cache_dedup(self, tmp_path):
        func = _make_func("f", 0x1000, decomp="void f() {}")
        db = _make_db(functions=[func])

        redb_path = tmp_path / "test.gpr"
        redb_path.write_text("")
        import json
        (tmp_path / "re-database.json").write_text(json.dumps(db.to_dict()))

        with patch(
            "packages.ghidra.context_inject._load_cached_redb",
            return_value=db,
        ) as mock_load:
            prepare_ghidra_context(
                tmp_path, ghidra_projects=[str(redb_path)],
            )
            prepare_ghidra_context(
                tmp_path, ghidra_projects=[str(redb_path)],
            )

        assert mock_load.call_count == 1

    def test_missing_gpr_skipped(self, tmp_path):
        with patch(
            "packages.ghidra.context_inject._resolve_ghidra_projects",
            return_value=[str(tmp_path / "nonexistent.gpr")],
        ):
            prepare_ghidra_context(tmp_path)

        blocks = ghidra_blocks_for_finding({
            "repo_path": str(tmp_path),
            "function": "anything",
        })
        assert blocks == ()

    def test_load_cached_redb_from_project_output(self, tmp_path):
        """_load_cached_redb finds re-database.json in the project's ghidra-<stem>/ dir."""
        from packages.ghidra.context_inject import _load_cached_redb

        func = _make_func("target_func", 0x4000, decomp="void target_func() {}")
        db = _make_db(functions=[func])

        gpr = tmp_path / "firmware.gpr"
        gpr.write_text("")

        project_out = tmp_path / "project-out"
        ghidra_dir = project_out / "ghidra-firmware"
        ghidra_dir.mkdir(parents=True)

        import json
        (ghidra_dir / "re-database.json").write_text(json.dumps(db.to_dict()))

        mock_project = type("P", (), {"output_dir": str(project_out)})()

        with patch("core.project.project.ProjectManager") as MockMgr:
            mgr = MockMgr.return_value
            mgr.get_active.return_value = "test-proj"
            mgr.load.return_value = mock_project
            result = _load_cached_redb(gpr)

        assert result is not None
        assert len(result.functions) == 1
        assert result.functions[0].name == "target_func"
