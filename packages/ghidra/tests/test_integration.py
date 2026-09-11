"""Integration tests for Ghidra bridge wiring into RAPTOR.

Tests the project CLI (ghidra add/list/remove/clear), the
understand dispatcher's .gpr routing, and annotation import.

These tests do NOT require Ghidra to be installed — they mock
the headless subprocess and test the orchestration layer.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_EXPORT = {
    "source_tool": "ghidra",
    "binary_path": "/opt/sap/saprouter",
    "architecture": "x86/64",
    "metadata": {
        "program_name": "saprouter",
        "ghidra_version": "11.1.2",
    },
    "functions": [
        {
            "name": "main",
            "address": 4198400,
            "size": 256,
            "signature": "int main(int argc, char **argv)",
            "is_auto_named": False,
            "is_thunk": False,
            "is_external": False,
            "decompilation": "int main(int argc, char **argv) { return 0; }",
            "source_tool": "ghidra",
        },
        {
            "name": "parse_route",
            "address": 4199000,
            "size": 512,
            "is_auto_named": False,
            "is_thunk": False,
            "is_external": False,
            "source_tool": "ghidra",
        },
    ],
    "xrefs": [
        {"from_addr": 4198400, "to_addr": 4199000, "kind": "call", "source_tool": "ghidra"},
    ],
    "types": [],
    "comments": [
        {
            "address": 4199050,
            "function": "parse_route",
            "kind": "eol",
            "text": "CVE-2013-6817: unchecked memcpy",
            "source_tool": "ghidra",
        },
        {
            "address": 4199000,
            "function": "parse_route",
            "kind": "plate",
            "text": "Route string parser",
            "source_tool": "ghidra",
        },
    ],
    "segments": [],
    "imports": [],
    "exports": [],
    "strings": [],
    "bookmarks": [],
}


@pytest.fixture
def gpr_project(tmp_path):
    """Create a minimal .gpr project structure for testing."""
    gpr = tmp_path / "saprouter.gpr"
    rep = tmp_path / "saprouter.rep"
    rep.mkdir()
    idata = rep / "idata"
    idata.mkdir()
    (idata / "00").mkdir()
    gpr.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<FILE_INFO>\n'
        '  <BASIC_INFO>\n'
        '    <STATE NAME="OWNER" TYPE="string" VALUE="test" />\n'
        '  </BASIC_INFO>\n'
        '</FILE_INFO>\n',
        encoding="utf-8",
    )
    return gpr


# ---------------------------------------------------------------------------
# Project CLI: /project ghidra add/list/remove/clear
# ---------------------------------------------------------------------------

class TestGhidraMapRouting:
    def test_is_ghidra_project_detection(self, gpr_project):
        from packages.ghidra.detect import is_ghidra_project
        assert is_ghidra_project(gpr_project) is True

    def test_non_gpr_not_detected(self, tmp_path):
        elf = tmp_path / "binary"
        elf.write_bytes(b"\x7fELF" + b"\x00" * 100)

        from packages.ghidra.detect import is_ghidra_project
        assert is_ghidra_project(elf) is False


# ---------------------------------------------------------------------------
# Annotation import from Ghidra comments
# ---------------------------------------------------------------------------


# ------------------------------------------------------------------
# Ghidra comments reach reviews via context injection — NOT via
# /annotate. Annotations are human-written only (operator policy:
# machinery reads but never writes annotation content; the machine
# channel for Ghidra-derived signal is findings via bookmarks_bridge
# and prompt context via context_inject). The former comments-to-
# annotations import tests asserted the forbidden direction.
# ------------------------------------------------------------------

class TestCommentsReachReviewContext:
    def test_comments_render_in_context_block(self):
        """Ghidra analyst comments for the function under review are
        rendered into the injected context (bounded, labelled), so
        the RE knowledge reaches the LLM without machinery writing
        annotation files."""
        from packages.ghidra.context_inject import (
            _render_function_context,
        )
        from packages.ghidra.parser import parse_dict

        db = parse_dict(SAMPLE_EXPORT)
        assert len(db.comments) == 2
        func = next(f for f in db.functions if f.name == "parse_route")
        block = "\n".join(_render_function_context(func, db))
        assert "Ghidra project comments (untrusted)" in block
        assert "CVE-2013-6817" in block
        assert "Route string parser" in block

    def test_no_comments_for_function_omits_section(self):
        from packages.ghidra.context_inject import (
            _render_function_context,
        )
        from packages.ghidra.parser import parse_dict

        db = parse_dict(SAMPLE_EXPORT)
        func = next(f for f in db.functions if f.name != "parse_route")
        block = "\n".join(_render_function_context(func, db))
        assert "Ghidra project comments (untrusted)" not in block

class TestBridgeOrchestration:
    @pytest.mark.slow
    def test_import_project_writes_re_database(self, tmp_path, gpr_project):
        """Full import flow with mocked PyGhidra session."""
        out_dir = tmp_path / "output"

        from packages.ghidra.parser import parse_dict
        fake_db = parse_dict(SAMPLE_EXPORT)

        mock_session = type("MockSession", (), {
            "open": lambda self, *a, **kw: None,
            "export": lambda self, **kw: fake_db,
            "close": lambda self: None,
        })()

        # Pin the in-process route: import_project routes through
        # prefer_in_process(), and the default (headless subprocess)
        # requires a real analyzeHeadless on PATH — this test exercises
        # the PyGhidra session path with the session mocked.
        with patch("packages.ghidra.detect.prefer_in_process", return_value=True), \
             patch("packages.ghidra.bridge.pyghidra_available", return_value=True), \
             patch("packages.ghidra.bridge.GhidraSession", return_value=mock_session):
            from packages.ghidra.bridge import GhidraBridge
            bridge = GhidraBridge(gpr_project)
            db = bridge.import_project(out_dir)

        assert len(db.functions) == 2
        assert (out_dir / "re-database.json").exists()

        re_db = json.loads((out_dir / "re-database.json").read_text())
        assert re_db["source_tool"] == "ghidra"
        assert len(re_db["functions"]) == 2


class TestEnrichMetadataBinaryPath:
    """The project-metadata binary path is a free string inside the
    (attacker-controlled) project. A RELATIVE value is relative to the
    project directory — resolving it against the process CWD both
    breaks the bundled-sibling feature and probes the CWD for an
    attacker-chosen name."""

    def _enrich(self, gpr, metadata_path, monkeypatch, tmp_path):
        from packages.ghidra.bridge import GhidraBridge
        from packages.ghidra.model import REDatabase

        bridge = GhidraBridge(gpr)
        db = REDatabase(source_tool="ghidra", binary_path=metadata_path)
        monkeypatch.setattr(
            bridge, "import_project", lambda out: db, raising=True)
        seen = []

        def fake_r2(bin_path, out):
            seen.append(Path(bin_path))
            return None

        monkeypatch.setattr(bridge, "_run_r2", fake_r2, raising=True)
        bridge.import_and_enrich(tmp_path / "out")
        return seen

    def test_relative_path_anchors_at_project_dir(
            self, gpr_project, monkeypatch, tmp_path):
        bundled = gpr_project.parent / "firmware.bin"
        bundled.write_bytes(b"\x7fELF")
        seen = self._enrich(gpr_project, "firmware.bin",
                            monkeypatch, tmp_path)
        assert seen == [bundled]

    def test_relative_escape_is_ignored(
            self, gpr_project, monkeypatch, tmp_path):
        outside = gpr_project.parent.parent / "escape.bin"
        outside.write_bytes(b"\x7fELF")
        seen = self._enrich(gpr_project, "../escape.bin",
                            monkeypatch, tmp_path)
        assert seen == []

    def test_absolute_outside_path_is_ignored(
            self, gpr_project, monkeypatch, tmp_path):
        outside = gpr_project.parent.parent / "abs_elsewhere.bin"
        outside.write_bytes(b"\x7fELF")
        seen = self._enrich(gpr_project, str(outside),
                            monkeypatch, tmp_path)
        assert seen == []
