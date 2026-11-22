"""Tests for packages.joern.slicing (joern-slice wrapper)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import packages.joern.slicing as slicing

# The real resolver, captured before the autouse fixture shadows it —
# TestPathResolution exercises resolution itself.
_REAL_JOERN_SLICE_PATH = slicing.joern_slice_path


VALID_DOC = {
    "$type": "DataFlowSlice",
    "nodes": [{"id": 1, "label": "CALL", "code": "x = read(fd, b, n)",
               "name": "read", "lineNumber": 7, "columnNumber": 3,
               "parentFile": "a.c", "parentMethod": "f"}],
    "edges": [],
}


@pytest.fixture
def cpg(tmp_path):
    p = tmp_path / "cache" / "cpg.bin"
    p.parent.mkdir()
    p.write_bytes(b"\x00cpg")
    return p


@pytest.fixture
def out_dir(tmp_path):
    return tmp_path / "run-out"


@pytest.fixture(autouse=True)
def fake_launcher(monkeypatch):
    monkeypatch.setattr(slicing, "joern_slice_path",
                        lambda: "/opt/joern/joern-slice")


def _writer_runner(out_dir, doc=VALID_DOC, returncode=0, record=None):
    """Sandbox-kwarg-accepting fake that writes the slice document."""
    def runner(cmd, **kwargs):
        if record is not None:
            record.append((cmd, kwargs))
        if doc is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "dataflow-slice.json").write_text(
                doc if isinstance(doc, str) else json.dumps(doc))
        return SimpleNamespace(returncode=returncode, stdout="", stderr="boom")
    return runner


class TestCommandShape:
    def test_argument_order_and_sandbox_kwargs(self, cpg, out_dir):
        seen = []
        errors = []
        doc = slicing.run_data_flow_slice(
            cpg, out_dir, slice_depth=12,
            subprocess_runner=_writer_runner(out_dir, record=seen),
            errors_out=errors)
        assert doc == VALID_DOC
        assert errors == []
        cmd, kwargs = seen[0]
        # JVM scratch wrap pins tmp + home inside the run-owned dir.
        resolved_out = str(out_dir.resolve())
        assert cmd[0] == "/usr/bin/env"
        assert f"TMPDIR={resolved_out}" in cmd
        assert f"HOME={resolved_out}" in cmd
        assert any(e.startswith("_JAVA_OPTIONS=") and resolved_out in e
                   for e in cmd)
        # Load-bearing CLI order: subcommand options BEFORE the CPG
        # positional, top-level options after it (the tool silently
        # ignores a positional placed before the subcommand options).
        i = cmd.index("/opt/joern/joern-slice")
        tail = cmd[i:]
        assert tail[1:4] == ["data-flow", "--slice-depth", "12"]
        assert tail[4] == str(cpg.resolve())
        assert tail[5:7] == ["-o", str(out_dir.resolve() / "dataflow-slice")]
        # Containment mirrors the CPG-build spawn.
        assert kwargs["block_network"] is True
        assert kwargs["output"] == resolved_out
        assert kwargs["target"] == str(cpg.resolve().parent)
        assert "limits" in kwargs and "tool_paths" in kwargs
        assert kwargs["timeout"] == 300

    def test_filters_appended_after_positional(self, cpg, out_dir):
        seen = []
        slicing.run_data_flow_slice(
            cpg, out_dir, file_filter="a.c", method_filter="parse_hdr",
            subprocess_runner=_writer_runner(out_dir, record=seen))
        cmd, _ = seen[0]
        pos = cmd.index(str(cpg.resolve()))
        assert cmd.index("--file-filter") > pos
        assert cmd[cmd.index("--file-filter") + 1] == "a.c"
        # Identifier is anchored so it cannot widen into a pattern.
        assert cmd[cmd.index("--method-name-filter") + 1] == "^parse_hdr$"

    def test_stub_runner_falls_back_to_cwd_pin(self, cpg, out_dir):
        seen = []

        def stub(cmd, *, capture_output, text, timeout, cwd):
            seen.append(cwd)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "dataflow-slice.json").write_text(json.dumps(VALID_DOC))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        doc = slicing.run_data_flow_slice(cpg, out_dir,
                                          subprocess_runner=stub)
        assert doc == VALID_DOC
        assert seen == [str(out_dir.resolve())]


class TestRefusals:
    def test_missing_cpg_refused(self, tmp_path, out_dir):
        errors = []
        assert slicing.run_data_flow_slice(
            tmp_path / "absent.bin", out_dir,
            subprocess_runner=_writer_runner(out_dir),
            errors_out=errors) is None
        assert any("CPG not found" in e for e in errors)

    def test_launcher_missing_refused(self, cpg, out_dir, monkeypatch):
        monkeypatch.setattr(slicing, "joern_slice_path", lambda: None)
        errors = []
        assert slicing.run_data_flow_slice(
            cpg, out_dir, subprocess_runner=_writer_runner(out_dir),
            errors_out=errors) is None
        assert any("not installed" in e for e in errors)

    def test_non_identifier_method_filter_refused_before_spawn(
            self, cpg, out_dir):
        seen = []
        errors = []
        assert slicing.run_data_flow_slice(
            cpg, out_dir, method_filter=".*|^",
            subprocess_runner=_writer_runner(out_dir, record=seen),
            errors_out=errors) is None
        assert seen == []
        assert any("identifier" in e for e in errors)

    def test_non_printable_file_filter_refused(self, cpg, out_dir):
        errors = []
        assert slicing.run_data_flow_slice(
            cpg, out_dir, file_filter="a\x1b]0;x\x07.c",
            subprocess_runner=_writer_runner(out_dir),
            errors_out=errors) is None
        assert any("non-printable" in e for e in errors)


class TestFailurePaths:
    def test_nonzero_exit_returns_none(self, cpg, out_dir):
        errors = []
        assert slicing.run_data_flow_slice(
            cpg, out_dir,
            subprocess_runner=_writer_runner(out_dir, returncode=3),
            errors_out=errors) is None
        assert any("exited 3" in e for e in errors)

    def test_zero_exit_without_document(self, cpg, out_dir):
        errors = []
        assert slicing.run_data_flow_slice(
            cpg, out_dir, subprocess_runner=_writer_runner(out_dir, doc=None),
            errors_out=errors) is None
        assert any("wrote no document" in e for e in errors)

    def test_stale_document_never_read_back(self, cpg, out_dir):
        # A document left by a previous attempt must not satisfy a run
        # whose own tool wrote nothing.
        out_dir.mkdir(parents=True)
        (out_dir / "dataflow-slice.json").write_text(json.dumps(VALID_DOC))
        errors = []
        assert slicing.run_data_flow_slice(
            cpg, out_dir, subprocess_runner=_writer_runner(out_dir, doc=None),
            errors_out=errors) is None
        assert any("wrote no document" in e for e in errors)

    def test_oversized_document_refused_unread(self, cpg, out_dir,
                                               monkeypatch):
        monkeypatch.setattr(slicing, "MAX_SLICE_BYTES", 16)
        errors = []
        assert slicing.run_data_flow_slice(
            cpg, out_dir, subprocess_runner=_writer_runner(out_dir),
            errors_out=errors) is None
        assert any("too large" in e for e in errors)

    def test_malformed_json_returns_none(self, cpg, out_dir):
        errors = []
        assert slicing.run_data_flow_slice(
            cpg, out_dir,
            subprocess_runner=_writer_runner(out_dir, doc="{not json"),
            errors_out=errors) is None
        assert any("unreadable" in e for e in errors)

    def test_wrong_shape_returns_none(self, cpg, out_dir):
        bad = {"$type": "Slice", "nodes": [], "edges": []}
        errors = []
        assert slicing.run_data_flow_slice(
            cpg, out_dir, subprocess_runner=_writer_runner(out_dir, doc=bad),
            errors_out=errors) is None
        assert any("unexpected shape" in e for e in errors)

    def test_errors_also_logged_without_errors_out(self, cpg, out_dir):
        # errors_out is optional — failure must not require it.
        assert slicing.run_data_flow_slice(
            cpg, out_dir,
            subprocess_runner=_writer_runner(out_dir, returncode=1)) is None


class TestPathResolution:
    def test_cache_reset_clears_resolution(self, monkeypatch):
        monkeypatch.setattr(slicing, "joern_slice_path",
                            _REAL_JOERN_SLICE_PATH)
        slicing.reset_slice_path_cache()
        monkeypatch.setattr(slicing, "_joern_parse_path", lambda: None)
        import shutil
        monkeypatch.setattr(shutil, "which", lambda name: None)
        try:
            assert slicing.joern_slice_path() is None
            # Cached: a second call must not re-resolve.
            monkeypatch.setattr(shutil, "which",
                                lambda name: "/late/joern-slice")
            assert slicing.joern_slice_path() is None
            slicing.reset_slice_path_cache()
            assert slicing.joern_slice_path() == "/late/joern-slice"
        finally:
            slicing.reset_slice_path_cache()

    def test_sibling_of_joern_parse_preferred(self, tmp_path, monkeypatch):
        monkeypatch.setattr(slicing, "joern_slice_path",
                            _REAL_JOERN_SLICE_PATH)
        slicing.reset_slice_path_cache()
        parse = tmp_path / "joern-cli" / "joern-parse"
        parse.parent.mkdir()
        parse.write_text("#!/bin/sh\n")
        sib = parse.parent / "joern-slice"
        sib.write_text("#!/bin/sh\n")
        sib.chmod(0o755)
        monkeypatch.setattr(slicing, "_joern_parse_path", lambda: str(parse))
        try:
            assert slicing.joern_slice_path() == str(sib)
        finally:
            slicing.reset_slice_path_cache()
