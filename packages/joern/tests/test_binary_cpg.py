"""Tests for packages.joern.binary_cpg (ghidra2cpg wrapper)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import packages.joern.binary_cpg as binary_cpg

_REAL_GHIDRA2CPG_PATH = binary_cpg.ghidra2cpg_path


@pytest.fixture
def binary(tmp_path):
    p = tmp_path / "bin" / "target"
    p.parent.mkdir()
    p.write_bytes(b"\x7fELF-ish")
    return p


@pytest.fixture
def out_dir(tmp_path):
    return tmp_path / "run-out" / "joern-ghidra"


@pytest.fixture(autouse=True)
def fake_launcher(monkeypatch):
    monkeypatch.setattr(binary_cpg, "ghidra2cpg_path",
                        lambda: "/opt/joern/ghidra2cpg")


def _writer_runner(out_dir, *, payload=b"CPG", returncode=0, record=None):
    """Sandbox-kwarg-accepting fake that writes cpg.bin."""
    def runner(cmd, **kwargs):
        if record is not None:
            record.append((cmd, kwargs))
        if payload is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "cpg.bin").write_bytes(payload)
        return SimpleNamespace(returncode=returncode, stdout="", stderr="eep")
    return runner


class TestCommandShape:
    def test_cmd_order_and_sandbox_kwargs(self, binary, out_dir):
        seen = []
        errors = []
        cpg = binary_cpg.build_ghidra_cpg(
            binary, out_dir, timeout=42,
            subprocess_runner=_writer_runner(out_dir, record=seen),
            errors_out=errors)
        assert cpg == out_dir.resolve() / "cpg.bin"
        assert errors == []
        cmd, kwargs = seen[0]
        resolved_out = str(out_dir.resolve())
        # JVM/Ghidra scratch pinned inside the run-owned dir — Ghidra
        # writes project state under HOME.
        assert cmd[0] == "/usr/bin/env"
        assert f"TMPDIR={resolved_out}" in cmd
        assert f"HOME={resolved_out}" in cmd
        assert any(e.startswith("_JAVA_OPTIONS=") and resolved_out in e
                   for e in cmd)
        i = cmd.index("/opt/joern/ghidra2cpg")
        assert cmd[i + 1] == str(binary.resolve())
        assert cmd[i + 2:i + 4] == ["-o", str(out_dir.resolve() / "cpg.bin")]
        assert kwargs["block_network"] is True
        assert kwargs["target"] == str(binary.resolve().parent)
        assert kwargs["output"] == resolved_out
        assert kwargs["timeout"] == 42
        assert "limits" in kwargs and "tool_paths" in kwargs

    def test_stub_runner_falls_back_to_cwd_pin(self, binary, out_dir):
        seen = []

        def stub(cmd, *, capture_output, text, timeout, cwd):
            seen.append(cwd)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "cpg.bin").write_bytes(b"CPG")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        cpg = binary_cpg.build_ghidra_cpg(binary, out_dir,
                                          subprocess_runner=stub)
        assert cpg is not None
        assert seen == [str(out_dir.resolve())]


class TestFailurePaths:
    def test_missing_binary_refused(self, tmp_path, out_dir):
        errors = []
        assert binary_cpg.build_ghidra_cpg(
            tmp_path / "absent", out_dir,
            subprocess_runner=_writer_runner(out_dir),
            errors_out=errors) is None
        assert any("binary not found" in e for e in errors)

    def test_launcher_missing_refused(self, binary, out_dir, monkeypatch):
        monkeypatch.setattr(binary_cpg, "ghidra2cpg_path", lambda: None)
        errors = []
        assert binary_cpg.build_ghidra_cpg(
            binary, out_dir, subprocess_runner=_writer_runner(out_dir),
            errors_out=errors) is None
        assert any("not installed" in e for e in errors)

    def test_nonzero_exit_returns_none(self, binary, out_dir):
        errors = []
        assert binary_cpg.build_ghidra_cpg(
            binary, out_dir,
            subprocess_runner=_writer_runner(out_dir, returncode=2),
            errors_out=errors) is None
        assert any("exited 2" in e for e in errors)

    def test_zero_exit_without_graph(self, binary, out_dir):
        errors = []
        assert binary_cpg.build_ghidra_cpg(
            binary, out_dir,
            subprocess_runner=_writer_runner(out_dir, payload=None),
            errors_out=errors) is None
        assert any("wrote no graph" in e for e in errors)

    def test_empty_graph_refused(self, binary, out_dir):
        errors = []
        assert binary_cpg.build_ghidra_cpg(
            binary, out_dir,
            subprocess_runner=_writer_runner(out_dir, payload=b""),
            errors_out=errors) is None
        assert any("wrote no graph" in e for e in errors)

    def test_stale_graph_never_returned(self, binary, out_dir):
        # A cpg.bin left by a previous attempt must not satisfy a
        # build whose own tool wrote nothing.
        out_dir.mkdir(parents=True)
        (out_dir / "cpg.bin").write_bytes(b"OLD")
        errors = []
        assert binary_cpg.build_ghidra_cpg(
            binary, out_dir,
            subprocess_runner=_writer_runner(out_dir, payload=None),
            errors_out=errors) is None
        assert any("wrote no graph" in e for e in errors)


class TestPathResolution:
    def test_sibling_of_joern_parse_preferred(self, tmp_path, monkeypatch):
        monkeypatch.setattr(binary_cpg, "ghidra2cpg_path",
                            _REAL_GHIDRA2CPG_PATH)
        binary_cpg.reset_ghidra_path_cache()
        parse = tmp_path / "joern-cli" / "joern-parse"
        parse.parent.mkdir()
        parse.write_text("#!/bin/sh\n")
        sib = parse.parent / "ghidra2cpg"
        sib.write_text("#!/bin/sh\n")
        sib.chmod(0o755)
        monkeypatch.setattr(binary_cpg, "_joern_parse_path",
                            lambda: str(parse))
        try:
            assert binary_cpg.ghidra2cpg_path() == str(sib)
        finally:
            binary_cpg.reset_ghidra_path_cache()

    def test_cache_reset_clears_resolution(self, monkeypatch):
        monkeypatch.setattr(binary_cpg, "ghidra2cpg_path",
                            _REAL_GHIDRA2CPG_PATH)
        binary_cpg.reset_ghidra_path_cache()
        monkeypatch.setattr(binary_cpg, "_joern_parse_path", lambda: None)
        import shutil
        monkeypatch.setattr(shutil, "which", lambda name: None)
        try:
            assert binary_cpg.ghidra2cpg_path() is None
            monkeypatch.setattr(shutil, "which",
                                lambda name: "/late/ghidra2cpg")
            assert binary_cpg.ghidra2cpg_path() is None  # cached
            binary_cpg.reset_ghidra_path_cache()
            assert binary_cpg.ghidra2cpg_path() == "/late/ghidra2cpg"
        finally:
            binary_cpg.reset_ghidra_path_cache()
