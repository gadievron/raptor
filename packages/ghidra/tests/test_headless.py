"""Tests for the analyzeHeadless wrapper contracts."""

from pathlib import Path
from types import SimpleNamespace

import pytest


class TestCreateProjectFromBinary:
    """Raw-binary project creation: sandboxed invocation shape, the
    RAPTOR-chosen project name, and the same refusal gates as the
    other headless entry points."""

    _HEADLESS = "/opt/ghidra/support/analyzeHeadless"

    def _stub(self, monkeypatch, calls, returncode=0):
        import packages.ghidra.headless as headless

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if returncode == 0:
                project_dir = Path(cmd[1])
                (project_dir / "raptor.gpr").write_text("")
                (project_dir / "raptor.rep").mkdir()
            return SimpleNamespace(
                returncode=returncode, stdout="", stderr="boom")

        monkeypatch.setattr(
            headless, "_find_headless", lambda: self._HEADLESS)
        monkeypatch.setattr("core.sandbox.run", fake_run)
        return headless

    def test_create_invokes_headless_and_returns_gpr(
            self, tmp_path, monkeypatch):
        binary = tmp_path / "firmware.bin"
        binary.write_bytes(b"\x7fELF")
        project_dir = tmp_path / "out" / "ghidra-project" / "firmware"
        calls: list = []
        headless = self._stub(monkeypatch, calls)

        gpr = headless.create_project_from_binary(binary, project_dir)

        assert gpr == project_dir / "raptor.gpr"
        assert project_dir.is_dir()  # mkdir parents happened
        cmd, kwargs = calls[0]
        assert cmd == [
            self._HEADLESS, str(project_dir), "raptor",
            "-import", str(binary.resolve()),
        ]
        # The JVM parses an attacker-supplied binary — the sandboxed,
        # network-denied invocation is a hard requirement.
        assert kwargs["block_network"] is True
        assert kwargs["restrict_reads"] is True
        assert kwargs["output"] == str(project_dir)
        assert kwargs["timeout"] == 3600

    def test_timeout_override_reaches_the_subprocess(
            self, tmp_path, monkeypatch):
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x7fELF")
        calls: list = []
        headless = self._stub(monkeypatch, calls)
        headless.create_project_from_binary(
            binary, tmp_path / "proj", timeout=123)
        assert calls[0][1]["timeout"] == 123

    def test_hidden_path_element_refused_before_launch(
            self, tmp_path, monkeypatch):
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x7fELF")
        calls: list = []
        headless = self._stub(monkeypatch, calls)
        with pytest.raises(headless.GhidraError, match="hidden"):
            headless.create_project_from_binary(
                binary, tmp_path / ".cache" / "fw")
        assert calls == []

    def test_preplaced_project_refused(self, tmp_path, monkeypatch):
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x7fELF")
        project_dir = tmp_path / "proj"
        project_dir.mkdir()
        (project_dir / "raptor.gpr").write_text("pre-placed")
        calls: list = []
        headless = self._stub(monkeypatch, calls)
        # The DISTINCT type is load-bearing: callers key terminal
        # (never degrade-to-fallback) handling on it.
        with pytest.raises(headless.GhidraProjectExistsError,
                           match="already exists"):
            headless.create_project_from_binary(binary, project_dir)
        assert calls == []
        # A refusal must never delete what it refused over — the
        # debris cleanup applies only to files this create made.
        assert (project_dir / "raptor.gpr").read_text() == "pre-placed"

    def test_nonzero_exit_raises(self, tmp_path, monkeypatch):
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x7fELF")
        calls: list = []
        headless = self._stub(monkeypatch, calls, returncode=1)
        with pytest.raises(headless.GhidraError, match="exited 1"):
            headless.create_project_from_binary(
                binary, tmp_path / "proj")

    def test_failed_create_removes_own_debris(
            self, tmp_path, monkeypatch):
        """A nonzero create exit must not strand partial project
        files for the next run's occupied-destination refusal to
        blame on the operator."""
        import packages.ghidra.headless as headless
        calls: list = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            project_dir = Path(cmd[1])
            (project_dir / "raptor.gpr").write_text("partial")
            (project_dir / "raptor.rep").mkdir()
            (project_dir / "raptor.lock").write_text("")
            return SimpleNamespace(
                returncode=1, stdout="", stderr="analysis crashed")

        monkeypatch.setattr(
            headless, "_find_headless", lambda: self._HEADLESS)
        monkeypatch.setattr("core.sandbox.run", fake_run)
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x7fELF")
        project_dir = tmp_path / "proj"
        with pytest.raises(headless.GhidraError, match="exited 1"):
            headless.create_project_from_binary(binary, project_dir)
        assert not (project_dir / "raptor.gpr").exists()
        assert not (project_dir / "raptor.rep").exists()
        assert not (project_dir / "raptor.lock").exists()
        # And the cleaned destination does not trip the
        # occupied-destination refusal on the retry: the retry gets
        # back to the (still failing) headless run, not a pre-launch
        # "already exists".
        with pytest.raises(headless.GhidraError, match="exited 1"):
            headless.create_project_from_binary(binary, project_dir)
        assert len(calls) == 2

    def test_symlinked_leaf_refused(self, tmp_path, monkeypatch):
        """The sandbox realpath-resolves grants: a symlinked
        destination would hand the JVM's write scope to the symlink's
        target."""
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x7fELF")
        victim = tmp_path / "victim"
        victim.mkdir()
        link = tmp_path / "proj"
        link.symlink_to(victim)
        calls: list = []
        headless = self._stub(monkeypatch, calls)
        with pytest.raises(headless.GhidraError, match="symlink"):
            headless.create_project_from_binary(binary, link)
        assert calls == []
        assert list(victim.iterdir()) == []

    def test_symlinked_intermediate_refused(
            self, tmp_path, monkeypatch):
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x7fELF")
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "mid"
        link.symlink_to(real)
        calls: list = []
        headless = self._stub(monkeypatch, calls)
        with pytest.raises(headless.GhidraError, match="symlink"):
            headless.create_project_from_binary(
                binary, link / "proj")
        assert calls == []
        assert list(real.iterdir()) == []

    def test_project_dir_argv_is_normalized_abspath(
            self, tmp_path, monkeypatch):
        """analyzeHeadless receives the textually normalized absolute
        destination — never a raw relative or ``..``-carrying form."""
        import os
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x7fELF")
        calls: list = []
        headless = self._stub(monkeypatch, calls)
        messy = tmp_path / "a" / ".." / "proj"
        gpr = headless.create_project_from_binary(binary, messy)
        cmd, _kwargs = calls[0]
        expected = os.path.abspath(str(tmp_path / "proj"))
        assert cmd[1] == expected
        assert gpr == Path(expected) / "raptor.gpr"


class TestCopyPreparedContract:
    def test_standalone_refuses_existing_destination(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        dst = tmp_path / "out" / "p.gpr"
        dst.parent.mkdir()
        dst.write_text("pre-placed")
        with pytest.raises(GhidraError, match="already exists"):
            import_enrichments(gpr, tmp_path / "e.json", dst)

    def test_copy_prepared_requires_copy(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        dst = tmp_path / "out" / "p.gpr"
        dst.parent.mkdir()
        with pytest.raises(GhidraError, match="no working copy"):
            import_enrichments(
                gpr, tmp_path / "e.json", dst, copy_prepared=True,
            )

    def test_name_mismatch_refused(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        with pytest.raises(GhidraError, match="project name"):
            import_enrichments(
                gpr, tmp_path / "e.json", tmp_path / "renamed.gpr",
            )

    def test_preplaced_rep_only_refused(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        dst = tmp_path / "out"
        dst.mkdir()
        (dst / "p.rep").mkdir()
        with pytest.raises(GhidraError, match="already exists"):
            import_enrichments(gpr, tmp_path / "e.json", dst / "p.gpr")


class TestCmdLogScrubbing:
    def test_both_running_log_sites_scrub_the_argv(self):
        # The argv embeds project/program names from the hostile
        # project database; both "running:" log sites must route
        # through the terminal sanitiser (drift guard).
        import inspect

        from packages.ghidra import headless
        src = inspect.getsource(headless)
        assert 'logger.info("running: %s", " ".join(cmd))' not in src
        assert src.count('sanitise_for_terminal(" ".join(cmd)') == 2
