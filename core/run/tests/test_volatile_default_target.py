"""Volatile-target sanity gate on default-target resolution.

Receipt: a stale machine-generated corpus project (target /tmp) was
still active; a no-path command would have analysed /tmp under the
DEFAULT TARGET rules. The DEFAULT resolution now refuses scratch/
volatile active-project targets with a loud banner; explicit paths
always bypass (the gate guards only the implicit default).
"""

from __future__ import annotations

import tempfile
from unittest.mock import patch

from core.run.output import resolve_default_target, volatile_target_reason


class TestVolatileTargetReason:
    def test_system_temp_roots_flag(self):
        assert volatile_target_reason("/tmp") is not None
        assert volatile_target_reason("/var/tmp") is not None
        assert volatile_target_reason(tempfile.gettempdir()) is not None

    def test_nonexistent_path_flags(self, tmp_path):
        assert volatile_target_reason(str(tmp_path / "gone")) == (
            "does not exist"
        )

    def test_empty_dir_flags(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert volatile_target_reason(str(empty)) == "is an empty directory"

    def test_populated_dir_passes(self, tmp_path):
        (tmp_path / "main.c").write_text("int main(void){}\n")
        assert volatile_target_reason(str(tmp_path)) is None

    def test_temp_subdirectory_passes(self, tmp_path):
        """Checkouts under /tmp are legitimate — only the root flags.

        pytest's tmp_path lives under the system temp dir, so the
        populated-dir case above already exercises this; make the
        intent explicit with a direct child."""
        sub = tmp_path / "repo"
        sub.mkdir()
        (sub / "x.py").write_text("x = 1\n")
        assert volatile_target_reason(str(sub)) is None

    def test_file_target_passes(self, tmp_path):
        f = tmp_path / "binary"
        f.write_bytes(b"\x7fELF")
        assert volatile_target_reason(str(f)) is None

    def test_none_and_empty_pass(self):
        assert volatile_target_reason(None) is None
        assert volatile_target_reason("") is None


class TestResolveDefaultTargetGate:
    def test_volatile_active_project_refused_with_banner(
        self, capsys, monkeypatch,
    ):
        # Refusal must be total: no silent fallback to the caller dir
        # either — the operator decides.
        monkeypatch.setenv("RAPTOR_CALLER_DIR", "/some/real/dir")
        with patch(
            "core.run.output._resolve_active_project",
            return_value=("out", "corpus-1787231329", "/tmp"),
        ):
            assert resolve_default_target() is None
        err = capsys.readouterr().err
        assert "REFUSING default target" in err
        assert "corpus-1787231329" in err
        assert "/tmp" in err
        assert "explicitly" in err

    def test_healthy_active_project_resolves(self, tmp_path):
        (tmp_path / "src.c").write_text("int main(void){}\n")
        with patch(
            "core.run.output._resolve_active_project",
            return_value=("out", "myapp", str(tmp_path)),
        ):
            assert resolve_default_target() == str(tmp_path)

    def test_no_project_falls_back_to_caller_dir(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_CALLER_DIR", "/callers/dir")
        with patch(
            "core.run.output._resolve_active_project",
            return_value=None,
        ):
            assert resolve_default_target() == "/callers/dir"

    def test_nonexistent_project_target_refused(
        self, tmp_path, capsys,
    ):
        with patch(
            "core.run.output._resolve_active_project",
            return_value=("out", "p", str(tmp_path / "deleted")),
        ):
            assert resolve_default_target() is None
        assert "does not exist" in capsys.readouterr().err
