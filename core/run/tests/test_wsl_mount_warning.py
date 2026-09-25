"""Windows-interop (drvfs/9p) mount advisory at the output-resolution
chokepoints.

Warn-only by design: the default-target arms and every
``get_output_dir`` arm print one advisory line when the resolved path
sits on a Windows-interop mount on a WSL host, and the resolution
result is byte-identical either way. Hermetic — WSL-ness and the
mount probe are monkeypatched; no test depends on the host
filesystem.
"""

from __future__ import annotations

from contextlib import ExitStack
from unittest import mock

import pytest

from core.run.output import get_output_dir, resolve_default_target
from core.startup import wsl


@pytest.fixture
def on_interop_mount():
    """Pretend every probed path is a drvfs/9p mount on a WSL host."""
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(
            wsl, "is_wsl", return_value=True))
        stack.enter_context(mock.patch.object(
            wsl, "fs_is_drvfs_or_9p", return_value=True))
        yield


def _active_project(tmp_path):
    target = tmp_path / "repo"
    target.mkdir(exist_ok=True)
    (target / "main.c").write_text("int main(void){}\n")
    return (str(tmp_path / "proj-out"), "proj", str(target))


class TestResolveDefaultTarget:
    def test_project_target_warns_and_resolves(
            self, tmp_path, capsys, on_interop_mount):
        active = _active_project(tmp_path)
        with mock.patch("core.run.output._resolve_active_project",
                        return_value=active):
            got = resolve_default_target()
        assert got == active[2]
        err = capsys.readouterr().err
        assert "default target (active project)" in err
        assert "drvfs/9p" in err
        assert "docs/wsl.md" in err

    def test_caller_dir_warns_and_resolves(
            self, tmp_path, capsys, on_interop_mount, monkeypatch):
        target = tmp_path / "checkout"
        target.mkdir()
        (target / "x.py").write_text("x = 1\n")
        monkeypatch.setenv("RAPTOR_CALLER_DIR", str(target))
        with mock.patch("core.run.output._resolve_active_project",
                        return_value=None):
            got = resolve_default_target()
        assert got == str(target)
        assert "default target (RAPTOR_CALLER_DIR)" in \
            capsys.readouterr().err

    def test_off_wsl_is_silent(self, tmp_path, capsys):
        active = _active_project(tmp_path)
        with mock.patch("core.run.output._resolve_active_project",
                        return_value=active), \
             mock.patch.object(wsl, "is_wsl", return_value=False):
            got = resolve_default_target()
        assert got == active[2]
        assert "drvfs/9p" not in capsys.readouterr().err


class TestGetOutputDir:
    def test_standalone_out_dir_warns(
            self, capsys, on_interop_mount):
        with mock.patch("core.run.output._resolve_active_project",
                        return_value=None):
            out = get_output_dir("scan", target_name="repo")
        assert out.name.startswith("scan_repo_")
        err = capsys.readouterr().err
        assert "output directory" in err
        assert "drvfs/9p" in err

    def test_explicit_out_warns(self, tmp_path, capsys, on_interop_mount):
        with mock.patch("core.run.output._resolve_active_project",
                        return_value=None):
            out = get_output_dir(
                "scan", explicit_out=str(tmp_path / "custom"))
        assert out == (tmp_path / "custom").resolve()
        assert "output directory (--out)" in capsys.readouterr().err

    def test_project_run_dir_warns(
            self, tmp_path, capsys, on_interop_mount):
        active = _active_project(tmp_path)
        with mock.patch("core.run.output._resolve_active_project",
                        return_value=active):
            out = get_output_dir("scan", target_path=active[2])
        assert str(out).startswith(active[0])
        assert "output directory" in capsys.readouterr().err

    def test_off_wsl_is_silent(self, capsys):
        with mock.patch("core.run.output._resolve_active_project",
                        return_value=None), \
             mock.patch.object(wsl, "is_wsl", return_value=False):
            get_output_dir("scan", target_name="repo")
        assert "drvfs/9p" not in capsys.readouterr().err
