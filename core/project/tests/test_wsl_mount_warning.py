"""Windows-interop (drvfs/9p) mount advisory on project creation.

Warn-only: creating a project whose target or output dir sits on a
Windows-interop mount (WSL host) prints one advisory line per
affected path and the project is created exactly as before. Hermetic
— WSL-ness and the mount probe are monkeypatched.
"""

from __future__ import annotations

from contextlib import ExitStack
from unittest import mock

import pytest

from core.project.project import ProjectManager
from core.startup import wsl


@pytest.fixture
def on_interop_mount():
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(
            wsl, "is_wsl", return_value=True))
        stack.enter_context(mock.patch.object(
            wsl, "fs_is_drvfs_or_9p", return_value=True))
        yield


def _mgr(tmp_path) -> ProjectManager:
    return ProjectManager(projects_dir=tmp_path / "projects")


def test_create_warns_on_interop_target_and_out(
        tmp_path, capsys, on_interop_mount):
    target = tmp_path / "repo"
    target.mkdir()
    project = _mgr(tmp_path).create(
        "myapp", str(target), output_dir=str(tmp_path / "out"))
    assert project.name == "myapp"  # creation itself is untouched
    err = capsys.readouterr().err
    assert "project target" in err
    assert "project output directory" in err
    assert "drvfs/9p" in err
    assert "docs/wsl.md" in err


def test_create_url_target_skips_target_advisory(
        tmp_path, capsys, on_interop_mount):
    project = _mgr(tmp_path).create(
        "webapp", "https://example.com", output_dir=str(tmp_path / "out"))
    assert project.target == "https://example.com"
    err = capsys.readouterr().err
    assert "project target" not in err  # URLs are not filesystem paths
    assert "project output directory" in err


def test_create_off_wsl_is_silent(tmp_path, capsys):
    target = tmp_path / "repo"
    target.mkdir()
    with mock.patch.object(wsl, "is_wsl", return_value=False):
        _mgr(tmp_path).create(
            "quiet", str(target), output_dir=str(tmp_path / "out"))
    assert "drvfs/9p" not in capsys.readouterr().err
