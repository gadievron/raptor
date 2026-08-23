"""The production bash coverage hook (plugins/coverage/libexec/
raptor-hook-read) appends to the run's reads-manifest. Regression:
the append used bare ``>>`` with no symlink guard while its Python
twin (core/coverage/track_read.py) documents and defends the exact
attack with O_NOFOLLOW — a symlink planted at
``<run_dir>/.reads-manifest`` by a sandboxed child (run_dir is the
sandbox's writable output path) redirected the unsandboxed hook's
writes to an arbitrary user file."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK = REPO_ROOT / "plugins" / "coverage" / "libexec" / "raptor-hook-read"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash not available",
)


@pytest.fixture
def hook_env(tmp_path):
    """Fake HOME with an active project and one running run."""
    home = tmp_path / "home"
    target = tmp_path / "target"
    target.mkdir(parents=True)
    (target / "a.py").write_text("x = 1\n")

    projects = home / ".raptor" / "projects"
    projects.mkdir(parents=True)
    project_dir = tmp_path / "proj-out"
    run_dir = project_dir / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"status": "running"}),
    )
    (projects / "myproj").write_text(json.dumps({
        "output_dir": str(project_dir),
        "target": str(target),
    }))
    (projects / ".active").symlink_to("myproj")

    env = dict(os.environ)
    env["HOME"] = str(home)
    return {"env": env, "target": target, "run_dir": run_dir}


def _fire(hook_env, file_path: Path) -> subprocess.CompletedProcess:
    payload = json.dumps({"tool_input": {"file_path": str(file_path)}})
    return subprocess.run(
        ["bash", str(HOOK)],
        input=payload,
        env=hook_env["env"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_normal_append_records_read(hook_env):
    proc = _fire(hook_env, hook_env["target"] / "a.py")
    assert proc.returncode == 0, proc.stderr
    manifest = hook_env["run_dir"] / ".reads-manifest"
    assert manifest.is_file()
    assert manifest.read_text().strip() == str(
        (hook_env["target"] / "a.py").resolve(),
    )


def test_symlinked_manifest_is_refused(hook_env, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("original\n")
    manifest = hook_env["run_dir"] / ".reads-manifest"
    manifest.symlink_to(victim)

    proc = _fire(hook_env, hook_env["target"] / "a.py")
    assert proc.returncode == 0, proc.stderr
    # Nothing appended through the symlink; victim untouched.
    assert victim.read_text() == "original\n"


def test_dangling_symlink_not_followed_on_create(hook_env, tmp_path):
    # O_CREAT through a dangling symlink would create the TARGET.
    victim = tmp_path / "never-created"
    manifest = hook_env["run_dir"] / ".reads-manifest"
    manifest.symlink_to(victim)

    proc = _fire(hook_env, hook_env["target"] / "a.py")
    assert proc.returncode == 0, proc.stderr
    assert not victim.exists()
