"""``libexec/raptor-frida`` project-pin contract.

An explicit ``--project`` only takes effect through the lifecycle
start, which a caller-supplied ``--out`` bypasses — the wrapper must
hard-error on the combination instead of silently dropping the pin.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-frida"

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="bash wrapper",
)


def _run(args: list[str], tmp_path: Path,
         stub_python: bool = False) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    if stub_python:
        # Replace python3 with a fast no-op so the wrapper's tail (the
        # actual Frida CLI launch) is hermetic.
        stub_dir = tmp_path / "stub-bin"
        stub_dir.mkdir(exist_ok=True)
        stub = stub_dir / "python3"
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP
                   | stat.S_IXOTH)
        env["PATH"] = f"{stub_dir}:{env['PATH']}"
    return subprocess.run(
        ["bash", str(CLI), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


class TestProjectWithOut:
    def test_project_plus_out_hard_errors(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        res = _run(
            ["--target", "someprocess", "--template", "syscalls",
             "--out", str(out), "--project", "myproj"],
            tmp_path,
        )
        assert res.returncode == 3
        assert "--project cannot be combined with --out" in res.stderr

    def test_out_without_project_still_runs(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        res = _run(
            ["--target", "someprocess", "--template", "syscalls",
             "--out", str(out)],
            tmp_path,
            stub_python=True,
        )
        assert res.returncode == 0, res.stderr
        assert "cannot be combined" not in res.stderr
