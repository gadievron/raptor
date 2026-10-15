"""The launcher re-execs itself under ``uv run`` (the documented
``uv sync --locked`` environment).

Builds a throwaway RAPTOR tree holding a copy of ``bin/raptor`` and a
stub ``uv`` that logs its argv and then runs the command after ``--``,
the way ``uv run`` does. A stub ``python3`` stands in for the project
interpreter so the ``--version`` fast path has something to exec.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _make_tree(root: Path, *, with_uv: bool) -> Path:
    (root / "bin").mkdir()
    (root / "core" / "security").mkdir(parents=True)
    shutil.copy2(_REPO / "bin" / "raptor", root / "bin" / "raptor")
    shutil.copy2(
        _REPO / "core" / "security" / "_dangerous_env_strip.sh",
        root / "core" / "security" / "_dangerous_env_strip.sh",
    )
    tools = root / "tools"
    tools.mkdir()
    py = tools / "python3"
    py.write_text("#!/bin/sh\necho PYTHON3 \"$@\"\n")
    py.chmod(0o755)
    if with_uv:
        uv = tools / "uv"
        uv.write_text(
            "#!/bin/sh\n"
            f"echo \"$@\" >> '{root}/uv.log'\n"
            "while [ \"$1\" != \"--\" ]; do shift; done\n"
            "shift\n"
            "exec \"$@\"\n"
        )
        uv.chmod(0o755)
    return tools


def _run_version(root: Path, tools: Path, extra_env: dict | None = None):
    env = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "PATH": f"{tools}:/usr/bin:/bin",
        "RAPTOR_WORK_DIR": str(root / "work"),
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(root / "bin" / "raptor"), "--version"],
        capture_output=True, text=True, timeout=60, env=env,
    )


class TestLauncherUvRun(unittest.TestCase):
    def test_reexecs_once_under_uv_run(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root, with_uv=True)
            proc = _run_version(root, tools)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("PYTHON3", proc.stdout)
            calls = (root / "uv.log").read_text().splitlines()
            self.assertEqual(len(calls), 1, calls)
            self.assertTrue(calls[0].startswith(
                f"run --project {root} --locked -- bash "
            ), calls[0])
            self.assertTrue(calls[0].endswith("bin/raptor --version"), calls[0])

    def test_runs_directly_without_uv(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root, with_uv=False)
            if shutil.which("uv", path="/usr/bin:/bin"):
                self.skipTest("system uv on /usr/bin:/bin")
            proc = _run_version(root, tools)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("PYTHON3", proc.stdout)
            self.assertFalse((root / "uv.log").exists())


if __name__ == "__main__":
    unittest.main()
