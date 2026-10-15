"""The launcher selects an installed Python environment without invoking uv.

Each candidate environment has a distinct interpreter executable so these
tests exercise the launcher's selection order rather than an argv-forwarding
stub. A failing ``uv`` executable pins that launch never creates or syncs an
environment.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _write_interpreter(path: Path, identity: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\nprintf '%s\\n' {identity!r}\n")
    path.chmod(0o755)


def _write_python_entry_point(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env python3\n")
    path.chmod(0o755)


def _make_tree(root: Path) -> Path:
    (root / "bin").mkdir()
    (root / "core" / "security").mkdir(parents=True)
    shutil.copy2(_REPO / "bin" / "raptor", root / "bin" / "raptor")
    shutil.copy2(
        _REPO / "core" / "security" / "_dangerous_env_strip.sh",
        root / "core" / "security" / "_dangerous_env_strip.sh",
    )
    tools = root / "tools"
    tools.mkdir()
    _write_interpreter(tools / "python3", "system")
    uv = tools / "uv"
    uv.write_text("#!/bin/sh\necho 'uv must not run' >&2\nexit 97\n")
    uv.chmod(0o755)
    return tools


def _run(root: Path, tools: Path, *args: str, extra_env: dict | None = None):
    env = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "PATH": f"{tools}:/usr/bin:/bin",
        "RAPTOR_WORK_DIR": str(root / "work"),
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(root / "bin" / "raptor"), *args],
        capture_output=True,
        cwd=root,
        text=True,
        timeout=60,
        env=env,
    )


class TestLauncherPythonEnvironment(unittest.TestCase):
    def test_active_virtualenv_takes_precedence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root)
            _write_interpreter(root / ".venv" / "bin" / "python3", "project")
            active = root / "active"
            _write_interpreter(active / "bin" / "python3", "active")

            proc = _run(
                root,
                tools,
                "--version",
                extra_env={
                    "PATH": f"{active / 'bin'}:{tools}:/usr/bin:/bin",
                    "VIRTUAL_ENV": str(active),
                },
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "active\n")

    def test_project_virtualenv_takes_precedence_over_path(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root)
            _write_interpreter(root / ".venv" / "bin" / "python3", "project")

            proc = _run(root, tools, "--version")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "project\n")

    def test_selected_environment_leads_path_for_python_shebangs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root)
            project_bin = root / ".venv" / "bin"
            _write_interpreter(project_bin / "python3", "project")
            _write_python_entry_point(root / "libexec" / "raptor-project-manager")

            proc = _run(
                root,
                tools,
                "project",
                extra_env={
                    "PATH": f"{tools}:/usr/bin:/bin:{project_bin}",
                },
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "project\n")

    def test_python3_on_path_is_the_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root)

            proc = _run(root, tools, "--version")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "system\n")

    def test_relative_virtualenv_dropped_from_path_is_not_selected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root)
            _write_interpreter(root / "active" / "bin" / "python3", "active")

            proc = _run(
                root,
                tools,
                "--version",
                extra_env={
                    "PATH": f"active/bin:{tools}:/usr/bin:/bin",
                    "VIRTUAL_ENV": "active",
                },
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "system\n")
            self.assertIn("dropped unsafe PATH entry (relative entry)", proc.stderr)

    def test_world_writable_virtualenv_dropped_from_path_is_not_selected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root)
            active = root / "active"
            _write_interpreter(active / "bin" / "python3", "active")
            (active / "bin").chmod(0o777)

            proc = _run(
                root,
                tools,
                "--version",
                extra_env={
                    "PATH": f"{active / 'bin'}:{tools}:/usr/bin:/bin",
                    "VIRTUAL_ENV": str(active),
                },
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "system\n")
            self.assertIn("dropped unsafe PATH entry (world-writable dir)", proc.stderr)

    def test_unsafe_path_override_keeps_active_virtualenv(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root)
            _write_interpreter(root / "active" / "bin" / "python3", "active")

            proc = _run(
                root,
                tools,
                "--version",
                extra_env={
                    "PATH": f"active/bin:{tools}:/usr/bin:/bin",
                    "RAPTOR_ALLOW_UNSAFE_PATH": "1",
                    "VIRTUAL_ENV": "active",
                },
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "active\n")
            self.assertIn("keeping unsafe PATH entry", proc.stderr)

    def test_help_does_not_invoke_uv_or_python(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            tools = _make_tree(root)

            proc = _run(root, tools, "--help")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("Usage: raptor", proc.stdout)
            self.assertNotIn("system", proc.stdout)
            self.assertNotIn("uv must not run", proc.stderr)


if __name__ == "__main__":
    unittest.main()
