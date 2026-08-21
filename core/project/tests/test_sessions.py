"""Session-awareness registry — pruning, awareness lines, CLI + launcher wiring.

The registry is advisory only: these tests pin that entries round-trip
between the two writers (bash launcher, python ``/project use``), that
dead-pid entries prune at read time, and that the awareness line
surfaces on project switch and launcher startup — and nowhere else.
"""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project import sessions
from core.project.cli import main
from core.project.project import ProjectManager

REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "bin" / "raptor"

DEAD_PID = 999999999


class SessionsRegistryTest(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.sessions_dir = Path(self._tmp.name) / "sessions.d"
        p = patch.object(sessions, "SESSIONS_DIR", self.sessions_dir)
        p.start()
        self.addCleanup(p.stop)

    def _write_entry(self, pid: int, project: str,
                     since: str = "2026-08-20T00:00:00+00:00"):
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.sessions_dir / str(pid)).write_text(
            f"project={project}\nsince={since}\n", encoding="utf-8")

    def test_record_and_read_roundtrip(self):
        pid = sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(pid, os.getpid())
        entries = sessions.read_sessions()
        self.assertEqual(entries[os.getpid()]["project"], "myapp")
        self.assertIn("since", entries[os.getpid()])

    def test_record_none_clears_entry(self):
        sessions.record_session("myapp", pid=os.getpid())
        sessions.record_session(None, pid=os.getpid())
        self.assertNotIn(os.getpid(), sessions.read_sessions())

    def test_record_without_session_pid_is_noop(self):
        with patch.object(sessions, "session_pid", return_value=None):
            self.assertIsNone(sessions.record_session("myapp"))
        self.assertFalse(self.sessions_dir.exists())

    def test_dead_pid_entries_pruned_at_read(self):
        self._write_entry(DEAD_PID, "myapp")
        self._write_entry(os.getpid(), "myapp")
        entries = sessions.read_sessions()
        self.assertIn(os.getpid(), entries)
        self.assertNotIn(DEAD_PID, entries)
        self.assertFalse((self.sessions_dir / str(DEAD_PID)).exists(),
                         "dead entry not unlinked")

    def test_non_pid_files_left_alone(self):
        self.sessions_dir.mkdir(parents=True)
        stray = self.sessions_dir / "README"
        stray.write_text("not an entry", encoding="utf-8")
        sessions.read_sessions()
        self.assertTrue(stray.exists())

    def test_other_sessions_filters_project_and_self(self):
        self._write_entry(os.getpid(), "myapp",
                          since="2026-08-20T01:00:00+00:00")
        others = sessions.other_sessions("myapp")
        self.assertEqual([e["pid"] for e in others], [os.getpid()])
        # Excluding ourselves empties it.
        self.assertEqual(
            sessions.other_sessions("myapp", exclude_pid=os.getpid()), [])
        # Different project doesn't match.
        self.assertEqual(sessions.other_sessions("otherapp"), [])

    def test_registry_dir_is_private(self):
        """0700 on the registry dir — including tightening a
        pre-existing looser one."""
        self.sessions_dir.mkdir(parents=True, mode=0o755)
        sessions.record_session("myapp", pid=os.getpid())
        self.assertEqual(self.sessions_dir.stat().st_mode & 0o777, 0o700)

    def test_hostile_since_field_is_escaped_and_bounded(self):
        """Entry fields are file content — no raw escapes or floods in
        the awareness line."""
        self._write_entry(os.getpid(), "myapp",
                          since="2026\x1b[2J\x07" + "C" * 4000)
        lines = sessions.awareness_lines("myapp")
        self.assertEqual(len(lines), 1)
        self.assertNotIn("\x1b", lines[0])
        self.assertNotIn("\x07", lines[0])
        self.assertLess(len(lines[0]), 400)

    def test_awareness_line_wording(self):
        self._write_entry(os.getpid(), "myapp",
                          since="2026-08-20T01:00:00+00:00")
        lines = sessions.awareness_lines("myapp")
        self.assertEqual(lines, [
            f"project myapp is also active in session pid {os.getpid()} "
            f"(since 2026-08-20T01:00:00+00:00)"
        ])


class UseCommandAwarenessTest(unittest.TestCase):
    """/project use writes the registry and prints the awareness line."""

    FAKE_SELF = 555555

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.sessions_dir = root / "sessions.d"
        target = root / "code"
        target.mkdir()
        mgr = ProjectManager(projects_dir=self.projects_dir)
        mgr.create("myapp", str(target),
                   output_dir=str(root / "out" / "myapp"))
        for p in (
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            # `use` runs outside a real claude session here; give it a
            # deterministic fake session pid. The fake must read as
            # LIVE so its own freshly-written entry isn't pruned —
            # patch the liveness probe: our real pid + the fake are
            # alive, everything else dead.
            patch.object(sessions, "session_pid",
                         return_value=self.FAKE_SELF),
            patch.object(sessions, "_pid_running",
                         lambda pid: pid in (os.getpid(), self.FAKE_SELF)),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch.object(sys, "argv", ["raptor-project", *argv]), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                main()
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def test_use_records_entry(self):
        code, out, _ = self._run("use", "myapp")
        self.assertEqual(code, 0)
        entry = self.sessions_dir / str(self.FAKE_SELF)
        self.assertTrue(entry.exists())
        self.assertIn("project=myapp", entry.read_text(encoding="utf-8"))

    def test_use_prints_awareness_for_other_session(self):
        self.sessions_dir.mkdir(parents=True)
        (self.sessions_dir / str(os.getpid())).write_text(
            "project=myapp\nsince=2026-08-20T01:00:00+00:00\n",
            encoding="utf-8")
        code, out, _ = self._run("use", "myapp")
        self.assertEqual(code, 0)
        self.assertIn(
            f"project myapp is also active in session pid {os.getpid()}",
            out)

    def test_use_no_awareness_when_alone(self):
        code, out, _ = self._run("use", "myapp")
        self.assertEqual(code, 0)
        self.assertNotIn("also active", out)

    def test_use_none_clears_entry(self):
        self._run("use", "myapp")
        self._run("none")
        self.assertFalse(
            (self.sessions_dir / str(self.FAKE_SELF)).exists())


@unittest.skipIf(sys.platform == "win32", "bash launcher")
class LauncherAwarenessTest(unittest.TestCase):
    """The launcher prunes, warns, and registers before exec."""

    def _launch(self, home: Path, tmpdir: Path):
        path_dirs = [str(Path(sys.executable).resolve().parent)]
        path_dirs += [d for d in ("/usr/bin", "/bin") if os.path.isdir(d)]
        stub_dir = home / "stub-bin"
        stub_dir.mkdir(exist_ok=True)
        stub = stub_dir / "claude"
        stub.write_text("#!/usr/bin/env bash\necho STUB_CLAUDE_RAN\n",
                        encoding="utf-8")
        stub.chmod(0o755)
        return subprocess.run(
            ["bash", str(LAUNCHER)],
            capture_output=True, text=True, timeout=120, check=False,
            env={
                "PATH": ":".join([str(stub_dir)] + path_dirs),
                "HOME": str(home), "TMPDIR": str(tmpdir), "TERM": "xterm",
            },
            cwd=str(home),
        )

    def test_launcher_registers_prunes_and_warns(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            # Active project whose target is the launch cwd (home) so
            # startup-check sees no mismatch.
            mgr = ProjectManager(projects_dir=home / ".raptor" / "projects")
            mgr.create("myapp", str(home),
                       output_dir=str(root / "out" / "myapp"))
            mgr.set_active("myapp")
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            sessions_dir.mkdir(parents=True)
            # One live "other" session on the same project, one dead.
            (sessions_dir / str(os.getpid())).write_text(
                "project=myapp\nsince=2026-08-20T01:00:00+00:00\n",
                encoding="utf-8")
            (sessions_dir / str(DEAD_PID)).write_text(
                "project=myapp\nsince=2026-08-20T01:00:00+00:00\n",
                encoding="utf-8")
            r = self._launch(home, tmpdir)
            self.assertIn("STUB_CLAUDE_RAN", r.stdout,
                          (r.stdout, r.stderr))
            self.assertIn(
                f"project myapp is also active in session pid {os.getpid()}",
                r.stderr)
            self.assertNotIn(str(DEAD_PID), r.stderr,
                             "dead session produced an awareness line")
            self.assertFalse((sessions_dir / str(DEAD_PID)).exists(),
                             "dead entry not pruned at launch")
            # The launcher registered its own (now-exited) session.
            own = [f for f in sessions_dir.iterdir()
                   if f.name.isdigit()
                   and f.name not in (str(os.getpid()), str(DEAD_PID))]
            self.assertEqual(len(own), 1, list(sessions_dir.iterdir()))
            self.assertIn("project=myapp",
                          own[0].read_text(encoding="utf-8"))
            self.assertEqual(sessions_dir.stat().st_mode & 0o777, 0o700,
                             "registry dir readable by other users")

    def test_launcher_awareness_escapes_hostile_since(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            tmpdir = root / "tmp"
            tmpdir.mkdir()
            mgr = ProjectManager(projects_dir=home / ".raptor" / "projects")
            mgr.create("myapp", str(home),
                       output_dir=str(root / "out" / "myapp"))
            mgr.set_active("myapp")
            sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
            sessions_dir.mkdir(parents=True)
            (sessions_dir / str(os.getpid())).write_text(
                "project=myapp\nsince=2026\x1b[2J\x07" + "C" * 4000 + "\n",
                encoding="utf-8")
            r = self._launch(home, tmpdir)
            self.assertIn("also active in session pid", r.stderr)
            self.assertNotIn("\x1b", r.stderr, "raw ESC reached stderr")
            self.assertNotIn("\x07", r.stderr)
            line = next(ln for ln in r.stderr.splitlines()
                        if "also active" in ln)
            self.assertLess(len(line), 300, "since field flooded the line")


if __name__ == "__main__":
    unittest.main()
