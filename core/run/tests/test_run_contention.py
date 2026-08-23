"""Run-start contention on managed project dirs — hermetic tests.

Design under test (see ``core.run.metadata._project_run_gate``): the
run itself is represented by its metadata (``status=running`` + a live
recorded ``session_pid``), NOT by a flock — the stub-based
``raptor-run-lifecycle start``/``complete`` flow spans processes, so
no single process could hold a lock for the run's duration. The
``.op.lock`` flock only guards the [contention check → metadata write]
window. Consequences pinned here:

* another session's live run refuses a new start IMMEDIATELY, naming
  the holder;
* a crashed run (running status, dead pid) never blocks;
* same-session parallel runs stay legal;
* ``wait_for_project=True`` queues until the live run finishes;
* non-project dirs never contend.

PID liveness and session identity are patched — no real claude
processes are involved.
"""

from __future__ import annotations

import json
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.json import load_json, save_json
from core.project.oplock import OpLockContention, ProjectRunContention
from core.project.project import ProjectManager
from core.run.metadata import (
    RUN_METADATA_FILE,
    _live_conflicting_run,
    start_run,
)

SELF_SESSION = 11111
OTHER_SESSION = 22222


class RunContentionBase(unittest.TestCase):
    """Temp project registry + a managed project output dir.

    Liveness is patched by default (OTHER_SESSION alive, all else
    dead) for BOTH probes — the gate's and _cleanup_abandoned's — so
    fake siblings neither sweep nor contend for the wrong reason.
    Set ``LIVENESS_PATCHES = False`` to exercise the real probes.
    """

    LIVENESS_PATCHES = True

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        target = root / "code"
        target.mkdir()
        self.project_out = root / "out" / "myapp"
        mgr = ProjectManager(projects_dir=self.projects_dir)
        mgr.create("myapp", str(target), output_dir=str(self.project_out))

        self._patches = [
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            # We are SELF_SESSION.
            patch("core.run.metadata._get_session_pid",
                  lambda: SELF_SESSION),
        ]
        if self.LIVENESS_PATCHES:
            self._patches += [
                patch("core.run.metadata._gate_session_alive",
                      lambda pid: pid == OTHER_SESSION),
                patch("core.run.metadata._pid_alive",
                      lambda pid: pid == OTHER_SESSION),
            ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def _write_sibling(self, name="scan_20260101_000000",
                       status="running", session_pid=OTHER_SESSION,
                       command="scan"):
        d = self.project_out / name
        d.mkdir(parents=True, exist_ok=True)
        meta = {
            "version": 2,
            "command": command,
            "timestamp": "2026-01-01T00:00:00+00:00",
            "status": status,
        }
        if session_pid is not None:
            meta["session_pid"] = session_pid
        save_json(d / RUN_METADATA_FILE, meta)
        return d


class LiveConflictScanTest(RunContentionBase):

    def _scan(self, self_dir="agentic_new"):
        return _live_conflicting_run(
            self.project_out, self.project_out / self_dir, SELF_SESSION)

    def test_other_session_live_run_is_contention(self):
        self._write_sibling()
        holder = self._scan()
        self.assertIsNotNone(holder)
        self.assertEqual(holder["pid"], OTHER_SESSION)
        self.assertEqual(holder["operation"], "scan")
        self.assertEqual(holder["run_dir"], "scan_20260101_000000")

    def test_dead_owner_is_not_contention(self):
        self._write_sibling(session_pid=99999)  # dead per the patch
        self.assertIsNone(self._scan())

    def test_same_session_is_not_contention(self):
        self._write_sibling(session_pid=SELF_SESSION)
        self.assertIsNone(self._scan())

    def test_completed_run_is_not_contention(self):
        self._write_sibling(status="completed")
        self.assertIsNone(self._scan())

    def test_no_recorded_pid_is_not_contention(self):
        self._write_sibling(session_pid=None)
        self.assertIsNone(self._scan())

    def test_self_dir_is_excluded(self):
        self._write_sibling(name="agentic_new")
        self.assertIsNone(self._scan(self_dir="agentic_new"))

    def test_corrupt_sibling_metadata_is_skipped(self):
        d = self.project_out / "junk_run"
        d.mkdir(parents=True)
        (d / RUN_METADATA_FILE).write_text("{not json", encoding="utf-8")
        self.assertIsNone(self._scan())


class StartRunGateTest(RunContentionBase):

    def test_contention_refuses_immediately_with_holder(self):
        self._write_sibling()
        out = self.project_out / "agentic_20260102_000000"
        with self.assertRaises(ProjectRunContention) as cm:
            start_run(out, "agentic")
        msg = str(cm.exception)
        self.assertIn(str(OTHER_SESSION), msg)
        self.assertIn("scan", msg)
        self.assertIn("--wait", msg)
        # ProjectRunContention is an OpLockContention — one handler at
        # each CLI boundary covers both contention shapes.
        self.assertIsInstance(cm.exception, OpLockContention)
        # A refused start leaves nothing behind.
        self.assertFalse(out.exists())

    def test_crashed_run_does_not_block_start(self):
        self._write_sibling(session_pid=99999)  # dead pid
        out = self.project_out / "agentic_20260102_000000"
        start_run(out, "agentic")
        meta = load_json(out / RUN_METADATA_FILE)
        self.assertEqual(meta["status"], "running")

    def test_same_session_parallel_start_allowed(self):
        self._write_sibling(session_pid=SELF_SESSION)
        out = self.project_out / "agentic_20260102_000000"
        start_run(out, "agentic")
        self.assertTrue((out / RUN_METADATA_FILE).exists())

    def test_non_project_dir_never_contends(self):
        plain = Path(self._tmp.name) / "plain-out"
        sibling = plain / "scan_20260101_000000"
        sibling.mkdir(parents=True)
        save_json(sibling / RUN_METADATA_FILE, {
            "version": 2, "command": "scan", "status": "running",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "session_pid": OTHER_SESSION,
        })
        out = plain / "agentic_20260102_000000"
        start_run(out, "agentic")
        self.assertTrue((out / RUN_METADATA_FILE).exists())

    def test_reentrant_stamp_skips_gate(self):
        """raptor.py's wrapper start_run()s the dir; the child's
        start_run() on the SAME dir is an enrich, not a new start —
        it must pass even with a live conflicting sibling."""
        from datetime import datetime, timezone
        self._write_sibling()
        out = self.project_out / "agentic_20260102_000000"
        out.mkdir(parents=True)
        save_json(out / RUN_METADATA_FILE, {
            "version": 2, "command": "agentic", "status": "running",
            # Fresh stamp, as in the real flow (the wrapper start_run()s
            # moments before the child) — also keeps _cleanup_abandoned's
            # freshness gate from sweeping it as an Esc-abandon.
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_pid": SELF_SESSION,
        })
        start_run(out, "agentic")  # must not raise
        meta = load_json(out / RUN_METADATA_FILE)
        self.assertEqual(meta["status"], "running")

    def test_wait_queues_until_holder_finishes(self):
        sibling = self._write_sibling()

        def _finish():
            meta = json.loads(
                (sibling / RUN_METADATA_FILE).read_text(encoding="utf-8"))
            meta["status"] = "completed"
            save_json(sibling / RUN_METADATA_FILE, meta)

        timer = threading.Timer(0.5, _finish)
        timer.start()
        self.addCleanup(timer.cancel)
        out = self.project_out / "agentic_20260102_000000"
        with patch("time.sleep"):  # collapse the 2s poll interval
            start_run(out, "agentic", wait_for_project=True)
        meta = load_json(out / RUN_METADATA_FILE)
        self.assertEqual(meta["status"], "running")


if __name__ == "__main__":
    unittest.main()


class UnsignallablePidGateTest(RunContentionBase):
    """A recorded session pid we cannot signal must not read as a live
    session: planted metadata with session_pid=1 (init — EPERM on
    kill(0), comm is not claude) was a PERMANENT run-start DoS under
    the cleanup-oriented probe, and --wait queued forever. Real
    probes on purpose: _pid_alive(1) is True (EPERM = alive), so the
    planted sibling survives _cleanup_abandoned and the GATE alone
    must decline it."""

    LIVENESS_PATCHES = False

    def test_planted_init_pid_does_not_block_start(self):
        self._write_sibling(session_pid=1)
        out = self.project_out / "agentic_20260102_000000"
        start_run(out, "agentic")  # must not raise
        self.assertTrue((out / RUN_METADATA_FILE).exists())

    def test_gate_probe_semantics(self):
        from core.run.metadata import _gate_session_alive
        self.assertFalse(_gate_session_alive(1), "init read as a session")
        self.assertFalse(_gate_session_alive(-5))
        self.assertFalse(_gate_session_alive(999999999))
        # Our own (python) pid is signallable but comm isn't claude —
        # on Linux the comm gate rejects it too.
        import os
        if Path(f"/proc/{os.getpid()}/comm").exists():
            self.assertFalse(_gate_session_alive(os.getpid()))


class HostileSiblingMetadataTest(RunContentionBase):
    """Sibling run metadata is plantable file content — the contention
    message must never carry raw escape bytes or floods."""

    def test_contention_message_escapes_hostile_fields(self):
        self._write_sibling(
            name="scan\x1b[2J_20260101",
            command="\x1b]0;evil\x07scan" + "B" * 4000,
        )
        d = self.project_out / "scan\x1b[2J_20260101"
        meta = load_json(d / RUN_METADATA_FILE)
        meta["timestamp"] = "2026-01-01\x1b[31mT00:00:00"
        save_json(d / RUN_METADATA_FILE, meta)
        out = self.project_out / "agentic_20260102_000000"
        with self.assertRaises(ProjectRunContention) as cm:
            start_run(out, "agentic")
        msg = str(cm.exception)
        self.assertNotIn("\x1b", msg, "raw ESC reached the message")
        self.assertNotIn("\x07", msg)
        self.assertLess(len(msg), 800, "unbounded field flooded the message")
