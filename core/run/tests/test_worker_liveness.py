"""Worker (``tool_pid``) liveness identity — (pid, starttime) binding.

The trap these tests pin: a detached launch (setsid/nohup) reparents
the orchestrator to init before ``start_run`` executes, so the recorded
``session_pid``/``tool_pid`` were both 1 — and PID 1 is always alive,
so the in-flight guards (audit resume, journal compaction) refused
forever until an operator hand-edited the run metadata. Both ends are
covered here: the RECORDER never stamps pid<=1 (it records the calling
orchestrator instead, bound as (pid, /proc starttime)), and the GUARD
treats pid<=1 as never-live, requires the full identity for stamped
records, and keeps legacy bare-pid semantics otherwise.

Hermetic: /proc reads are injected by patching
``core.project.sessions.proc_starttime`` (the shared reader the stamp
writer and the verifiers all call) — the repo-wide idiom for
starttime-dependent tests.
"""

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from core.json import load_json, save_json
from core.project import sessions
from core.run.metadata import (
    RUN_METADATA_FILE,
    _tool_pid_alive,
    _worker_stamp,
    resume_run,
    start_run,
    worker_liveness_for_meta,
)


def _fake_starttime(table):
    """A ``proc_starttime`` stand-in reading from a dict — the
    injectable /proc for these tests."""
    return lambda pid: table.get(pid)


class TestWorkerStampRecorder(unittest.TestCase):

    def test_session_bound_start_records_parent_with_starttime(self):
        table = {os.getppid(): "424242"}
        with TemporaryDirectory() as d, \
                mock.patch("core.run.metadata._get_session_pid",
                           return_value=11111), \
                mock.patch.object(sessions, "proc_starttime",
                                  _fake_starttime(table)):
            out = Path(d) / "run"
            start_run(out, "scan")
            meta = load_json(out / RUN_METADATA_FILE)
        self.assertEqual(meta["tool_pid"], os.getppid())
        self.assertEqual(meta["tool_pid_start"], "424242")

    def test_detached_start_records_own_pid_not_init(self):
        # setsid/nohup shape: the parent exited, getppid() is 1. The
        # calling process IS the long-lived orchestrator — record it,
        # never pid 1 (always alive → guards would refuse forever).
        table = {os.getpid(): "10101"}
        with TemporaryDirectory() as d, \
                mock.patch("os.getppid", return_value=1), \
                mock.patch.object(sessions, "proc_starttime",
                                  _fake_starttime(table)):
            out = Path(d) / "run"
            start_run(out, "audit")
            meta = load_json(out / RUN_METADATA_FILE)
        self.assertEqual(meta["tool_pid"], os.getpid())
        self.assertEqual(meta["tool_pid_start"], "10101")

    def test_detached_start_records_no_session_pid(self):
        # The CLAUDECODE getppid() fallback must not mint session_pid=1
        # for a reparented-to-init process — PID 1 is not a session.
        with TemporaryDirectory() as d, \
                mock.patch("os.getppid", return_value=1), \
                mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            out = Path(d) / "run"
            start_run(out, "audit")
            meta = load_json(out / RUN_METADATA_FILE)
        self.assertNotIn("session_pid", meta)

    def test_unreadable_starttime_records_bare_pid(self):
        # Off-Linux / unreadable /proc: the record degrades to the
        # legacy bare-pid shape — readers then apply legacy semantics.
        with mock.patch.object(sessions, "proc_starttime",
                               lambda pid: None):
            stamp = _worker_stamp(session_bound=True)
        self.assertNotIn("tool_pid_start", stamp)
        self.assertEqual(stamp["tool_pid"], os.getppid())

    def test_sessionless_interactive_start_records_no_worker(self):
        # Bare-shell run with a live interactive parent: recording
        # that parent would wedge resume/compaction on every crashed
        # run until the terminal closed (the pid-1 wedge class with a
        # different always-alive pid) — record nothing, as before.
        with TemporaryDirectory() as d, \
                mock.patch("core.run.metadata._get_session_pid",
                           return_value=None):
            out = Path(d) / "run"
            start_run(out, "scan")
            meta = load_json(out / RUN_METADATA_FILE)
        self.assertNotIn("session_pid", meta)
        self.assertNotIn("tool_pid", meta)
        self.assertNotIn("tool_pid_start", meta)

    def test_container_init_orchestrator_records_nothing(self):
        # An orchestrator running AS pid 1 (container init) has no
        # recordable worker: legacy pid-less posture, never a poisoned
        # pid<=1 credential.
        with mock.patch("os.getppid", return_value=0), \
                mock.patch("os.getpid", return_value=1):
            self.assertEqual(_worker_stamp(session_bound=False), {})

    def test_sessionless_resume_refreshes_worker_and_drops_session(self):
        # Detached resume: segment N's liveness credential must be
        # segment N's worker, and the dead prior session's stamp must
        # not linger (the dead-session sweep would fail the resumed
        # run mid-flight).
        table = {os.getpid(): "555"}
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "audit")
            meta_path = out / RUN_METADATA_FILE
            meta = load_json(meta_path)
            meta["status"] = "interrupted"
            meta["session_pid"] = 999999
            meta["session_start"] = "1"
            meta["session_boot_id"] = "b"
            meta["tool_pid"] = 999999
            meta["tool_pid_start"] = "999"
            save_json(meta_path, meta)
            with mock.patch("core.run.metadata._get_session_pid",
                            return_value=None), \
                    mock.patch("os.getppid", return_value=1), \
                    mock.patch.object(sessions, "proc_starttime",
                                      _fake_starttime(table)):
                resume_run(out)
            meta = load_json(meta_path)
        self.assertEqual(meta["status"], "running")
        self.assertEqual(meta["tool_pid"], os.getpid())
        self.assertEqual(meta["tool_pid_start"], "555")
        for key in ("session_pid", "session_start", "session_boot_id"):
            self.assertNotIn(key, meta)


class TestToolPidAlive(unittest.TestCase):

    def test_init_is_never_live_evidence(self):
        # PID 1 answers kill(pid, 0) forever — the exact wedge.
        self.assertFalse(_tool_pid_alive(1))
        self.assertFalse(_tool_pid_alive(1, "12345"))

    def test_malformed_pids_read_dead(self):
        for pid in (None, 0, -4, True, "123", 1.5):
            self.assertFalse(_tool_pid_alive(pid))

    def test_stamped_match_is_alive(self):
        me = os.getpid()
        with mock.patch.object(sessions, "proc_starttime",
                               _fake_starttime({me: "777"})):
            self.assertTrue(_tool_pid_alive(me, "777"))

    def test_stamped_mismatch_is_dead(self):
        # Recycled pid: alive process, different incarnation.
        me = os.getpid()
        with mock.patch.object(sessions, "proc_starttime",
                               _fake_starttime({me: "777"})):
            self.assertFalse(_tool_pid_alive(me, "123"))

    def test_stamped_but_unverifiable_keeps_bare_alive(self):
        # Off-Linux reader of a Linux-stamped record: legacy posture.
        me = os.getpid()
        with mock.patch.object(sessions, "proc_starttime",
                               lambda pid: None):
            self.assertTrue(_tool_pid_alive(me, "123"))

    def test_dead_pid_is_dead_regardless_of_stamp(self):
        import subprocess
        proc = subprocess.Popen(["/bin/true"])
        proc.wait()
        self.assertFalse(_tool_pid_alive(proc.pid, "777"))

    def test_legacy_bare_pid_keeps_old_probe(self):
        self.assertTrue(_tool_pid_alive(os.getpid()))

    def test_malformed_stamp_degrades_to_legacy_not_dead(self):
        # A planted non-numeric stamp must not defeat the in-flight
        # guards on a live worker: malformed degrades to the LEGACY
        # bare-pid verdict (alive → guards refuse), never to
        # "mismatch → dead".
        me = os.getpid()
        with mock.patch.object(sessions, "proc_starttime",
                               _fake_starttime({me: "777"})):
            for planted in ({"a": 1}, ["224"], "not-digits", 1.5,
                            True, -3, "  777  ", "٧٧٧"):
                self.assertTrue(_tool_pid_alive(me, planted),
                                repr(planted))

    def test_int_stamp_accepted(self):
        # A hand-repaired record whose stamp round-tripped as int.
        me = os.getpid()
        with mock.patch.object(sessions, "proc_starttime",
                               _fake_starttime({me: "777"})):
            self.assertTrue(_tool_pid_alive(me, 777))
            self.assertFalse(_tool_pid_alive(me, 778))


class TestWorkerLivenessForMeta(unittest.TestCase):

    def test_no_recorded_pid(self):
        alive, detail = worker_liveness_for_meta({})
        self.assertFalse(alive)
        self.assertIn("no recorded worker pid", detail)

    def test_malformed_recorded_pid(self):
        for pid in (0, -1, "12", True):
            alive, detail = worker_liveness_for_meta({"tool_pid": pid})
            self.assertFalse(alive)
            self.assertIn("malformed", detail)

    def test_init_record_reads_not_in_flight_with_note(self):
        # The note is warn-once-per-process: reset the one-shot so the
        # assertion is order-independent (any earlier pid-1 evaluation
        # in this process would otherwise have consumed it).
        with mock.patch("core.run.metadata._PID1_NOTE_EMITTED", False):
            with self.assertLogs("core.run.metadata",
                                 level="WARNING") as cm:
                alive, detail = worker_liveness_for_meta({"tool_pid": 1})
            self.assertFalse(alive)
            self.assertIn("not a liveness credential", detail)
            self.assertTrue(
                any("never a liveness credential" in line
                    for line in cm.output))
            # Second evaluation in the same process demotes to DEBUG
            # (the sweeps re-evaluate every sibling run each pass —
            # one wedged legacy record must not warn per run per
            # sweep).
            with self.assertNoLogs("core.run.metadata",
                                   level="WARNING"):
                worker_liveness_for_meta({"tool_pid": 1})

    def test_stamped_match_names_the_identity(self):
        me = os.getpid()
        with mock.patch.object(sessions, "proc_starttime",
                               _fake_starttime({me: "777"})):
            alive, detail = worker_liveness_for_meta(
                {"tool_pid": me, "tool_pid_start": "777"})
        self.assertTrue(alive)
        self.assertIn("start time matches", detail)

    def test_stamped_mismatch_names_the_recycle(self):
        me = os.getpid()
        with mock.patch.object(sessions, "proc_starttime",
                               _fake_starttime({me: "777"})):
            alive, detail = worker_liveness_for_meta(
                {"tool_pid": me, "tool_pid_start": "123"})
        self.assertFalse(alive)
        self.assertIn("recycled", detail)

    def test_legacy_alive_names_unverified_identity(self):
        alive, detail = worker_liveness_for_meta(
            {"tool_pid": os.getpid()})
        self.assertTrue(alive)
        self.assertIn("identity unverified", detail)


class TestCleanLivenessGrace(unittest.TestCase):
    """``run_is_live`` keys its activity grace on the absent SESSION,
    not absent pids — session-less runs now carry a (possibly
    transient-stub) ``tool_pid``, and its death alone must not read
    as deletable."""

    def _make_run(self, parent: Path, *, meta: dict) -> Path:
        d = parent / "run"
        d.mkdir()
        (d / RUN_METADATA_FILE).write_text(json.dumps(meta))
        return d

    def test_sessionless_dead_worker_recent_activity_is_live(self):
        import subprocess

        from core.project.clean import run_is_live
        proc = subprocess.Popen(["/bin/true"])
        proc.wait()
        with TemporaryDirectory() as td:
            d = self._make_run(Path(td), meta={
                "status": "running",
                "tool_pid": proc.pid,
                "timestamp": "2026-09-20T00:00:00+00:00",
            })
            self.assertTrue(run_is_live(d))

    def test_sessionless_dead_worker_quiet_run_not_live(self):
        import subprocess
        import time

        from core.project.clean import run_is_live
        proc = subprocess.Popen(["/bin/true"])
        proc.wait()
        with TemporaryDirectory() as td:
            d = self._make_run(Path(td), meta={
                "status": "running",
                "tool_pid": proc.pid,
                "timestamp": "2026-09-20T00:00:00+00:00",
            })
            old = time.time() - 7200
            os.utime(d / RUN_METADATA_FILE, (old, old))
            os.utime(d, (old, old))
            self.assertFalse(run_is_live(d))

    def test_init_worker_record_with_quiet_dir_not_live(self):
        # The incident record shape (pid-1 stamps, dead session):
        # judgeable now — the wedge run is sweepable, not immortal.
        import time

        from core.project.clean import run_is_live
        with TemporaryDirectory() as td:
            d = self._make_run(Path(td), meta={
                "status": "running",
                "session_pid": 1,
                "tool_pid": 1,
                "timestamp": "2026-09-20T00:00:00+00:00",
            })
            old = time.time() - 7200
            os.utime(d / RUN_METADATA_FILE, (old, old))
            os.utime(d, (old, old))
            self.assertFalse(run_is_live(d))


if __name__ == "__main__":
    unittest.main()
