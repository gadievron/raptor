"""Tests for the interrupted lifecycle status and resume transitions."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json, save_json
from core.run import (
    RUN_METADATA_FILE,
    complete_run,
    fail_run,
    interrupt_run,
    resume_run,
    start_run,
)


import pytest

@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path: Path):
    """User registries stay out of the real home: the root-conftest
    layer doing this is stripped from release extracts (conftest.py
    is export-ignore), so the pin must travel in-file."""
    from core.testing.state_isolation import pin_user_state_dirs
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path)
        yield


@pytest.fixture
def monkeypatch(_user_state_in_tmp):
    """Undo body patches before restoring the file-owned registry pins."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


class TestInterruptRun(unittest.TestCase):

    def test_interrupt_sets_status_and_reason(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            interrupt_run(out, "SIGTERM received")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "interrupted")
            self.assertEqual(
                meta["extra"]["interrupt_reason"], "SIGTERM received",
            )
            # Terminal transition records timing like the others.
            self.assertIn("end_timestamp", meta)

    def test_interrupt_is_terminal_for_late_finalisers(self):
        """A late fail_run/complete_run must not clobber interrupted."""
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            interrupt_run(out, "supervisor stop")
            fail_run(out, "late failure handler")
            self.assertEqual(
                load_json(out / RUN_METADATA_FILE)["status"], "interrupted",
            )
            complete_run(out)
            self.assertEqual(
                load_json(out / RUN_METADATA_FILE)["status"], "interrupted",
            )

    def test_schema_accepts_interrupted(self):
        from core.project.schema import VALID_RUN_STATUSES
        self.assertIn("interrupted", VALID_RUN_STATUSES)

    def test_reaper_never_reaps_interrupted_runs(self):
        """reap_stale_runs deletes aged failed/cancelled dirs only —
        an interrupted run is resumable state, not junk."""
        import json
        import os
        import time

        from core.run.tmp_reaper import reap_stale_runs

        with TemporaryDirectory() as d:
            parent = Path(d)
            out = parent / "audit-run"
            start_run(out, "audit")
            interrupt_run(out, "supervisor stop")
            # Age the metadata far past any plausible reap floor.
            meta_path = out / RUN_METADATA_FILE
            meta = json.loads(meta_path.read_text())
            meta_path.write_text(json.dumps(meta))
            old = time.time() - 400 * 86400
            os.utime(meta_path, (old, old))
            os.utime(out, (old, old))
            reap_stale_runs(parent)
            self.assertTrue(out.is_dir())
            self.assertEqual(
                load_json(meta_path)["status"], "interrupted",
            )


class TestResumeRun(unittest.TestCase):

    def test_resume_interrupted_flips_to_running_with_segment_row(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            interrupt_run(out, "supervisor stop")
            segment = resume_run(out, note="resumed by test")
            self.assertEqual(segment, 2)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "running")
            resumes = meta["extra"]["resumes"]
            self.assertEqual(len(resumes), 1)
            self.assertEqual(resumes[0]["segment"], 2)
            self.assertEqual(resumes[0]["prior_status"], "interrupted")
            self.assertEqual(resumes[0]["note"], "resumed by test")
            # Segment-1 end timing dropped so the eventual terminal
            # transition measures the full envelope.
            self.assertNotIn("end_timestamp", meta)
            self.assertNotIn("duration_seconds", meta)

    def test_resume_failed_run_allowed(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            fail_run(out, "harness kill")
            self.assertEqual(resume_run(out), 2)
            self.assertEqual(
                load_json(out / RUN_METADATA_FILE)["status"], "running",
            )

    def test_resume_running_run_allowed(self):
        """SIGKILLed runs never got a terminal transition — they sit in
        'running' and must still be resumable (their worker is dead)."""
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            # Model the SIGKILL shape deterministically: the worker died
            # with the run. Under a live harness session start_run stamps
            # this test runner's parent shell — alive for the whole test,
            # which the in-flight guard would (correctly) refuse.
            meta_path = out / RUN_METADATA_FILE
            meta = load_json(meta_path)
            meta.pop("tool_pid", None)
            meta.pop("tool_pid_start", None)
            save_json(meta_path, meta)
            self.assertEqual(resume_run(out), 2)

    def test_resume_running_with_live_worker_refused(self):
        """Two concurrent resumes must not double-drive a run: once the
        first resume stamps a live worker, a second resume_run on the
        still-``running`` metadata is refused inside the metadata lock
        (the advisory eligibility check runs long before the flip and
        both racers can pass it). The record carries the provenance
        token a real writer mints — only a VERIFIED record refuses."""
        import subprocess
        import sys

        from core.project.sessions import proc_starttime
        from core.run.resume_state_provenance import stamp_worker_record

        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            worker = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
            )
            try:
                meta_path = out / RUN_METADATA_FILE
                meta = load_json(meta_path)
                meta["tool_pid"] = worker.pid
                start = proc_starttime(worker.pid)
                if start is not None:
                    meta["tool_pid_start"] = start
                stamp_worker_record(meta, out)
                save_json(meta_path, meta)
                with self.assertRaises(ValueError) as ctx:
                    resume_run(out)
                self.assertIn("in flight", str(ctx.exception))
                # The refused resume must not have mutated the record.
                meta = load_json(meta_path)
                self.assertEqual(meta.get("extra", {}).get("resumes"), None)
            finally:
                worker.kill()
                worker.wait(timeout=10)

    def test_resume_running_live_worker_without_stamp_proceeds(self):
        """An UNVERIFIED live-worker record (legacy pre-stamp run, or
        a pid planted into the writable run dir) must not block resume
        forever — it demotes to a loud warning and the resume
        proceeds. A planted long-lived pid was a standing denial of
        resume when the bare record was trusted."""
        import subprocess
        import sys

        from core.project.sessions import proc_starttime

        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            worker = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
            )
            try:
                meta_path = out / RUN_METADATA_FILE
                meta = load_json(meta_path)
                meta["tool_pid"] = worker.pid
                start = proc_starttime(worker.pid)
                if start is not None:
                    meta["tool_pid_start"] = start
                meta.pop("tool_pid_provenance", None)
                save_json(meta_path, meta)
                with self.assertLogs("core.run.metadata",
                                     level="WARNING") as cm:
                    self.assertEqual(resume_run(out), 2)
                self.assertTrue(any(
                    "UNVERIFIED" in line for line in cm.output))
            finally:
                worker.kill()
                worker.wait(timeout=10)

    def test_resume_running_tampered_stamp_proceeds(self):
        """A verified-then-rewritten record (the token no longer
        matches the recorded tuple) is the tampering shape: demote,
        never refuse — and never an error."""
        import subprocess
        import sys

        from core.project.sessions import proc_starttime
        from core.run.resume_state_provenance import stamp_worker_record

        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            worker = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
            )
            other = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
            )
            try:
                meta_path = out / RUN_METADATA_FILE
                meta = load_json(meta_path)
                # Token minted for one live pid, record rewritten to
                # point at ANOTHER live pid (the planted-pid shape).
                meta["tool_pid"] = other.pid
                start = proc_starttime(other.pid)
                if start is not None:
                    meta["tool_pid_start"] = start
                stamp_worker_record(meta, out)
                meta["tool_pid"] = worker.pid
                start = proc_starttime(worker.pid)
                if start is not None:
                    meta["tool_pid_start"] = start
                save_json(meta_path, meta)
                with self.assertLogs("core.run.metadata",
                                     level="WARNING") as cm:
                    self.assertEqual(resume_run(out), 2)
                self.assertTrue(any(
                    "UNVERIFIED" in line for line in cm.output))
            finally:
                for proc in (worker, other):
                    proc.kill()
                    proc.wait(timeout=10)

    def test_resume_running_with_dead_worker_allowed(self):
        """The SIGKILL-recovery lane survives the live-worker guard: a
        dead recorded worker is exactly the resumable shape."""
        import subprocess
        import sys

        from core.project.sessions import proc_starttime

        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            worker = subprocess.Popen(
                [sys.executable, "-c", "pass"],
            )
            start = proc_starttime(worker.pid)
            worker.wait(timeout=10)
            meta_path = out / RUN_METADATA_FILE
            meta = load_json(meta_path)
            meta["tool_pid"] = worker.pid
            if start is not None:
                meta["tool_pid_start"] = start
            save_json(meta_path, meta)
            self.assertEqual(resume_run(out), 2)

    def test_resume_running_own_worker_stamp_allowed(self):
        """A detached orchestrator records ITSELF as the worker; its own
        re-entry must not be refused (it would wedge forever — its
        recorded worker is alive by construction). Stamped: the
        self-pid exemption applies to VERIFIED records only."""
        import os

        from core.project.sessions import proc_starttime
        from core.run.resume_state_provenance import stamp_worker_record

        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            meta_path = out / RUN_METADATA_FILE
            meta = load_json(meta_path)
            meta["tool_pid"] = os.getpid()
            start = proc_starttime(os.getpid())
            if start is not None:
                meta["tool_pid_start"] = start
            stamp_worker_record(meta, out)
            save_json(meta_path, meta)
            self.assertEqual(resume_run(out), 2)

    def test_resume_interrupted_ignores_stale_worker_stamp(self):
        """The live-worker guard applies to ``running`` only: an
        interrupted run went through a real terminal transition, and its
        (possibly still-live) stale stamp keeps the existing eligibility
        semantics."""
        import subprocess
        import sys

        from core.project.sessions import proc_starttime

        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            interrupt_run(out, "supervisor stop")
            worker = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
            )
            try:
                meta_path = out / RUN_METADATA_FILE
                meta = load_json(meta_path)
                meta["tool_pid"] = worker.pid
                start = proc_starttime(worker.pid)
                if start is not None:
                    meta["tool_pid_start"] = start
                save_json(meta_path, meta)
                self.assertEqual(resume_run(out), 2)
            finally:
                worker.kill()
                worker.wait(timeout=10)

    def test_resume_completed_refused(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            complete_run(out)
            with self.assertRaises(ValueError) as ctx:
                resume_run(out)
            self.assertIn("completed", str(ctx.exception))

    def test_resume_without_metadata_raises(self):
        with TemporaryDirectory() as d, self.assertRaises(FileNotFoundError):
            resume_run(Path(d) / "nope")

    def test_second_resume_increments_segment(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            interrupt_run(out, "one")
            self.assertEqual(resume_run(out), 2)
            interrupt_run(out, "two")
            self.assertEqual(resume_run(out), 3)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(
                [r["segment"] for r in meta["extra"]["resumes"]], [2, 3],
            )

    def test_resume_then_complete(self):
        """interrupted → running → completed is the documented cycle."""
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            interrupt_run(out, "supervisor stop")
            resume_run(out)
            complete_run(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")
            self.assertEqual(len(meta["extra"]["resumes"]), 1)


if __name__ == "__main__":
    unittest.main()
