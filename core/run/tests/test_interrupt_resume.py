"""Tests for the interrupted lifecycle status and resume transitions."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json
from core.run import (
    RUN_METADATA_FILE,
    complete_run,
    fail_run,
    interrupt_run,
    resume_run,
    start_run,
)


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
        'running' and must still be resumable."""
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            self.assertEqual(resume_run(out), 2)

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
