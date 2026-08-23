"""Tests for run-ownership enforcement on terminal lifecycle transitions.

Regression for the premature-completion incident: an early in-session
/understand mapping step running with ``--out`` pointed at an
/audit-owned run dir called lifecycle ``complete`` on it ~2.5 minutes
in — hours before the audit orchestrator even launched. The SIGTERM
drain then hit the double-finalisation refusal and ``raptor-audit
resume`` refused ("run is completed — never resumed").

Only the flow that started a run may finalise it. The finaliser
declares the command it believes it is finishing (``expected_command``
/ the stub's ``--command``); a mismatch refuses BEFORE any side effect
and leaves the run's status untouched, so the owner's later interrupt
and resume keep working.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json
from core.run import (
    RUN_METADATA_FILE,
    RunOwnershipError,
    cancel_run,
    complete_run,
    ensure_run_command,
    fail_run,
    interrupt_run,
    resume_run,
    start_run,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
LIFECYCLE = str(REPO_ROOT / "libexec" / "raptor-run-lifecycle")


class TestOwnershipEnforcement(unittest.TestCase):

    def _status(self, out: Path) -> str:
        return load_json(out / RUN_METADATA_FILE)["status"]

    def test_understand_claim_cannot_complete_audit_run(self):
        """The incident shape: an understand-phase step must NOT flip
        an audit-owned run's status."""
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            with self.assertRaises(RunOwnershipError):
                complete_run(out, expected_command="understand")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "running")
            # No terminal side effects either — timing untouched.
            self.assertNotIn("end_timestamp", meta)

    def test_resume_works_after_refused_complete_and_simulated_kill(self):
        """The full incident replay with the fix: refused trespass →
        owner's SIGTERM-drain interrupt lands → resume re-enters."""
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            with self.assertRaises(RunOwnershipError):
                complete_run(out, expected_command="understand")
            # Simulated supervisor kill: the drain's interrupt must not
            # hit the double-finalisation refusal (pre-fix it did,
            # because the run was already stamped completed).
            interrupt_run(out, "SIGTERM drain",
                          expected_command="audit")
            self.assertEqual(self._status(out), "interrupted")
            segment = resume_run(out, note="resumed by test")
            self.assertEqual(segment, 2)
            self.assertEqual(self._status(out), "running")

    def test_owner_claim_completes(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            complete_run(out, expected_command="audit")
            self.assertEqual(self._status(out), "completed")

    def test_no_claim_keeps_legacy_surface(self):
        """Callers that make no claim (sweeps, legacy scripts) are
        unchecked — behaviour identical to pre-fix."""
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            complete_run(out)
            self.assertEqual(self._status(out), "completed")

    def test_all_terminal_transitions_enforce(self):
        for finaliser, kwargs in (
            (fail_run, {"error": "x"}),
            (cancel_run, {}),
            (interrupt_run, {"reason": "stop"}),
        ):
            with TemporaryDirectory() as d:
                out = Path(d) / "audit-run"
                start_run(out, "audit")
                with self.assertRaises(RunOwnershipError, msg=finaliser):
                    finaliser(out, expected_command="understand", **kwargs)
                self.assertEqual(self._status(out), "running", finaliser)

    def test_missing_metadata_is_not_an_ownership_violation(self):
        """Missing/malformed metadata keeps its existing handling
        (FileNotFoundError from the status update), never a spurious
        ownership refusal."""
        with TemporaryDirectory() as d:
            out = Path(d) / "empty"
            out.mkdir()
            ensure_run_command(out, "understand")  # must not raise
            with self.assertRaises(FileNotFoundError):
                complete_run(out, expected_command="understand")

    def test_legacy_metadata_without_command_is_unchecked(self):
        """Runs predating command recording (or hand-built dirs) have
        no owner to defend — a claim passes through."""
        import json
        with TemporaryDirectory() as d:
            out = Path(d) / "legacy"
            out.mkdir()
            (out / RUN_METADATA_FILE).write_text(
                json.dumps({"status": "running"}))
            ensure_run_command(out, "understand")  # must not raise


class TestOwnershipViaStub(unittest.TestCase):
    """End-to-end through libexec/raptor-run-lifecycle — the surface
    the in-session skills actually invoke."""

    @staticmethod
    def _run(*args, cwd=None):
        env = os.environ.copy()
        env["_RAPTOR_TRUSTED"] = "1"
        env.pop("RAPTOR_CALLER_DIR", None)
        return subprocess.run(
            [sys.executable, LIFECYCLE] + list(args),
            capture_output=True, text=True, env=env, cwd=cwd,
        )

    def test_stub_refuses_foreign_claim_and_owner_proceeds(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")

            refused = self._run("complete", str(out),
                                "--command", "understand")
            self.assertEqual(refused.returncode, 1, refused.stderr)
            self.assertIn("owned by command 'audit'", refused.stderr)
            self.assertEqual(
                load_json(out / RUN_METADATA_FILE)["status"], "running",
            )

            owned = self._run("complete", str(out), "--command", "audit")
            self.assertEqual(owned.returncode, 0, owned.stderr)
            self.assertEqual(
                load_json(out / RUN_METADATA_FILE)["status"], "completed",
            )

    def test_stub_fail_with_claim_and_message(self):
        """--command composes with the positional message on `fail`."""
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-run"
            start_run(out, "scan")
            refused = self._run("fail", str(out), "boom",
                                "--command", "understand")
            self.assertEqual(refused.returncode, 1, refused.stderr)
            ok = self._run("fail", str(out), "boom", "--command", "scan")
            self.assertEqual(ok.returncode, 0, ok.stderr)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "boom")

    def test_stub_interrupt_with_claim(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "audit-run"
            start_run(out, "audit")
            refused = self._run("interrupt", str(out), "drain",
                                "--command", "understand")
            self.assertEqual(refused.returncode, 1, refused.stderr)
            self.assertEqual(
                load_json(out / RUN_METADATA_FILE)["status"], "running",
            )
            ok = self._run("interrupt", str(out), "drain",
                           "--command", "audit")
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(
                load_json(out / RUN_METADATA_FILE)["status"], "interrupted",
            )


if __name__ == "__main__":
    unittest.main()
