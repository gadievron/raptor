"""Stamping precedence between heuristic finalisers and a run's own.

The lifecycle hook's Stop path judges a run it did not start: it infers
"the tool call ended" from the recorded worker credential reading dead,
then finalizes. When that inference is wrong — the run is mid-flight —
its stamp used to be indistinguishable from a real verdict, so the
terminal guard in ``_update_status`` refused the owner's genuine
``fail_run``/``complete_run`` and the heuristic verdict stood forever
(observed as a failed scan permanently reading Completed).

These tests pin the adjudicated precedence rule:

* real vs real           — first writer wins (the terminal guard);
* heuristic vs real      — the REAL verdict wins regardless of order;
* heuristic vs heuristic — first writer wins (the no-op clause).

``TestForcedDeadWorkerWindow`` forces the misjudged-liveness window
deterministically with real machinery: a subprocess whose recorded
worker parent is made to die after ``start_run`` records it, so the
hook's REAL liveness check (no patching) reads the worker dead while
the run is, by construction, still in flight.
"""

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.json import load_json, save_json
from core.run.metadata import (
    RUN_METADATA_FILE,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_RUNNING,
    complete_run,
    fail_run,
    cancel_run,
    worker_liveness_for_meta,
)

REPO_ROOT = Path(__file__).resolve().parents[3]  # core/run/tests/ → raptor/
HOOK_SCRIPT = REPO_ROOT / "libexec" / "raptor-lifecycle-hook"

# Import the hook module despite its hyphenated filename and missing .py ext.
_loader = importlib.machinery.SourceFileLoader(
    "lifecycle_hook_precedence", str(HOOK_SCRIPT))
_spec = importlib.util.spec_from_loader(
    "lifecycle_hook_precedence", _loader, origin=str(HOOK_SCRIPT))
_hook_mod = importlib.util.module_from_spec(_spec)
_hook_mod.__file__ = str(HOOK_SCRIPT)
_spec.loader.exec_module(_hook_mod)

SESSION_PID = 99999

#: An aged start timestamp: past the Stop path's freshness floor, so
#: the hook's judgement is gated only by worker liveness.
_AGED_TS = "2026-05-03T12:00:00+00:00"


def _make_running_run(parent: Path, name: str, command: str = "scan",
                      session_pid: int = SESSION_PID,
                      tool_pid: int = 11111,
                      timestamp: str = _AGED_TS) -> Path:
    d = parent / name
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "version": 1,
        "command": command,
        "timestamp": timestamp,
        "status": STATUS_RUNNING,
        "extra": {},
        "session_pid": session_pid,
        "tool_pid": tool_pid,
    }
    save_json(d / RUN_METADATA_FILE, meta)
    return d


def _meta(d: Path) -> dict:
    return load_json(d / RUN_METADATA_FILE)


def _status(d: Path) -> str:
    return _meta(d).get("status")


def _extra(d: Path) -> dict:
    return _meta(d).get("extra") or {}


def _run_stop_hook(tmp: Path) -> None:
    """Fire the hook's Stop path against *tmp* as the repo root.

    Only session identity is patched — worker liveness is the REAL
    check, so a test reaching a finalization proves the recorded
    credential genuinely read dead.
    """
    with patch.object(_hook_mod, "REPO_ROOT", tmp), \
         patch("core.run.metadata._get_session_pid",
               return_value=SESSION_PID):
        sys.argv = ["hook", "stop"]
        _hook_mod.main()


# Subprocess B: performs a REAL start_run, recording its parent (A) as
# the worker credential (tool_pid + tool_pid_start).
_STARTER_CHILD = """\
import sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from core.run.metadata import start_run
start_run(Path(sys.argv[2]), "scan")
"""

# Subprocess A: spawns B, waits for B's start_run to finish, then
# exits — so the credential B recorded (A) dies AFTER it was recorded
# while the run itself is still in flight. (A parent that dies BEFORE
# start_run never becomes the credential: the worker stamp's pid<=1
# clause records the calling process itself instead.)
_TRANSIENT_PARENT = """\
import subprocess
import sys
subprocess.run(
    [sys.executable, "-c", %r, sys.argv[1], sys.argv[2]],
    check=True, timeout=120,
)
""" % _STARTER_CHILD


class TestForcedDeadWorkerWindow(unittest.TestCase):
    """Deterministically force the Stop path's misjudged-liveness
    window and pin the precedence outcome in both orderings.

    This is the flake's mechanism, forced: the hook session-matches a
    running run whose recorded worker reads dead and stamps a verdict
    while the owner is still in flight; the owner's real finaliser
    lands afterwards. Pre-fix, the hook's unmarked ``completed`` was
    final and the owner's ``fail_run`` was refused — a failed run read
    Completed forever.
    """

    def _start_run_with_dead_worker(self, tmp: Path) -> Path:
        """REAL ``start_run`` whose recorded worker credential is dead
        by the time this returns."""
        run = tmp / "out" / "scan-001"
        env = dict(os.environ)
        # Hermetic session posture for the subprocess: a fresh HOME
        # (no registered sessions.d entry → no ledger writes) and no
        # inherited env credential; CLAUDECODE keeps the session-bound
        # worker-stamp lane via the getppid fallback when no claude
        # ancestor is walkable (CI).
        home = tmp / "home"
        home.mkdir()
        env["HOME"] = str(home)
        env["CLAUDECODE"] = "1"
        env.pop("RAPTOR_SESSION_PID", None)
        env.pop("RAPTOR_SESSION_TOKEN", None)
        proc = subprocess.Popen(
            [sys.executable, "-c", _TRANSIENT_PARENT,
             str(REPO_ROOT), str(run)],
            env=env, cwd=str(tmp),
        )
        proc.wait(timeout=120)
        self.assertEqual(proc.returncode, 0)

        meta = _meta(run)
        # The window is REAL: the recorded worker (the transient
        # parent) is dead, and the unpatched liveness check says so.
        self.assertEqual(meta.get("status"), STATUS_RUNNING)
        self.assertEqual(meta.get("tool_pid"), proc.pid)
        alive, _detail = worker_liveness_for_meta(meta)
        self.assertFalse(alive)

        # Re-key the run to the test's session identity and age it
        # past the freshness floor — the floor is a separate defence
        # pinned in TestStopFreshnessFloor; here the window itself is
        # under test.
        meta["session_pid"] = SESSION_PID
        meta["timestamp"] = _AGED_TS
        save_json(run / RUN_METADATA_FILE, meta)
        return run

    def test_hook_first_owner_fail_still_wins(self):
        # The observed-failure ordering: hook stamps first, the
        # owner's real fail_run lands second and must supersede.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run = self._start_run_with_dead_worker(tmp)

            _run_stop_hook(tmp)
            self.assertEqual(_status(run), STATUS_COMPLETED)
            # The heuristic verdict is MARKED — this is what makes it
            # recoverable at all.
            self.assertIs(_extra(run).get("hook_finalize"), True)

            fail_run(run, "exit code 3")
            self.assertEqual(_status(run), STATUS_FAILED)
            extra = _extra(run)
            self.assertEqual(extra.get("error"), "exit code 3")
            self.assertNotIn("hook_finalize", extra)

    def test_owner_fail_first_hook_noops(self):
        # Reverse ordering: the real verdict landed first; the hook
        # must leave it alone entirely.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run = self._start_run_with_dead_worker(tmp)

            fail_run(run, "exit code 3")
            self.assertEqual(_status(run), STATUS_FAILED)

            _run_stop_hook(tmp)
            self.assertEqual(_status(run), STATUS_FAILED)
            extra = _extra(run)
            self.assertEqual(extra.get("error"), "exit code 3")
            self.assertNotIn("hook_finalize", extra)

    def test_hook_first_owner_complete_consumes_marker(self):
        # The benign-window variant: the hook guessed COMPLETED and the
        # owner then really completes. The marker must be consumed so a
        # later stray fail_run cannot use the recovery clause to flip a
        # genuinely completed run.
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run = self._start_run_with_dead_worker(tmp)

            _run_stop_hook(tmp)
            self.assertEqual(_status(run), STATUS_COMPLETED)
            self.assertIs(_extra(run).get("hook_finalize"), True)

            complete_run(run)
            self.assertEqual(_status(run), STATUS_COMPLETED)
            self.assertNotIn("hook_finalize", _extra(run))

            fail_run(run, "stray late failure")
            self.assertEqual(_status(run), STATUS_COMPLETED)


class TestPrecedenceMatrix(unittest.TestCase):
    """The adjudicated precedence rule, pinned in both directions for
    each pairing (heuristic writes use the same call shapes the hook
    and the abandon sweeps use)."""

    def _running(self, tmp: str) -> Path:
        return _make_running_run(Path(tmp) / "out", "scan-001")

    # heuristic vs real: real wins regardless of order -----------------

    def test_heuristic_complete_then_real_fail(self):
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            complete_run(run, extra={"hook_finalize": True})
            self.assertEqual(_status(run), STATUS_COMPLETED)
            fail_run(run, "exit code 1")
            self.assertEqual(_status(run), STATUS_FAILED)
            extra = _extra(run)
            self.assertEqual(extra.get("error"), "exit code 1")
            self.assertNotIn("hook_finalize", extra)

    def test_real_fail_then_heuristic_complete(self):
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            fail_run(run, "exit code 1")
            complete_run(run, extra={"hook_finalize": True})
            self.assertEqual(_status(run), STATUS_FAILED)
            extra = _extra(run)
            self.assertEqual(extra.get("error"), "exit code 1")
            self.assertNotIn("hook_finalize", extra)

    def test_heuristic_fail_then_real_complete(self):
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            fail_run(run, "tool exited with error",
                     extra={"hook_finalize": True})
            self.assertEqual(_status(run), STATUS_FAILED)
            complete_run(run)
            self.assertEqual(_status(run), STATUS_COMPLETED)
            extra = _extra(run)
            self.assertNotIn("hook_finalize", extra)
            # The heuristic's error must not contaminate the real
            # outcome.
            self.assertNotIn("error", extra)

    def test_real_complete_then_heuristic_fail(self):
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            complete_run(run)
            fail_run(run, "tool exited with error",
                     extra={"hook_finalize": True})
            self.assertEqual(_status(run), STATUS_COMPLETED)
            self.assertNotIn("hook_finalize", _extra(run))

    def test_heuristic_fail_then_real_fail_consumes_marker(self):
        # Same-status refail lane: the real failure supersedes the
        # heuristic one — marker consumed, error refreshed — so a later
        # stray complete_run cannot launder the genuine failure.
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            fail_run(run, "tool exited with error",
                     extra={"hook_finalize": True})
            fail_run(run, "exit code 3")
            self.assertEqual(_status(run), STATUS_FAILED)
            extra = _extra(run)
            self.assertEqual(extra.get("error"), "exit code 3")
            self.assertNotIn("hook_finalize", extra)
            complete_run(run)
            self.assertEqual(_status(run), STATUS_FAILED)

    def test_real_cancel_overrides_heuristic_complete(self):
        # The rule covers every real finaliser, not just fail_run.
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            complete_run(run, extra={"hook_finalize": True})
            cancel_run(run)
            self.assertEqual(_status(run), STATUS_CANCELLED)
            self.assertNotIn("hook_finalize", _extra(run))

    # real vs real: first writer wins (unchanged) ----------------------

    def test_real_complete_then_real_fail(self):
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            complete_run(run)
            fail_run(run, "late failure")
            self.assertEqual(_status(run), STATUS_COMPLETED)

    def test_real_fail_then_real_complete(self):
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            fail_run(run, "exit code 1")
            complete_run(run)
            self.assertEqual(_status(run), STATUS_FAILED)
            self.assertEqual(_extra(run).get("error"), "exit code 1")

    # heuristic vs heuristic: first writer wins ------------------------

    def test_heuristic_complete_then_sweep_fail(self):
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            complete_run(run, extra={"hook_finalize": True})
            fail_run(run, "session ended without explicit completion",
                     extra={"abandon_sweep": True})
            self.assertEqual(_status(run), STATUS_COMPLETED)
            extra = _extra(run)
            # The loser's marker/error must not be merged in.
            self.assertNotIn("abandon_sweep", extra)
            self.assertNotIn("error", extra)

    def test_sweep_fail_then_heuristic_complete(self):
        with TemporaryDirectory() as tmp:
            run = self._running(tmp)
            fail_run(run, "session ended without explicit completion",
                     extra={"abandon_sweep": True})
            complete_run(run, extra={"hook_finalize": True})
            self.assertEqual(_status(run), STATUS_FAILED)
            self.assertIs(_extra(run).get("abandon_sweep"), True)


class TestStopFreshnessFloor(unittest.TestCase):
    """The Stop path does not judge a run younger than the abandon
    freshness floor — the misjudged-liveness inference is at its
    weakest right after start, when the run's own finaliser is
    typically milliseconds away."""

    def _stop(self, tmp: str) -> None:
        with patch.object(_hook_mod, "REPO_ROOT", Path(tmp)), \
             patch("core.run.metadata._get_session_pid",
                   return_value=SESSION_PID), \
             patch("core.run.metadata._pid_alive", return_value=False):
            sys.argv = ["hook", "stop"]
            _hook_mod.main()

    def test_young_run_is_left_alone(self):
        with TemporaryDirectory() as tmp:
            now = datetime.now(timezone.utc).isoformat()
            run = _make_running_run(Path(tmp) / "out", "scan-001",
                                    tool_pid=1, timestamp=now)
            self._stop(tmp)
            self.assertEqual(_status(run), STATUS_RUNNING)

    def test_aged_run_is_finalized_with_marker(self):
        with TemporaryDirectory() as tmp:
            run = _make_running_run(Path(tmp) / "out", "scan-001",
                                    tool_pid=1)
            self._stop(tmp)
            self.assertEqual(_status(run), STATUS_COMPLETED)
            self.assertIs(_extra(run).get("hook_finalize"), True)

    def test_unparseable_timestamp_does_not_park_the_run(self):
        # Fail direction: a corrupt/missing/future stamp is NOT young —
        # the hook may act, so nothing stays running forever.
        for ts in ("not-a-timestamp", None,
                   (datetime.now(timezone.utc)
                    + timedelta(hours=1)).isoformat()):
            with TemporaryDirectory() as tmp:
                run = _make_running_run(Path(tmp) / "out", "scan-001",
                                        tool_pid=1)
                meta = _meta(run)
                if ts is None:
                    meta.pop("timestamp", None)
                else:
                    meta["timestamp"] = ts
                save_json(run / RUN_METADATA_FILE, meta)
                self._stop(tmp)
                self.assertEqual(
                    _status(run), STATUS_COMPLETED,
                    f"timestamp {ts!r} parked the run in running")

    def test_too_young_to_judge_boundaries(self):
        fn = _hook_mod._too_young_to_judge
        now = datetime.now(timezone.utc)
        self.assertTrue(fn({"timestamp": now.isoformat()}))
        self.assertFalse(
            fn({"timestamp": (now - timedelta(minutes=5)).isoformat()}))
        self.assertFalse(
            fn({"timestamp": (now + timedelta(minutes=5)).isoformat()}))
        self.assertFalse(fn({"timestamp": "garbage"}))
        self.assertFalse(fn({"timestamp": 12345}))
        self.assertFalse(fn({}))


if __name__ == "__main__":
    unittest.main()
