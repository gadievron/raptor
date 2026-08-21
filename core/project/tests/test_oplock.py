"""Operation-granular project locking — hermetic semantics tests.

Covers the ``core.project.oplock`` primitive (grace, --wait, holder
diagnostics, stale-content silence, crashed-holder recovery) and the
CLI wiring (mutating subcommands lock; read-only ones don't; one
stderr line on contention). Lock holders run in a child process —
flock is per-open-file-description, so a same-process "contender"
would silently succeed.
"""

from __future__ import annotations

import contextlib
import io
import json
import multiprocessing
import sys
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from core.project import oplock
from core.project.cli import main
from core.project.oplock import (
    OpLockContention,
    describe_holder,
    op_lock_path,
    project_op_lock,
    read_holder,
)
from core.project.project import ProjectManager

pytestmark = pytest.mark.skipif(
    not oplock._HAS_FCNTL, reason="flock semantics require fcntl"
)


def _hold_lock(project_dir: str, hold_s: float, acquired_evt, release_evt):
    """Child-process lock holder (module-level for spawn picklability)."""
    with project_op_lock(Path(project_dir), "test-holder"):
        acquired_evt.set()
        release_evt.wait(timeout=hold_s)


class _Holder:
    """Context manager running a lock holder in a child process."""

    def __init__(self, project_dir: Path, hold_s: float = 30.0):
        ctx = multiprocessing.get_context("fork")
        self.acquired = ctx.Event()
        self.release = ctx.Event()
        self.proc = ctx.Process(
            target=_hold_lock,
            args=(str(project_dir), hold_s, self.acquired, self.release),
        )

    def __enter__(self):
        self.proc.start()
        assert self.acquired.wait(timeout=10), "holder never acquired"
        return self

    def __exit__(self, *exc):
        self.release.set()
        self.proc.join(timeout=10)
        if self.proc.is_alive():  # pragma: no cover — cleanup only
            self.proc.kill()
            self.proc.join(timeout=5)
        return False


class OpLockPrimitiveTest(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.project_dir = Path(self._tmp.name) / "proj"

    def test_acquire_stamps_holder_and_releases(self):
        with project_op_lock(self.project_dir, "unit-op"):
            holder = read_holder(op_lock_path(self.project_dir))
            self.assertEqual(holder.get("operation"), "unit-op")
            self.assertIsInstance(holder.get("pid"), int)
            self.assertIn("since", holder)
        # Released: an immediate re-acquire must succeed silently.
        with project_op_lock(self.project_dir, "unit-op-2", grace=0.0):
            pass

    def test_stale_content_with_free_lock_is_silent(self):
        """Content is diagnostic only — a dead holder's stamp behind a
        FREE flock must produce no contention (and no message)."""
        self.project_dir.mkdir(parents=True)
        op_lock_path(self.project_dir).write_text(
            json.dumps({"pid": 999999999, "operation": "crashed-op",
                        "since": "2020-01-01T00:00:00+00:00"}),
            encoding="utf-8",
        )
        err = io.StringIO()
        with contextlib.redirect_stderr(err), \
                project_op_lock(self.project_dir, "recovery", grace=0.0):
            pass
        self.assertEqual(err.getvalue(), "")

    def test_contention_past_grace_names_holder(self):
        with _Holder(self.project_dir):
            t0 = time.monotonic()
            with self.assertRaises(OpLockContention) as cm:
                with project_op_lock(self.project_dir, "contender",
                                     grace=0.3):
                    pass
            elapsed = time.monotonic() - t0
            self.assertGreaterEqual(elapsed, 0.3, "grace not honoured")
            msg = str(cm.exception)
            self.assertIn("test-holder", msg)
            self.assertIn("--wait", msg)
            self.assertIn(str(cm.exception.holder.get("pid")), msg)

    def test_release_within_grace_is_silent(self):
        holder = _Holder(self.project_dir)
        with holder:
            # Release the holder shortly after the contender starts
            # polling — well inside the grace window.
            threading.Timer(0.3, holder.release.set).start()
            err = io.StringIO()
            with contextlib.redirect_stderr(err), \
                    project_op_lock(self.project_dir, "contender",
                                    grace=5.0):
                pass
            self.assertEqual(err.getvalue(), "")

    def test_wait_blocks_until_release(self):
        holder = _Holder(self.project_dir)
        with holder:
            threading.Timer(0.5, holder.release.set).start()
            t0 = time.monotonic()
            with project_op_lock(self.project_dir, "waiter", wait=True):
                waited = time.monotonic() - t0
            self.assertGreaterEqual(waited, 0.3)

    def test_crashed_holder_recovery(self):
        """A holder killed outright (no unlock path runs) must not
        block the next contender — the kernel drops the flock with the
        process."""
        holder = _Holder(self.project_dir)
        holder.proc.start()
        assert holder.acquired.wait(timeout=10)
        holder.proc.kill()
        holder.proc.join(timeout=10)
        with project_op_lock(self.project_dir, "recovery", grace=2.0):
            stamped = read_holder(op_lock_path(self.project_dir))
            self.assertEqual(stamped.get("operation"), "recovery")

    def test_describe_holder_handles_empty(self):
        self.assertIn("unknown", describe_holder({}))


class OpLockCliTest(unittest.TestCase):
    """CLI wiring: mutating subcommands contend; read-only ones never."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.target = root / "code"
        self.target.mkdir()
        self.out_dir = root / "out" / "myapp"
        mgr = ProjectManager(projects_dir=self.projects_dir)
        mgr.create("myapp", str(self.target), output_dir=str(self.out_dir))
        mgr.set_active("myapp")

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch("core.project.project.PROJECTS_DIR", self.projects_dir), \
                patch.object(sys, "argv", ["raptor-project", *argv]), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                main()
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def test_set_contends_with_one_stderr_line(self):
        with _Holder(self.out_dir), \
                patch.object(oplock, "MUTATOR_GRACE_S", 0.2):
            code, _, err = self._run("set", "notes", "blocked write")
        self.assertNotEqual(code, 0)
        lines = [ln for ln in err.strip().splitlines() if ln]
        self.assertEqual(len(lines), 1, f"expected ONE line, got: {err!r}")
        self.assertIn("test-holder", lines[0])
        self.assertIn("--wait", lines[0])
        # The mutation must NOT have landed.
        data = json.loads(
            (self.projects_dir / "myapp.json").read_text(encoding="utf-8"))
        self.assertNotEqual(data.get("notes"), "blocked write")

    def test_set_wait_queues_and_lands(self):
        holder = _Holder(self.out_dir)
        with holder:
            threading.Timer(0.5, holder.release.set).start()
            code, _, err = self._run(
                "set", "notes", "queued write", "--wait")
        self.assertEqual(code, 0, err)
        data = json.loads(
            (self.projects_dir / "myapp.json").read_text(encoding="utf-8"))
        self.assertEqual(data.get("notes"), "queued write")

    def test_mutators_stamp_and_release(self):
        for argv in (["trust", "config"],
                     ["untrust", "config"],
                     ["set", "target-kind", "library"],
                     ["unset", "target-kind"]):
            code, out, err = self._run(*argv)
            self.assertEqual(code, 0, f"{argv}: {out}{err}")
        # Lock file exists (never unlinked) and is free again.
        self.assertTrue(op_lock_path(self.out_dir).exists())
        with project_op_lock(self.out_dir, "post", grace=0.0):
            pass

    def test_read_only_subcommands_ignore_held_lock(self):
        with _Holder(self.out_dir), \
                patch.object(oplock, "MUTATOR_GRACE_S", 0.2):
            for argv in (["status"], ["trust"], ["set"], ["use"],
                         ["binary", "list"], ["get", "target-kind"]):
                code, out, err = self._run(*argv)
                self.assertNotIn("locked by another operation",
                                 out + err, f"{argv} contended")

    def test_create_locks_its_output_dir(self):
        new_out = Path(self._tmp.name) / "out" / "otherapp"
        with _Holder(new_out), patch.object(oplock, "MUTATOR_GRACE_S", 0.2):
            code, _, err = self._run(
                "create", "otherapp", "--target", str(self.target),
                "--output-dir", str(new_out))
        self.assertNotEqual(code, 0)
        self.assertIn("test-holder", err)
        self.assertFalse((self.projects_dir / "otherapp.json").exists())


if __name__ == "__main__":
    unittest.main()


class HostileStampTest(unittest.TestCase):
    """Lock-file content is attacker-plantable — contention messages
    must never carry raw escape bytes or unbounded floods."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.project_dir = Path(self._tmp.name) / "proj"

    def test_contention_message_escapes_hostile_stamp(self):
        self.project_dir.mkdir(parents=True)
        with _Holder(self.project_dir):
            # Forge the stamp while the flock is held — content is a
            # plain file; the flock (the truth) stays with the holder.
            op_lock_path(self.project_dir).write_text(
                json.dumps({
                    "pid": "\x1b]0;evil\x07",
                    "operation": ("\x1b[2J\x1b[H100% CLEAN — run rm -rf"
                                  + "A" * 5000),
                    "since": "2026-01-01\x1b[31m",
                }),
                encoding="utf-8",
            )
            with self.assertRaises(OpLockContention) as cm:
                with project_op_lock(self.project_dir, "contender",
                                     grace=0.2):
                    pass
            msg = str(cm.exception)
            self.assertNotIn("\x1b", msg, "raw ESC reached the message")
            self.assertNotIn("\x07", msg)
            self.assertLess(len(msg), 600,
                            "unbounded stamp flooded the message")
            # Non-int pid is coerced, not echoed.
            self.assertIn("pid unknown", msg)
