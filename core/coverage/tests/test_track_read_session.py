"""Session-ledger read attribution — the hook's primary route.

The python twin (`core.coverage.track_read._find_active_run`) and the
bash hook (`plugins/coverage/libexec/raptor-hook-read`) resolve the
run via the session RUN LEDGER when RAPTOR_SESSION_PID is present:
exact attribution for project, --out, and STANDALONE runs alike, with
per-candidate validation (status=running, session ownership) and
nothing attributed in-session when no candidate validates.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.coverage import track_read

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK = REPO_ROOT / "plugins" / "coverage" / "libexec" / "raptor-hook-read"


class _LedgerCase(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)
        self.sessions_dir = (self.home / ".local" / "share" / "raptor"
                             / "sessions.d")
        self.sessions_dir.mkdir(parents=True)
        self.pid = 424242

    def _mk_run(self, name: str, status: str = "running",
                session_pid: int | None = None,
                target: str | None = None) -> Path:
        d = self.home / "out" / name
        d.mkdir(parents=True)
        meta: dict = {"status": status,
                      "session_pid": session_pid
                      if session_pid is not None else self.pid}
        if target:
            meta["target_path"] = target
        (d / ".raptor-run.json").write_text(json.dumps(meta))
        return d

    def _ledger(self, *records: tuple[int, Path]):
        lines = [f"running {epoch} {d.name} {d}" for epoch, d in records]
        (self.sessions_dir / f"{self.pid}.run").write_text(
            "\n".join(lines) + "\n")


class PythonTwinSessionTest(_LedgerCase):

    def _resolve(self):
        with patch.dict(os.environ,
                        {"RAPTOR_SESSION_PID": str(self.pid)}), \
             patch.object(Path, "home", staticmethod(lambda: self.home)):
            return track_read._find_active_run()

    def test_standalone_run_attributes(self):
        """Decision 12: no project anywhere — the ledger still names
        the run, and the target filter comes from run metadata."""
        tree = self.home / "sometree"
        tree.mkdir()
        run = self._mk_run("scan_solo", target=str(tree))
        self._ledger((100, run))
        run_dir, target = self._resolve()
        self.assertEqual(run_dir, str(run))
        self.assertEqual(target, str(tree))

    def test_unresolvable_target_clears_the_filter(self):
        # bash-twin parity: realpath fails on a missing tree and the
        # hook attributes UNFILTERED — the twin must not silently
        # drop every read by keeping a filter nothing can match.
        run = self._mk_run("scan_gone", target="/no/such/tree")
        self._ledger((100, run))
        run_dir, target = self._resolve()
        self.assertEqual(run_dir, str(run))
        self.assertEqual(target, "")

    def test_deleted_leaf_keeps_the_filter_like_bash(self):
        # bash realpath resolves a missing LEAF fine (fails only on a
        # missing parent) and keeps the filter — parity means the twin
        # keeps it too.
        tree = self.home / "goneleaf"   # parent exists, leaf doesn't
        run = self._mk_run("scan_leaf", target=str(tree))
        self._ledger((100, run))
        _run_dir, target = self._resolve()
        self.assertEqual(target, str(tree))

    def test_far_future_epoch_record_skipped(self):
        ok = self._mk_run("scan_now")
        skew = self._mk_run("scan_skew")
        self._ledger((99999999999, skew), (100, ok))
        run_dir, _target = self._resolve()
        self.assertEqual(run_dir, str(ok))

    def test_scan_stops_at_first_pin_line(self):
        # Writer invariant: run records render BEFORE pin witnesses,
        # so nothing below a pin is a run record. The bash twin
        # early-stops there; the python twin must match — a
        # (writer-bug) running line after a pin is ignored by both.
        before = self._mk_run("scan_before")
        after = self._mk_run("scan_after")
        (self.sessions_dir / f"{self.pid}.run").write_text(
            f"running 100 {before.name} {before}\n"
            f"pin 100 {before.name} - {before}\n"
            f"running 200 {after.name} {after}\n")
        run_dir, _ = self._resolve()
        self.assertEqual(run_dir, str(before))

    def test_newest_valid_live_run_wins(self):
        old = self._mk_run("old_run")
        new = self._mk_run("new_run")
        self._ledger((100, old), (200, new))
        run_dir, _ = self._resolve()
        self.assertEqual(run_dir, str(new))

    def test_terminal_run_skipped_even_with_stale_ledger_line(self):
        """A killed run's ledger line stays 'running' — the
        self-authenticating metadata check rejects it."""
        dead = self._mk_run("dead_run", status="failed")
        live = self._mk_run("live_run")
        self._ledger((300, dead), (100, live))
        run_dir, _ = self._resolve()
        self.assertEqual(run_dir, str(live))

    def test_cross_session_resume_ownership(self):
        """A run resumed by ANOTHER session records that session's pid
        — this session's hook must stop attributing to it."""
        stolen = self._mk_run("resumed_elsewhere", session_pid=999999)
        self._ledger((100, stolen))
        run_dir, _ = self._resolve()
        self.assertIsNone(run_dir)

    def test_in_session_never_falls_to_global_heuristic(self):
        """With a session credential and NO valid ledger candidate,
        attribute nothing — even when a machine-global active project
        has a running run."""
        projects = self.home / ".raptor" / "projects"
        projects.mkdir(parents=True)
        proj_dir = self.home / "projout"
        other_run = proj_dir / "scan-1"
        other_run.mkdir(parents=True)
        (other_run / ".raptor-run.json").write_text(
            '{"status": "running"}')
        (projects / "p.json").write_text(json.dumps(
            {"name": "p", "target": "/t", "output_dir": str(proj_dir)}))
        (projects / ".active").symlink_to("p.json")
        run_dir, _ = self._resolve()
        self.assertIsNone(run_dir)

    def test_no_session_uses_global_fallback(self):
        projects = self.home / ".raptor" / "projects"
        projects.mkdir(parents=True)
        proj_dir = self.home / "projout"
        run = proj_dir / "scan-1"
        run.mkdir(parents=True)
        (run / ".raptor-run.json").write_text('{"status": "running"}')
        (projects / "p.json").write_text(json.dumps(
            {"name": "p", "target": "/t", "output_dir": str(proj_dir)}))
        (projects / ".active").symlink_to("p.json")
        with patch.dict(os.environ, {}, clear=False), \
             patch.object(Path, "home", staticmethod(lambda: self.home)):
            os.environ.pop("RAPTOR_SESSION_PID", None)
            run_dir, target = track_read._find_active_run()
        self.assertEqual(run_dir, str(run))
        self.assertEqual(target, "/t")

    def test_global_fallback_skips_oversize_metadata(self):
        # Lock-step parity with the session lane's 1 MiB gate: the
        # legacy walk read .raptor-run.json unbounded while its own
        # session lane refused oversize files.
        projects = self.home / ".raptor" / "projects"
        projects.mkdir(parents=True)
        proj_dir = self.home / "projout"
        run = proj_dir / "scan-1"
        run.mkdir(parents=True)
        (run / ".raptor-run.json").write_text(
            '{"status": "running", "pad": "'
            + "x" * 1_100_000 + '"}')
        (projects / "p.json").write_text(json.dumps(
            {"name": "p", "target": "/t", "output_dir": str(proj_dir)}))
        (projects / ".active").symlink_to("p.json")
        with patch.dict(os.environ, {}, clear=False), \
             patch.object(Path, "home", staticmethod(lambda: self.home)):
            os.environ.pop("RAPTOR_SESSION_PID", None)
            run_dir, _target = track_read._find_active_run()
        self.assertIsNone(run_dir)


@unittest.skipIf(sys.platform == "win32", "bash hook")
class BashHookSessionTest(_LedgerCase):
    """The bash hook honours the same contract (lock-step twin)."""

    def _fire(self, file_path: Path, extra_env: dict | None = None):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.home),
            "RAPTOR_SESSION_PID": str(self.pid),
        }
        if extra_env:
            env.update(extra_env)
        payload = json.dumps({"tool_input": {"file_path": str(file_path)}})
        return subprocess.run(
            ["bash", str(HOOK)], input=payload, capture_output=True,
            text=True, env=env, timeout=60, check=False,
        )

    def test_standalone_run_manifest_append(self):
        tree = self.home / "srctree"
        tree.mkdir()
        src = tree / "main.c"
        src.write_text("int main(void) { return 0; }\n")
        run = self._mk_run("scan_solo", target=str(tree))
        self._ledger((100, run))
        r = self._fire(src)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        manifest = run / ".reads-manifest"
        self.assertTrue(manifest.exists(),
                        "standalone run got no read attribution")
        self.assertIn(str(src.resolve()),
                      manifest.read_text(encoding="utf-8"))

    def test_target_filter_from_run_metadata(self):
        tree = self.home / "srctree"
        tree.mkdir()
        outside = self.home / "elsewhere.c"
        outside.write_text("int x;\n")
        run = self._mk_run("scan_solo", target=str(tree))
        self._ledger((100, run))
        r = self._fire(outside)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertFalse((run / ".reads-manifest").exists(),
                         "out-of-target read was attributed")

    def test_foreign_session_run_not_attributed(self):
        tree = self.home / "srctree"
        tree.mkdir()
        src = tree / "a.c"
        src.write_text("int a;\n")
        stolen = self._mk_run("resumed_elsewhere", session_pid=999999,
                              target=str(tree))
        self._ledger((100, stolen))
        r = self._fire(src)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertFalse((stolen / ".reads-manifest").exists())


if __name__ == "__main__":
    unittest.main()
