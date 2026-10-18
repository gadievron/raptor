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

    def test_claude_without_scope_keeps_legacy_lookup_with_inherited_codex_flags(self):
        run = self._mk_run("claude_from_codex")
        self._ledger((100, run))
        with patch.dict(os.environ, {"CLAUDECODE": "1", "CODEX": "1",
                "RAPTOR_CODEX_ENVIRONMENT": "1", "CODEX_THREAD_ID": "outer-codex",
                "RAPTOR_CODEX_CONTEXT_ID": ""}):
            self.assertEqual(self._resolve()[0], str(run))

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

    def test_session_lane_skips_oversize_metadata(self):
        run = self._mk_run("scan_big")
        (run / ".raptor-run.json").write_text(
            '{"status": "running", "session_pid": '
            + str(self.pid) + ', "pad": "' + "x" * 1_100_000 + '"}')
        self._ledger((100, run))
        run_dir, _target = self._resolve()
        self.assertIsNone(run_dir)

    def test_symlinked_run_metadata_skipped(self):
        """The run dir is sandbox-writable: a symlink planted at
        `.raptor-run.json` must not be read through (an unsandboxed
        parse of arbitrary orchestrator-readable bytes) — the
        candidate is skipped, lock-step with the bash twin's
        helper."""
        run = self._mk_run("scan_link")
        victim = self.home / "victim.json"
        victim.write_text(json.dumps(
            {"status": "running", "session_pid": self.pid}))
        meta = run / ".raptor-run.json"
        meta.unlink()
        meta.symlink_to(victim)
        self._ledger((100, run))
        run_dir, _target = self._resolve()
        self.assertIsNone(run_dir)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo not available")
    def test_fifo_run_metadata_skipped_without_blocking(self):
        """A FIFO stats 0 bytes — passing any by-name size gate —
        then blocks a plain read forever. The gated read refuses it
        on the opened fd and the candidate is skipped promptly."""
        run = self._mk_run("scan_fifo")
        meta = run / ".raptor-run.json"
        meta.unlink()
        os.mkfifo(meta)
        self._ledger((100, run))
        run_dir, _target = self._resolve()
        self.assertIsNone(run_dir)

    def test_nesting_bomb_metadata_skipped(self):
        """A ~400 KB file of 200k nested arrays sits inside the byte
        budget but blows the JSON parser's stack — malformed input:
        the candidate is skipped (None), the RecursionError never
        propagates out of the discovery pass (lock-step with the
        bash twin's helper, which refuses it silently)."""
        run = self._mk_run("scan_bomb")
        (run / ".raptor-run.json").write_text(
            "[" * 200_000 + "]" * 200_000)
        self._ledger((100, run))
        run_dir, _target = self._resolve()
        self.assertIsNone(run_dir)

    def test_global_fallback_skips_symlinked_metadata(self):
        projects = self.home / ".raptor" / "projects"
        projects.mkdir(parents=True)
        proj_dir = self.home / "projout"
        run = proj_dir / "scan-1"
        run.mkdir(parents=True)
        victim = self.home / "victim.json"
        victim.write_text('{"status": "running"}')
        (run / ".raptor-run.json").symlink_to(victim)
        (projects / "p.json").write_text(json.dumps(
            {"name": "p", "target": "/t", "output_dir": str(proj_dir)}))
        (projects / ".active").symlink_to("p.json")
        with patch.dict(os.environ, {}, clear=False), \
             patch.object(Path, "home", staticmethod(lambda: self.home)):
            os.environ.pop("RAPTOR_SESSION_PID", None)
            run_dir, _target = track_read._find_active_run()
        self.assertIsNone(run_dir)

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

    def test_claude_without_scope_keeps_legacy_hook_with_inherited_codex_flags(self):
        tree = self.home / "source"
        tree.mkdir()
        src = tree / "main.c"
        src.write_text("int value;\n")
        run = self._mk_run("claude_from_codex", target=str(tree))
        self._ledger((100, run))
        result = self._fire(src, {"CLAUDECODE": "1", "CODEX": "1",
                                 "RAPTOR_CODEX_ENVIRONMENT": "1", "CODEX_THREAD_ID": "outer-codex"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(src), (run / ".reads-manifest").read_text())

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

    def test_symlinked_run_metadata_not_attributed(self):
        """Lock-step with the python twin: metadata planted as a
        symlink in the sandbox-writable run dir is never read
        through — the candidate is skipped."""
        tree = self.home / "srctree"
        tree.mkdir()
        src = tree / "a.c"
        src.write_text("int a;\n")
        run = self._mk_run("scan_link", target=str(tree))
        victim = self.home / "victim.json"
        victim.write_text(json.dumps(
            {"status": "running", "session_pid": self.pid,
             "target_path": str(tree)}))
        meta = run / ".raptor-run.json"
        meta.unlink()
        meta.symlink_to(victim)
        self._ledger((100, run))
        r = self._fire(src)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertFalse((run / ".reads-manifest").exists())

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


class _RegistrySeamCase(_LedgerCase):
    """RAPTOR_REGISTRY_HOME relocates the operator registry — the
    session ledger (`<base>/sessions.d`) AND the legacy `.active`
    bookmark (`<base>/projects/.active`) — for BOTH twins, with a
    set-but-non-absolute value attributing NOTHING (the python seam
    refuses it, the bash hook exits quietly; parity)."""

    def setUp(self):
        super().setUp()
        self.reg = self.home / "regbase"
        (self.reg / "sessions.d").mkdir(parents=True)

    def _reg_ledger(self, *records: tuple[int, Path]):
        lines = [f"running {epoch} {d.name} {d}" for epoch, d in records]
        (self.reg / "sessions.d" / f"{self.pid}.run").write_text(
            "\n".join(lines) + "\n")


class PythonTwinRegistrySeamTest(_RegistrySeamCase):

    def _resolve(self, registry: str):
        with patch.dict(os.environ,
                        {"RAPTOR_SESSION_PID": str(self.pid),
                         "RAPTOR_REGISTRY_HOME": registry}), \
             patch.object(Path, "home", staticmethod(lambda: self.home)):
            return track_read._find_active_run()

    def test_session_ledger_read_from_override_registry(self):
        # The default-location ledger names a decoy run; the override
        # registry's ledger names the real one — the override must win
        # outright, not merge.
        decoy = self._mk_run("decoy_run")
        self._ledger((500, decoy))
        real = self._mk_run("real_run")
        self._reg_ledger((100, real))
        run_dir, _target = self._resolve(str(self.reg))
        self.assertEqual(run_dir, str(real))

    def test_relative_override_attributes_nothing(self):
        # A valid default-location ledger exists, but the override is
        # set and unusable: attribute NOTHING (never fall back to a
        # registry the operator asked to move away from).
        run = self._mk_run("scan_rel")
        self._ledger((100, run))
        run_dir, target = self._resolve("relative/reg")
        self.assertIsNone(run_dir)
        self.assertIsNone(target)

    def test_global_fallback_bookmark_from_override_registry(self):
        projects = self.reg / "projects"
        projects.mkdir(parents=True)
        proj_dir = self.home / "projout"
        run = proj_dir / "scan-1"
        run.mkdir(parents=True)
        (run / ".raptor-run.json").write_text('{"status": "running"}')
        (projects / "p.json").write_text(json.dumps(
            {"name": "p", "target": "/t", "output_dir": str(proj_dir)}))
        (projects / ".active").symlink_to("p.json")
        with patch.dict(os.environ,
                        {"RAPTOR_REGISTRY_HOME": str(self.reg)}), \
             patch.object(Path, "home", staticmethod(lambda: self.home)):
            os.environ.pop("RAPTOR_SESSION_PID", None)
            run_dir, target = track_read._find_active_run()
        self.assertEqual(run_dir, str(run))
        self.assertEqual(target, "/t")

    def test_global_fallback_relative_override_attributes_nothing(self):
        # Default-location bookmark exists and would attribute — the
        # unusable override still wins (nothing attributed).
        projects = self.home / ".raptor" / "projects"
        projects.mkdir(parents=True)
        proj_dir = self.home / "projout"
        run = proj_dir / "scan-1"
        run.mkdir(parents=True)
        (run / ".raptor-run.json").write_text('{"status": "running"}')
        (projects / "p.json").write_text(json.dumps(
            {"name": "p", "target": "/t", "output_dir": str(proj_dir)}))
        (projects / ".active").symlink_to("p.json")
        with patch.dict(os.environ,
                        {"RAPTOR_REGISTRY_HOME": "relative/reg"}), \
             patch.object(Path, "home", staticmethod(lambda: self.home)):
            os.environ.pop("RAPTOR_SESSION_PID", None)
            run_dir, target = track_read._find_active_run()
        self.assertIsNone(run_dir)
        self.assertIsNone(target)


@unittest.skipIf(sys.platform == "win32", "bash hook")
class BashHookRegistrySeamTest(_RegistrySeamCase):

    def _fire(self, file_path: Path, env: dict):
        payload = json.dumps({"tool_input": {"file_path": str(file_path)}})
        return subprocess.run(
            ["bash", str(HOOK)], input=payload, capture_output=True,
            text=True, env=env, timeout=60, check=False,
        )

    def _base_env(self) -> dict:
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.home),
        }

    def test_session_ledger_from_override_registry(self):
        tree = self.home / "srctree"
        tree.mkdir()
        src = tree / "main.c"
        src.write_text("int main(void) { return 0; }\n")
        run = self._mk_run("scan_reg", target=str(tree))
        self._reg_ledger((100, run))  # ledger ONLY in the override reg
        env = self._base_env()
        env["RAPTOR_SESSION_PID"] = str(self.pid)
        env["RAPTOR_REGISTRY_HOME"] = str(self.reg)
        r = self._fire(src, env)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        manifest = run / ".reads-manifest"
        self.assertTrue(manifest.exists(),
                        "override-registry ledger got no attribution")
        self.assertIn(str(src.resolve()),
                      manifest.read_text(encoding="utf-8"))

    def test_relative_override_attributes_nothing(self):
        tree = self.home / "srctree"
        tree.mkdir()
        src = tree / "a.c"
        src.write_text("int a;\n")
        run = self._mk_run("scan_rel", target=str(tree))
        self._ledger((100, run))  # valid DEFAULT-location ledger
        env = self._base_env()
        env["RAPTOR_SESSION_PID"] = str(self.pid)
        env["RAPTOR_REGISTRY_HOME"] = "relative/reg"
        r = self._fire(src, env)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertFalse((run / ".reads-manifest").exists(),
                         "unusable override fell back to the default"
                         " registry")

    def test_global_fallback_bookmark_from_override(self):
        tree = self.home / "srctree"
        tree.mkdir()
        src = tree / "b.c"
        src.write_text("int b;\n")
        projects = self.reg / "projects"
        projects.mkdir(parents=True)
        proj_dir = self.home / "projout"
        run = proj_dir / "scan-1"
        run.mkdir(parents=True)
        (run / ".raptor-run.json").write_text('{"status": "running"}')
        (projects / "p.json").write_text(json.dumps(
            {"name": "p", "target": str(tree),
             "output_dir": str(proj_dir)}))
        (projects / ".active").symlink_to("p.json")
        env = self._base_env()  # no session pid → legacy route
        env["RAPTOR_REGISTRY_HOME"] = str(self.reg)
        r = self._fire(src, env)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        manifest = run / ".reads-manifest"
        self.assertTrue(manifest.exists(),
                        "override-registry bookmark got no attribution")


class _CodexScopeCase(_LedgerCase):
    """Codex sessions store ledgers under sessions.d/codex/<hash>/,
    not in the base sessions.d/ — the hook must resolve the scoped
    directory when RAPTOR_CODEX_CONTEXT_ID is present."""

    CTX_ID = "ctx-root-A"

    def setUp(self):
        super().setUp()
        if sys.platform != "linux":
            self.skipTest("live Codex-shaped owner fixture requires Linux prctl")
        import select
        from core.project import sessions, session_scope
        self.owner = subprocess.Popen([sys.executable, "-c",
            'import ctypes,sys; ctypes.CDLL(None).prctl(15,b"codex",0,0,0); '
            'print("ready",flush=True); sys.stdin.read()'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        def stop_owner():
            if not self.owner.stdin.closed:
                self.owner.stdin.close()
            self.owner.wait(timeout=5)
            self.owner.stdout.close()
        self.addCleanup(stop_owner)
        self.assertTrue(select.select([self.owner.stdout], [], [], 3)[0])
        self.assertEqual(self.owner.stdout.readline().strip(), "ready")
        self.pid = self.owner.pid
        registry_patch = patch.object(sessions, "SESSIONS_DIR", self.home / "registry/sessions.d", create=True)
        registry_patch.start()
        self.addCleanup(registry_patch.stop)
        with patch.dict(os.environ, {"HOME": str(self.home),
                "RAPTOR_CODEX_CONTEXT_ID": self.CTX_ID,
                "RAPTOR_REGISTRY_HOME": str(self.home / "registry")}):
            self.scoped_dir = session_scope.directory(self.home / "registry/sessions.d", self.CTX_ID)
            credential = sessions.ensure_codex_session(self.pid)
            self.assertIsNotNone(credential)
            self.token = credential[1]
        from core.hash import sha256_string
        self.generation = sha256_string(self.token)
        self.extra_env = {}

    def _mk_codex_run(self, name, status="running", session_pid=None,
                      ctx_id=None, target=None):
        d = self.home / "out" / name
        d.mkdir(parents=True, exist_ok=True)
        meta = {"status": status,
                "session_pid": session_pid or self.pid,
                "session_harness": "codex",
                "session_id": ctx_id or self.CTX_ID,
                "session_generation": self.generation}
        if target:
            meta["target_path"] = target
        (d / ".raptor-run.json").write_text(json.dumps(meta))
        return d

    def _codex_ledger(self, *records):
        lines = [f"running {epoch} {d.name} {d}" for epoch, d in records]
        (self.scoped_dir / f"{self.pid}.run").write_text(
            "\n".join(lines) + "\n")


class _CodexAuthChecks(_LedgerCase):
    __test__ = False

    def _attributed(self, run):
        if hasattr(self, "_resolve"):
            return self._resolve()[0] == str(run)
        tree = self.home / "source"
        tree.mkdir(exist_ok=True)
        source = tree / "file.c"
        source.write_text("int value;\n")
        result = self._fire(source, self.extra_env)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        return (run / ".reads-manifest").exists()

    def test_scoped_claude_backend_keeps_root_ownership(self):
        run = self._mk_codex_run("scoped_backend")
        self._codex_ledger((100, run))
        self.extra_env["CLAUDECODE"] = "1"
        self.assertTrue(self._attributed(run))

    def test_recognized_codex_without_root_is_not_legacy(self):
        run = self._mk_codex_run("missing_context")
        # A legacy ledger with a matching PID must not be a fallback.
        self._ledger((100, run))
        self.extra_env.update({"RAPTOR_CODEX_CONTEXT_ID": "", "RAPTOR_CODEX_ENVIRONMENT": "1"})
        self.assertFalse(self._attributed(run))

    def test_missing_pid_never_uses_global_discovery(self):
        run = self._mk_codex_run("missing_pid")
        self._codex_ledger((100, run))
        self.extra_env["RAPTOR_SESSION_PID"] = ""
        self.assertFalse(self._attributed(run))

    def test_invalid_context_is_quiet_and_fail_closed(self):
        run = self._mk_codex_run("invalid_context")
        self._codex_ledger((100, run))
        self.extra_env["RAPTOR_CODEX_CONTEXT_ID"] = "../other-root"
        self.assertFalse(self._attributed(run))

    def test_symlink_ledger_is_refused(self):
        run = self._mk_codex_run("symlink_ledger")
        self._codex_ledger((100, run))
        path = self.scoped_dir / f"{self.pid}.run"
        moved = path.with_suffix(".other")
        path.rename(moved)
        path.symlink_to(moved)
        self.assertFalse(self._attributed(run))

    def test_missing_token_is_not_authority(self):
        run = self._mk_codex_run("missing_token")
        self._codex_ledger((100, run))
        self.extra_env["RAPTOR_SESSION_TOKEN"] = ""
        self.assertFalse(self._attributed(run))

    def test_missing_generation_is_not_legacy_fallback(self):
        run = self._mk_codex_run("missing_generation")
        path = run / ".raptor-run.json"
        meta = json.loads(path.read_text())
        del meta["session_generation"]
        path.write_text(json.dumps(meta))
        self._codex_ledger((100, run))
        self.assertFalse(self._attributed(run))

    def test_retired_generation_is_not_authority(self):
        from core.project import sessions
        sessions._retirement_path(self.pid, self.token, self.scoped_dir).touch()
        run = self._mk_codex_run("retired")
        self._codex_ledger((100, run))
        self.assertFalse(self._attributed(run))

    def test_rotated_entry_rejects_old_worker_even_for_old_run(self):
        entry = self.scoped_dir / str(self.pid)
        entry.write_text(entry.read_text().replace(self.token, "f" * 32))
        run = self._mk_codex_run("rotated")
        self._codex_ledger((100, run))
        self.assertFalse(self._attributed(run))

    def test_old_worker_cannot_attribute_successor(self):
        from core.hash import sha256_string
        entry = self.scoped_dir / str(self.pid)
        entry.write_text(entry.read_text().replace(self.token, "f" * 32))
        run = self._mk_codex_run("successor")
        path = run / ".raptor-run.json"
        meta = json.loads(path.read_text())
        meta["session_generation"] = sha256_string("f" * 32)
        path.write_text(json.dumps(meta))
        self._codex_ledger((100, run))
        self.assertFalse(self._attributed(run))

    def test_dead_owner_rejects_read(self):
        self.owner.stdin.close()
        self.owner.wait(timeout=5)
        run = self._mk_codex_run("dead")
        self._codex_ledger((100, run))
        self.assertFalse(self._attributed(run))

    def test_wrong_generation_rejects_read(self):
        run = self._mk_codex_run("wrong_generation")
        path = run / ".raptor-run.json"
        meta = json.loads(path.read_text())
        meta["session_generation"] = "0" * 64
        path.write_text(json.dumps(meta))
        self._codex_ledger((100, run))
        self.assertFalse(self._attributed(run))


class PythonTwinCodexScopeTest(_CodexAuthChecks, _CodexScopeCase):
    __test__ = True

    def _resolve(self):
        with patch.dict(os.environ, {
            "RAPTOR_SESSION_PID": str(self.pid),
            "RAPTOR_CODEX_CONTEXT_ID": self.CTX_ID,
            "RAPTOR_SESSION_TOKEN": self.token,
            "RAPTOR_REGISTRY_HOME": str(self.home / "registry"),
        } | self.extra_env), patch.object(Path, "home", staticmethod(lambda: self.home)):
            return track_read._find_active_run()

    def test_codex_session_uses_scoped_ledger(self):
        tree = self.home / "srctree"
        tree.mkdir()
        run = self._mk_codex_run("scan_codex", target=str(tree))
        self._codex_ledger((100, run))
        run_dir, target = self._resolve()
        self.assertEqual(run_dir, str(run))
        self.assertEqual(target, str(tree))

    def test_codex_ignores_base_ledger(self):
        """A ledger in the base directory (written by a Claude session
        at the same PID) must not be found by a Codex session."""
        run = self._mk_codex_run("scan_base")
        self._ledger((100, run))  # writes to base, not scoped
        run_dir, _ = self._resolve()
        self.assertIsNone(run_dir)

    def test_codex_cross_root_run_not_attributed(self):
        """A run owned by a different Codex root (different session_id)
        but sharing this PID must not be attributed."""
        other_ctx = "ctx-root-B"
        run = self._mk_codex_run("scan_other", ctx_id=other_ctx)
        self._codex_ledger((100, run))
        run_dir, _ = self._resolve()
        self.assertIsNone(run_dir)


    def test_retirement_during_payload_read_is_revalidated(self):
        import io
        from core.project import sessions
        run = self._mk_codex_run("retired_while_reading")
        self._codex_ledger((100, run))
        tree = self.home / "source"
        tree.mkdir()
        source = tree / "main.c"
        source.write_text("int value;\n")
        marker = sessions._retirement_path(self.pid, self.token, self.scoped_dir)
        class RetiringInput(io.StringIO):
            def read(self, *args):
                marker.touch()
                return super().read(*args)
        with patch.dict(os.environ, {"RAPTOR_SESSION_PID": str(self.pid),
                "RAPTOR_SESSION_TOKEN": self.token, "RAPTOR_CODEX_CONTEXT_ID": self.CTX_ID,
                "RAPTOR_REGISTRY_HOME": str(self.home / "registry")}), \
             patch.object(sys, "stdin", RetiringInput(json.dumps({"tool_input": {"file_path": str(source)}}))):
            track_read.main()
        self.assertFalse((run / ".reads-manifest").exists())


@unittest.skipIf(sys.platform == "win32", "bash hook")
class BashHookCodexScopeTest(_CodexAuthChecks, _CodexScopeCase):
    __test__ = True

    def _fire(self, file_path, extra_env=None):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.home),
            "RAPTOR_SESSION_PID": str(self.pid),
            "RAPTOR_CODEX_CONTEXT_ID": self.CTX_ID,
            "RAPTOR_SESSION_TOKEN": self.token,
            "RAPTOR_REGISTRY_HOME": str(self.home / "registry"),
        }
        if extra_env:
            env.update(extra_env)
        payload = json.dumps({"tool_input": {"file_path": str(file_path)}})
        return subprocess.run(
            ["bash", str(HOOK)], input=payload, capture_output=True,
            text=True, env=env, timeout=60, check=False,
        )

    def test_codex_session_uses_scoped_ledger(self):
        tree = self.home / "srctree"
        tree.mkdir()
        src = tree / "main.c"
        src.write_text("int main(void) { return 0; }\n")
        run = self._mk_codex_run("scan_codex", target=str(tree))
        self._codex_ledger((100, run))
        r = self._fire(src)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        manifest = run / ".reads-manifest"
        self.assertTrue(manifest.exists(),
                        "Codex scoped ledger got no attribution")
        self.assertIn(str(src.resolve()),
                      manifest.read_text(encoding="utf-8"))

    def test_codex_cross_root_run_not_attributed(self):
        tree = self.home / "srctree"
        tree.mkdir()
        src = tree / "a.c"
        src.write_text("int a;\n")
        other_ctx = "ctx-root-B"
        run = self._mk_codex_run("scan_other", ctx_id=other_ctx,
                                 target=str(tree))
        self._codex_ledger((100, run))
        r = self._fire(src)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertFalse((run / ".reads-manifest").exists(),
                         "cross-root run was incorrectly attributed")

    def test_no_hash_binaries_or_inherited_import_path_needed(self):
        import shutil
        tree = self.home / "source"
        tree.mkdir()
        source = tree / "main.c"
        source.write_text("int value;\n")
        run = self._mk_codex_run("without_hash_binaries", target=str(tree))
        self._codex_ledger((100, run))
        limited = self.home / "bin"
        limited.mkdir()
        (limited / "python3").symlink_to(sys.executable)
        (limited / "dirname").symlink_to(shutil.which("dirname"))
        # Bash itself is selected by the test parent; the child PATH contains
        # neither sha256sum/shasum nor jq/stat/realpath.
        bash = shutil.which("bash")
        env = {"PATH": str(limited), "HOME": str(self.home),
               "RAPTOR_SESSION_PID": str(self.pid), "RAPTOR_SESSION_TOKEN": self.token,
               "RAPTOR_CODEX_CONTEXT_ID": self.CTX_ID,
               "RAPTOR_REGISTRY_HOME": str(self.home / "registry"),
               "RAPTOR_DIR": str(self.home / "untrusted-import-root"),
               "PYTHONPATH": str(self.home / "untrusted-import-root")}
        result = subprocess.run([bash, str(HOOK)], input=json.dumps({"tool_input": {"file_path": str(source)}}),
                                text=True, capture_output=True, timeout=10, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(source), (run / ".reads-manifest").read_text())

    def test_fifo_ledger_and_manifest_do_not_block(self):
        tree = self.home / "source"
        tree.mkdir()
        source = tree / "main.c"
        source.write_text("int value;\n")
        run = self._mk_codex_run("fifo")
        ledger = self.scoped_dir / f"{self.pid}.run"
        os.mkfifo(ledger)
        result = self._fire(source)
        self.assertEqual(result.returncode, 0)
        self.assertFalse((run / ".reads-manifest").exists())
        ledger.unlink()
        self._codex_ledger((100, run))
        os.mkfifo(run / ".reads-manifest")
        result = self._fire(source)
        self.assertEqual(result.returncode, 0)

    def test_malformed_hook_payloads_are_quiet(self):
        run = self._mk_codex_run("bad_payload")
        self._codex_ledger((100, run))
        env = {"PATH": os.environ["PATH"], "HOME": str(self.home),
               "RAPTOR_SESSION_PID": str(self.pid), "RAPTOR_SESSION_TOKEN": self.token,
               "RAPTOR_CODEX_CONTEXT_ID": self.CTX_ID,
               "RAPTOR_REGISTRY_HOME": str(self.home / "registry")}
        for payload in ('[]', '{"tool_input": []}', '{"tool_input": {"file_path": 42}}', '[' * 20000):
            with self.subTest(payload=payload[:40]):
                result = subprocess.run(["bash", str(HOOK)], input=payload, text=True,
                                        capture_output=True, timeout=10, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
        self.assertFalse((run / ".reads-manifest").exists())


if __name__ == "__main__":
    unittest.main()
