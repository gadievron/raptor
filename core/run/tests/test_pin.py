"""Run-scoped project pinning — start-time precedence,
write-once, the in-run state table, walk-up safety, and the lifecycle
ledger wiring."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.json import load_json, save_json
from core.project import sessions
from core.project.project import ProjectManager
from core.run import RUN_METADATA_FILE, complete_run, start_run
from core.run.pin import (
    ProjectArgvError,
    RunPin,
    resolve_pin_for_start,
    resolve_run_pin,
    set_process_project,
)


class _PinCase(unittest.TestCase):
    """Isolated projects dir + sessions dir + a claude-shaped self."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.projects_dir = self.root / "projects"
        self.sessions_dir = self.root / "sessions.d"
        (self.root / "code").mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("pinned", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "pinned"))
        for p in (
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
            patch.object(sessions, "SESSIONS_DIR", self.sessions_dir),
            patch.object(sessions, "_comm",
                         lambda pid: "claude" if pid == os.getpid()
                         else None),
        ):
            p.start()
            self.addCleanup(p.stop)
        set_process_project(None)
        self.addCleanup(set_process_project, None)


class ResolveForStartTest(_PinCase):

    def test_argv_beats_binding_beats_symlink(self):
        self.mgr.create("other", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "other"))
        self.mgr.set_active("other")
        sessions.record_session("pinned", pid=os.getpid())
        with patch.object(sessions, "resolve_session_pid",
                          return_value=os.getpid()):
            self.assertEqual(resolve_pin_for_start(),
                             ("pinned", "session"))
            set_process_project("other")
            self.assertEqual(resolve_pin_for_start(), ("other", "argv"))
            set_process_project("-")
            self.assertEqual(resolve_pin_for_start(), (None, "argv"))

    def test_symlink_layer_when_no_binding(self):
        self.mgr.set_active("pinned")
        with patch.object(sessions, "resolve_session_pid",
                          return_value=None):
            self.assertEqual(resolve_pin_for_start(),
                             ("pinned", "symlink"))

    def test_none_when_nothing(self):
        with patch.object(sessions, "resolve_session_pid",
                          return_value=None):
            self.assertEqual(resolve_pin_for_start(), (None, "none"))

    def test_bound_to_none_is_authoritative_over_symlink(self):
        self.mgr.set_active("pinned")
        sessions.bind_session(None, pid=os.getpid())
        with patch.object(sessions, "resolve_session_pid",
                          return_value=os.getpid()):
            self.assertEqual(resolve_pin_for_start(), (None, "session"))

    def test_stale_binding_never_falls_through(self):
        self.mgr.create("doomed", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "doomed"))
        self.mgr.set_active("pinned")
        sessions.record_session("doomed", pid=os.getpid())
        self.mgr.delete("doomed")
        with patch.object(sessions, "resolve_session_pid",
                          return_value=os.getpid()):
            self.assertEqual(resolve_pin_for_start(), (None, "session"))

    def test_invalid_argv_is_hard_error(self):
        set_process_project("no-such-project")
        with self.assertRaises(ProjectArgvError):
            resolve_pin_for_start()
        set_process_project("../evil")
        with self.assertRaises(ProjectArgvError):
            resolve_pin_for_start()


class StartRunPinTest(_PinCase):

    def test_pin_recorded_null_for_standalone(self):
        out = self.root / "standalone" / "run"
        with patch.object(sessions, "resolve_session_pid",
                          return_value=None):
            start_run(out, "scan")
        meta = load_json(out / RUN_METADATA_FILE)
        self.assertIsNone(meta["project"])
        self.assertEqual(meta["project_source"], "none")

    def test_pin_write_once_across_reentrant_start(self):
        """The documented re-entrant flows must not re-pin: a binding
        change between the two starts is exactly the contamination the
        pin exists to stop."""
        out = self.root / "out" / "pinned" / "agentic-1"
        self.mgr.set_active("pinned")
        with patch.object(sessions, "resolve_session_pid",
                          return_value=None):
            start_run(out, "agentic")
            self.mgr.set_active(None)  # layer moves under the run
            start_run(out, "agentic")  # re-entrant second start
        meta = load_json(out / RUN_METADATA_FILE)
        self.assertEqual(meta["project"], "pinned")
        self.assertEqual(meta["project_source"], "symlink")

    def test_conflicting_argv_on_reentrant_start_is_hard_error(self):
        out = self.root / "out" / "pinned" / "agentic-2"
        self.mgr.set_active("pinned")
        self.mgr.create("other", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "other"))
        with patch.object(sessions, "resolve_session_pid",
                          return_value=None):
            start_run(out, "agentic")
            set_process_project("other")
            with self.assertRaises(ProjectArgvError):
                start_run(out, "agentic")

    def test_pin_survives_completion_metadata_merge(self):
        out = self.root / "out" / "pinned" / "scan-1"
        self.mgr.set_active("pinned")
        with patch.object(sessions, "resolve_session_pid",
                          return_value=None):
            start_run(out, "scan")
        complete_run(out)
        meta = load_json(out / RUN_METADATA_FILE)
        self.assertEqual(meta["project"], "pinned")


class ResolveRunPinTest(_PinCase):

    def _run_dir(self, name: str, project, source: str) -> Path:
        d = self.root / "out" / name
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": project,
            "project_source": source,
        })
        return d

    def test_pinned_project_authoritative(self):
        d = self._run_dir("r1", "pinned", "session")
        pin = resolve_run_pin(d)
        self.assertEqual((pin.project, pin.source), ("pinned", "session"))
        self.assertTrue(pin.authoritative)
        self.assertTrue(pin.writes_allowed)

    def test_null_pin_forbids_containment_inference(self):
        """A standalone run placed INSIDE a project dir via --out must
        stay standalone — containment would re-open the contamination
        pinning closes."""
        d = self.root / "out" / "pinned" / "smuggled"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": None, "project_source": "none",
        })
        pin = resolve_run_pin(d)
        self.assertIsNone(pin.project)
        self.assertTrue(pin.authoritative)

    def test_deleted_project_pin_is_authoritative_none(self):
        d = self._run_dir("r2", "ghost", "session")
        pin = resolve_run_pin(d)
        self.assertIsNone(pin.project)
        self.assertTrue(pin.authoritative)

    def test_child_out_dir_walks_up_to_owning_run(self):
        d = self._run_dir("r3", "pinned", "symlink")
        child = d / "scan"
        child.mkdir()
        pin = resolve_run_pin(child)
        self.assertEqual(pin.project, "pinned")
        self.assertEqual(pin.run_dir, d.resolve())

    def test_legacy_run_falls_back_to_containment_reads_only(self):
        d = Path(self.mgr.load("pinned").output_dir) / "old-run"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {"status": "running"})  # no pin
        pin = resolve_run_pin(d)
        self.assertEqual(pin.project, "pinned")
        self.assertFalse(pin.authoritative)
        self.assertFalse(pin.writes_allowed)

    def test_no_marker_containment_reads_only(self):
        d = Path(self.mgr.load("pinned").output_dir) / "not-a-run"
        d.mkdir(parents=True)
        pin = resolve_run_pin(d)
        self.assertEqual(pin.project, "pinned")
        self.assertFalse(pin.writes_allowed)

    def test_world_writable_marker_ignored(self):
        d = self.root / "out" / "planted"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": "pinned",
            "project_source": "session",
        })
        os.chmod(d, 0o777)
        sub = d / "victim"
        sub.mkdir()
        pin = resolve_run_pin(sub)
        self.assertFalse(pin.authoritative)
        self.assertFalse(pin.writes_allowed)


class LedgerWiringTest(_PinCase):

    def test_start_and_terminal_wire_the_ledger(self):
        sessions.record_session("pinned", pid=os.getpid())
        out = self.root / "out" / "pinned" / "scan-9"
        with patch("core.run.metadata._get_session_pid",
                   return_value=os.getpid()), \
                patch.object(sessions, "resolve_session_pid",
                             return_value=os.getpid()):
            start_run(out, "scan")
            runs = sessions.ledger_runs(pid=os.getpid())
            self.assertEqual(
                [(r["run_id"], r["status"]) for r in runs],
                [("scan-9", "running")])
            complete_run(out)
        runs = sessions.ledger_runs(pid=os.getpid())
        self.assertEqual(runs[0]["status"], "completed")

    def test_unregistered_session_gets_no_ledger(self):
        out = self.root / "out" / "pinned" / "scan-10"
        with patch("core.run.metadata._get_session_pid",
                   return_value=os.getpid()), \
                patch.object(sessions, "resolve_session_pid",
                             return_value=os.getpid()):
            start_run(out, "scan")
        self.assertFalse(
            (self.sessions_dir / f"{os.getpid()}.run").exists())


class RunPinShapeTest(unittest.TestCase):

    def test_dataclass_shape(self):
        pin = RunPin(None, "none", None, True, True)
        self.assertIsNone(pin.project)
        with self.assertRaises(AttributeError):
            pin.project = "x"  # frozen


if __name__ == "__main__":
    unittest.main()


class PinConsumerMigrationTest(_PinCase):
    """Wave-1 consumers follow the RUN PIN, not the ambient layers
   : trust markers, persisted binaries, and
    the child-process pin bootstrap."""

    def _pinned_run(self, project: str | None) -> Path:
        d = self.root / "out" / f"run-{project or 'none'}"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": project,
            "project_source": "session",
        })
        return d

    def test_trust_markers_follow_the_pin(self):
        proj = self.mgr.load("pinned")
        proj.trust = {"dynamic": "2026-08-23T00:00:00+00:00"}
        self.mgr._save(proj)
        self.mgr.create("ambient", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "ambient"))
        self.mgr.set_active("ambient")
        run = self._pinned_run("pinned")
        from core.project.trust import active_project_trust
        markers, name = active_project_trust(run_dir=run)
        self.assertEqual(name, "pinned")
        self.assertIn("dynamic", markers)
        # Ambient (no run_dir) resolves the active layer instead.
        _m, ambient_name = active_project_trust()
        self.assertEqual(ambient_name, "ambient")

    def test_dynamic_marker_gated_by_pinned_target(self):
        proj = self.mgr.load("pinned")
        proj.trust = {"dynamic": "2026-08-23T00:00:00+00:00"}
        self.mgr._save(proj)
        run = self._pinned_run("pinned")
        from core.project.trust import resolve_dynamic_validation
        self.assertTrue(resolve_dynamic_validation(
            None, banner=False,
            target_path=self.root / "code", run_dir=run))
        self.assertFalse(resolve_dynamic_validation(
            None, banner=False,
            target_path=self.root / "elsewhere", run_dir=run))

    def test_project_binaries_one_target_gate(self):
        """a security-review finding: project X's binaries must never drive absent
        verdicts for tree Y."""
        binary = self.root / "code" / "app.bin"
        binary.write_bytes(b"\x7fELF")
        proj = self.mgr.load("pinned")
        proj.binaries = [str(binary)]
        self.mgr._save(proj)
        self.mgr.set_active("pinned")
        from core.analysis.binary_oracle_cli import _project_binaries
        paths, name = _project_binaries(repo=self.root / "code")
        self.assertEqual([str(p) for p in paths], [str(binary)])
        foreign = self.root / "foreign-tree"
        foreign.mkdir()
        paths, name = _project_binaries(repo=foreign)
        self.assertEqual(paths, [])
        self.assertEqual(name, "pinned")

    def test_bootstrap_adopts_authoritative_pin_only(self):
        from core.run.pin import bootstrap_process_pin, get_process_project
        run = self._pinned_run("pinned")
        child_out = run / "scan"
        child_out.mkdir()
        bootstrap_process_pin(child_out)
        self.assertEqual(get_process_project(), "pinned")
        set_process_project(None)
        # Legacy (pin-less) run dir: containment is reads-only — the
        # bootstrap must NOT promote it to a process override.
        legacy = Path(self.mgr.load("pinned").output_dir) / "legacy"
        legacy.mkdir(parents=True)
        save_json(legacy / RUN_METADATA_FILE, {"status": "running"})
        bootstrap_process_pin(legacy)
        self.assertIsNone(get_process_project())

    def test_bootstrap_never_overwrites_explicit_argv(self):
        from core.run.pin import bootstrap_process_pin, get_process_project
        run = self._pinned_run("pinned")
        set_process_project("pinned")
        bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "pinned")

    def test_bootstrap_conflicting_argv_hard_errors(self):
        # --project X plus --out <run pinned to Y> would run SPLIT
        # (override for ambient consumers, pin for run-dir consumers):
        # hard error, never a silent pick.
        from core.run.pin import ProjectArgvError, bootstrap_process_pin
        run = self._pinned_run("pinned")
        set_process_project("-")
        with self.assertRaises(ProjectArgvError):
            bootstrap_process_pin(run)

    def test_null_pin_bootstraps_projectless(self):
        from core.run.pin import bootstrap_process_pin, get_process_project
        run = self._pinned_run(None)
        bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "-")

    def test_bootstrap_witness_disagreement_uses_witness(self):
        # The run marker is child-writable; the ledger witness is not.
        # A disagreement means the marker was rewritten — the witness
        # wins the adoption AND the seal.
        from core.run.pin import (
            _frozen_pins,
            bootstrap_process_pin,
            get_process_project,
        )
        run = self._pinned_run("pinned")
        with patch.object(sessions, "ledger_pin_witness",
                          lambda run_dir, pid=None: (True, None,
                                                     "session")):
            bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "-")
        frozen = _frozen_pins.get(str(run.resolve()))
        self.assertIsNotNone(frozen)
        self.assertIsNone(frozen.project)

    def test_bootstrap_unwitnessed_adoption_never_sealed(self):
        # No witness (pre-witness run, sessionless): the adoption keeps
        # compatibility, but an unwitnessed marker must never be
        # laundered into trusted frozen state for the process lifetime.
        from core.run.pin import (
            _frozen_pins,
            bootstrap_process_pin,
            get_process_project,
        )
        run = self._pinned_run("pinned")
        with patch.object(sessions, "ledger_pin_witness",
                          lambda run_dir, pid=None: (False, None, None)):
            bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "pinned")
        self.assertNotIn(str(run.resolve()), _frozen_pins)

    def test_bootstrap_witnessed_agreement_sealed(self):
        # Two-direction guard: a witnessed, agreeing marker still gets
        # the freeze-cache seal (marker-rewrite immunity).
        from core.run.pin import (
            _frozen_pins,
            bootstrap_process_pin,
            get_process_project,
        )
        run = self._pinned_run("pinned")
        with patch.object(sessions, "ledger_pin_witness",
                          lambda run_dir, pid=None: (True, "pinned",
                                                     "session")):
            bootstrap_process_pin(run)
        self.assertEqual(get_process_project(), "pinned")
        frozen = _frozen_pins.get(str(run.resolve()))
        self.assertIsNotNone(frozen)
        self.assertEqual(frozen.project, "pinned")


class PinFreezeCacheTest(_PinCase):
    """The process freeze cache seals the pin at start_run: a child
    rewriting the on-disk marker (the run dir is the sandbox write
    grant) must not move this process's consumers."""

    def _run_dir(self) -> Path:
        d = self.root / "out" / "pinned" / "scan_x"
        d.mkdir(parents=True)
        return d

    def test_marker_rewrite_cannot_move_frozen_pin(self):
        from core.run.metadata import start_run
        from core.run.pin import resolve_run_pin
        d = self._run_dir()
        self.mgr.set_active("pinned")
        start_run(d, "scan", target=str(self.root / "code"))
        self.assertEqual(resolve_run_pin(d).project, "pinned")
        # Hostile child rewrites the marker in place.
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": "evil",
            "project_source": "session",
        })
        self.assertEqual(resolve_run_pin(d).project, "pinned")

    def test_reentrant_start_consults_cache_not_disk(self):
        from core.run.metadata import load_run_metadata, start_run
        d = self._run_dir()
        self.mgr.set_active("pinned")
        start_run(d, "scan", target=str(self.root / "code"))
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": "evil",
            "project_source": "session",
        })
        start_run(d, "scan", target=str(self.root / "code"))
        self.assertEqual(load_run_metadata(d)["project"], "pinned")

    def test_pin_survives_completed_status(self):
        # /understand → /validate sharing one --out: the pin written at
        # the first start governs the second even after completion —
        # a mid-gap /project switch must not re-pin the dir. The
        # continuity is witness-backed: the first start's ledger
        # witness corroborates the disk pin for the second start
        # (an UNcorroborated disk pin in a reused --out dir does not
        # elect a project — that is the planted-marker defense).
        from core.run.metadata import complete_run, load_run_metadata, start_run
        from core.run.pin import _frozen_pins
        sessions.record_session("pinned", pid=os.getpid())
        patcher = patch.object(sessions, "resolve_session_pid",
                               return_value=os.getpid())
        patcher.start()
        self.addCleanup(patcher.stop)
        d = self._run_dir()
        self.mgr.set_active("pinned")
        start_run(d, "understand", target=str(self.root / "code"))
        complete_run(d)
        _frozen_pins.clear()  # simulate a fresh process
        self.mgr.create("other", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "other"))
        self.mgr.set_active("other")
        start_run(d, "validate", target=str(self.root / "code"))
        self.assertEqual(load_run_metadata(d)["project"], "pinned")

    def test_uncorroborated_disagreement_is_a_hard_error(self):
        # A disagreeing pin with NO witness (planted marker — or a
        # legitimate reuse across a relaunch, indistinguishable) must
        # not silently elect EITHER side: the operator disambiguates
        # via --project.
        from core.json import save_json as _sj
        from core.run.metadata import start_run
        from core.run.pin import ProjectArgvError, set_process_project
        d = self.root / "out" / "reused"
        d.mkdir(parents=True)
        _sj(d / RUN_METADATA_FILE, {
            "status": "completed", "project": "pinned",
            "project_source": "argv",
        })
        self.mgr.create("ambient3", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "ambient3"))
        self.mgr.set_active("ambient3")
        with self.assertRaises(ProjectArgvError):
            start_run(d, "scan", target=str(self.root / "code"))
        # Explicit --project resolves the ambiguity EITHER way: the
        # error's own remedies must both work.
        set_process_project("ambient3")   # re-pin to the fresh side
        try:
            start_run(d, "scan", target=str(self.root / "code"))
        finally:
            set_process_project(None)
        from core.run.metadata import load_run_metadata
        self.assertEqual(load_run_metadata(d)["project"], "ambient3")

    def test_uncorroborated_keep_side_override_works(self):
        from core.json import save_json as _sj
        from core.run.metadata import load_run_metadata, start_run
        from core.run.pin import set_process_project
        d = self.root / "out" / "reused3"
        d.mkdir(parents=True)
        _sj(d / RUN_METADATA_FILE, {
            "status": "completed", "project": "pinned",
            "project_source": "argv",
        })
        self.mgr.create("ambient4", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "ambient4"))
        self.mgr.set_active("ambient4")
        set_process_project("pinned")   # keep the dir's pin
        try:
            start_run(d, "scan", target=str(self.root / "code"))
        finally:
            set_process_project(None)
        self.assertEqual(load_run_metadata(d)["project"], "pinned")

    def test_uncorroborated_agreement_stands_silently(self):
        from core.json import save_json as _sj
        from core.run.metadata import load_run_metadata, start_run
        d = self.root / "out" / "reused2"
        d.mkdir(parents=True)
        _sj(d / RUN_METADATA_FILE, {
            "status": "completed", "project": "pinned",
            "project_source": "session",
        })
        self.mgr.set_active("pinned")
        start_run(d, "scan", target=str(self.root / "code"))
        self.assertEqual(load_run_metadata(d)["project"], "pinned")


class OutermostMarkerTest(_PinCase):
    def test_nested_planted_marker_loses_to_outer(self):
        from core.run.pin import resolve_run_pin
        outer = self.root / "out" / "pinned" / "fuzz_1"
        inner = outer / "afl-out" / "crashes"
        inner.mkdir(parents=True)
        save_json(outer / RUN_METADATA_FILE, {
            "status": "running", "project": "pinned",
            "project_source": "session",
        })
        save_json(inner / RUN_METADATA_FILE, {
            "status": "running", "project": "evil",
            "project_source": "session",
        })
        pin = resolve_run_pin(inner)
        self.assertEqual(pin.project, "pinned")


class OneTargetGateTest(_PinCase):
    def _pinned_run(self, target: str) -> Path:
        d = self.root / "out" / "pinned" / "audit_1"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "completed", "project": "pinned",
            "project_source": "session", "target_path": target,
        })
        return d

    def test_matching_target_passes(self):
        from core.run.pin import pinned_write_target_ok
        d = self._pinned_run(str(self.root / "code"))
        self.assertTrue(pinned_write_target_ok(d))

    def test_foreign_target_suppresses_project_store_writes(self):
        from core.run.metadata import _journal_project_dir
        from core.run.pin import pinned_write_target_ok
        (self.root / "elsewhere").mkdir()
        d = self._pinned_run(str(self.root / "elsewhere"))
        self.assertFalse(pinned_write_target_ok(d))
        self.assertIsNone(_journal_project_dir(d))

    def test_no_recorded_target_passes(self):
        from core.run.pin import pinned_write_target_ok
        d = self.root / "out" / "pinned" / "audit_1"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "completed", "project": "pinned",
            "project_source": "session",
        })
        self.assertTrue(pinned_write_target_ok(d))


class WriteRunPinTest(_PinCase):
    def test_upsert_preserves_other_keys(self):
        from core.json import load_json
        from core.run.metadata import write_run_pin
        d = self.root / "out" / "loose" / "scan_9"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "completed", "command": "scan",
            "extra": {"k": 1},
        })
        write_run_pin(d, "pinned", "adopted")
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertEqual(meta["project"], "pinned")
        self.assertEqual(meta["project_source"], "adopted")
        self.assertEqual(meta["command"], "scan")
        self.assertEqual(meta["extra"], {"k": 1})

    def test_invalid_source_refused(self):
        from core.run.metadata import write_run_pin
        d = self.root / "out" / "loose" / "scan_9"
        d.mkdir(parents=True)
        with self.assertRaises(ValueError):
            write_run_pin(d, "pinned", "containment")

    def test_updates_freeze_cache(self):
        from core.run.metadata import write_run_pin
        from core.run.pin import resolve_run_pin
        d = self.root / "out" / "loose" / "scan_9"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {"status": "completed"})
        write_run_pin(d, "pinned", "adopted")
        self.assertEqual(resolve_run_pin(d).project, "pinned")


class WitnessAndTamperTest(_PinCase):
    """The out-of-grant ledger witness, tampered markers failing
    closed, and the out-root capture stop."""

    def _sessioned(self):
        sessions.record_session("pinned", pid=os.getpid())
        # The conftest neutralises ambient session resolution for
        # hermeticity; the witness reader resolves ambiently like the
        # real completion path, so give it this test's session.
        patcher = patch.object(sessions, "resolve_session_pid",
                               return_value=os.getpid())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_forged_marker_loses_to_ledger_witness(self):
        from core.project.sessions import ledger_record_start
        from core.run.metadata import _journal_project_dir, _pin_witness_ok
        from core.run.pin import resolve_run_pin
        self._sessioned()
        d = self.root / "out" / "standalone" / "scan_1"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": None,
            "project_source": "none",
        })
        ledger_record_start(d, pid=os.getpid(),
                            pin_project=None, record_pin=True)
        # Hostile child re-pins the standalone run to the victim.
        save_json(d / RUN_METADATA_FILE, {
            "status": "completed", "project": "pinned",
            "project_source": "argv",
            "target_path": str(self.root / "code"),
        })
        pin = resolve_run_pin(d)
        self.assertFalse(_pin_witness_ok(d, pin))
        self.assertIsNone(_journal_project_dir(d))

    def test_agreeing_witness_passes(self):
        from core.project.sessions import ledger_record_start
        from core.run.metadata import _pin_witness_ok
        from core.run.pin import resolve_run_pin
        self._sessioned()
        d = self.root / "out" / "pinned" / "scan_2"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "completed", "project": "pinned",
            "project_source": "session",
        })
        ledger_record_start(d, pid=os.getpid(),
                            pin_project="pinned", record_pin=True)
        self.assertTrue(_pin_witness_ok(d, resolve_run_pin(d)))

    def test_corrupt_marker_fails_closed_for_writers(self):
        from core.run.metadata import _journal_project_dir
        from core.run.pin import legacy_probe_allowed, resolve_run_pin
        d = self.root / "out" / "pinned" / "scan_3"
        d.mkdir(parents=True)
        (d / RUN_METADATA_FILE).write_text("{garbage", encoding="utf-8")
        pin = resolve_run_pin(d)
        self.assertFalse(pin.authoritative)
        self.assertFalse(legacy_probe_allowed(pin))
        self.assertIsNone(_journal_project_dir(d))

    def test_preseries_marker_still_allows_legacy_probe(self):
        from core.run.pin import legacy_probe_allowed, resolve_run_pin
        d = self.root / "out" / "pinned" / "scan_4"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {"status": "completed"})
        pin = resolve_run_pin(d)
        self.assertTrue(legacy_probe_allowed(pin))

    def test_out_root_marker_cannot_capture_runs(self):
        from core.run.pin import resolve_run_pin
        out_root = self.root / "out"
        save_json(out_root / RUN_METADATA_FILE, {
            "status": "running", "project": "pinned",
            "project_source": "argv",
        })
        d = out_root / "scan_5"
        d.mkdir()
        with patch("core.config.RaptorConfig.get_out_dir",
                   return_value=out_root):
            pin = resolve_run_pin(d)
        self.assertNotEqual(pin.project, "pinned")

    def test_write_run_pin_refuses_live_runs_and_odd_sources(self):
        from core.run.metadata import write_run_pin
        d = self.root / "out" / "loose" / "scan_6"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "session_pid": os.getpid(),
        })
        with self.assertRaises(ValueError):
            write_run_pin(d, "pinned", "argv")  # not a rewrite source
        with patch("core.run.metadata._session_alive_for_meta",
                   return_value=True), self.assertRaises(ValueError):
            write_run_pin(d, "pinned", "adopted")  # live run


class ResumeAndTamperTest(_PinCase):
    """Resume laundering, witness restore on deleted marker,
    non-string tamper, bounded reads."""

    def _sessioned(self):
        sessions.record_session("pinned", pid=os.getpid())
        patcher = patch.object(sessions, "resolve_session_pid",
                               return_value=os.getpid())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_resume_refuses_laundered_marker_pin(self):
        from core.run.metadata import resume_run
        self._sessioned()
        self.mgr.create("mallory", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "mallory"))
        d = self.root / "out" / "standalone" / "scan_r"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": None,
            "project_source": "none", "command": "scan",
        })
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project=None, record_pin=True)
        # Hostile child re-pins to mallory and makes the run resumable.
        save_json(d / RUN_METADATA_FILE, {
            "status": "interrupted", "project": "mallory",
            "project_source": "argv", "command": "scan",
        })
        from core.run.pin import _frozen_pins
        _frozen_pins.clear()  # fresh resuming process
        resume_run(d)
        from core.json import load_json
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertIsNone(meta["project"],
                          "resume must restore the witnessed pin, not "
                          "seal the laundered one")

    def test_deleted_marker_pin_restored_from_witness_at_restart(self):
        from core.json import load_json
        from core.run.metadata import start_run
        from core.run.pin import _frozen_pins
        self._sessioned()
        d = self.root / "out" / "pinned" / "scan_dw"
        d.mkdir(parents=True)
        self.mgr.set_active("pinned")
        start_run(d, "scan", target=str(self.root / "code"))
        # Hostile child DELETES the marker; a cross-process re-entrant
        # start must restore the pin from the witness, not re-pin
        # ambiently.
        (d / RUN_METADATA_FILE).unlink()
        _frozen_pins.clear()
        self.mgr.create("ambient2", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "ambient2"))
        self.mgr.set_active("ambient2")
        start_run(d, "scan", target=str(self.root / "code"))
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertEqual(meta["project"], "pinned")

    def test_nonstring_marker_project_is_authoritative_none(self):
        from core.run.pin import resolve_run_pin
        d = self.root / "out" / "loose" / "scan_ns"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "completed", "project": 123,
            "project_source": "argv",
        })
        pin = resolve_run_pin(d)
        self.assertIsNone(pin.project)
        self.assertTrue(pin.authoritative)

    def test_nonstring_target_fails_the_write_gate(self):
        from core.run.pin import pinned_write_target_ok
        d = self.root / "out" / "pinned" / "scan_nt"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "completed", "project": "pinned",
            "project_source": "session", "target_path": ["/x"],
        })
        self.assertFalse(pinned_write_target_ok(d))


class ResumeWitnessLifecycleTest(_PinCase):
    """Resume-path witness semantics: locked restore, cross-session
    lookup via the prior owner's ledger, fresh witness for segment 2."""

    def _sessioned(self, name="pinned"):
        sessions.record_session(name, pid=os.getpid())
        patcher = patch.object(sessions, "resolve_session_pid",
                               return_value=os.getpid())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_cross_session_resume_consults_prior_owner_witness(self):
        from core.json import load_json
        from core.run.metadata import resume_run
        from core.run.pin import _frozen_pins
        self._sessioned()
        self.mgr.create("mallory", str(self.root / "code"),
                        output_dir=str(self.root / "out" / "mallory"))
        d = self.root / "out" / "standalone" / "scan_x"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": None,
            "project_source": "none", "command": "scan",
            "session_pid": os.getpid(),
        })
        # The ORIGINAL owner's ledger carries the witness.
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project=None, record_pin=True)
        # Hostile child re-pins + makes resumable; the RESUMING
        # session is a different pid with no witness of its own.
        save_json(d / RUN_METADATA_FILE, {
            "status": "interrupted", "project": "mallory",
            "project_source": "argv", "command": "scan",
            "session_pid": os.getpid(),
        })
        _frozen_pins.clear()
        other_pid = os.getpid() + 1  # no ledger for this pid
        with patch.object(sessions, "resolve_session_pid",
                          return_value=other_pid):
            resume_run(d)
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertIsNone(meta["project"],
                          "the prior owner's witness must veto the "
                          "laundered marker on a cross-session resume")

    def test_resume_restore_is_a_fresh_locked_rmw(self):
        # The restore must re-read the file, not save a stale
        # snapshot: a field written by a concurrent locked writer
        # after resume's first save must survive the restore.
        from core.json import load_json
        from core.run import metadata as md
        from core.run.pin import _frozen_pins
        self._sessioned()
        d = self.root / "out" / "standalone" / "scan_y"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": None,
            "project_source": "none", "command": "scan",
        })
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project=None, record_pin=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "interrupted", "project": "pinned",
            "project_source": "argv", "command": "scan",
            "sentinel_field": "must-survive",
        })
        _frozen_pins.clear()
        md.resume_run(d)
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertIsNone(meta["project"])
        self.assertEqual(meta.get("sentinel_field"), "must-survive")

    def test_resume_writes_a_segment2_witness(self):
        from core.run.metadata import resume_run
        from core.run.pin import _frozen_pins
        self._sessioned()
        d = self.root / "out" / "pinned" / "scan_z"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "interrupted", "project": "pinned",
            "project_source": "session", "command": "scan",
        })
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project="pinned",
                                     record_pin=True,
                                     pin_source="session")
        _frozen_pins.clear()
        resume_run(d)
        found, project, _src = sessions.ledger_pin_witness(
            d, pid=os.getpid())
        self.assertTrue(found)
        self.assertEqual(project, "pinned")


class OutRootBoundaryTest(_PinCase):
    def test_stray_checklist_at_out_root_is_not_a_project_store(self):
        from core.run.metadata import _journal_project_dir
        out_root = self.root / "out"
        (out_root / "checklist.json").write_text("{}", encoding="utf-8")
        legacy = out_root / "scan_legacy"
        legacy.mkdir()
        with patch("core.config.RaptorConfig.get_out_dir",
                   return_value=out_root):
            self.assertIsNone(_journal_project_dir(legacy))


class WalkBoundaryExactTest(_PinCase):
    def test_planted_subdir_marker_inside_project_dir_loses(self):
        # Inside a project dir the walk previously stopped at the
        # FIRST parent (descendant matching), so the nearest planted
        # marker won — the exact capture the outermost rule kills.
        from core.run.pin import resolve_run_pin
        run = Path(self.mgr.load("pinned").output_dir) / "fuzz_9"
        sub = run / "afl-out"
        sub.mkdir(parents=True)
        save_json(run / RUN_METADATA_FILE, {
            "status": "running", "project": "pinned",
            "project_source": "session",
        })
        save_json(sub / RUN_METADATA_FILE, {
            "status": "running", "project": "attacker",
            "project_source": "argv",
        })
        pin = resolve_run_pin(sub)
        self.assertEqual(pin.project, "pinned")


class FallbackWitnessVetoTest(_PinCase):
    def test_prior_owner_witness_vetoes_but_never_elects(self):
        # A fallback (prior-pid) witness that disagrees with the
        # marker freezes the run PROJECTLESS — a forged session_pid
        # steering the lookup can suppress, never choose a project.
        from core.json import load_json
        from core.run.metadata import resume_run
        from core.run.pin import _frozen_pins
        sessions.record_session("pinned", pid=os.getpid())
        d = self.root / "out" / "standalone" / "scan_v"
        d.mkdir(parents=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "running", "project": None,
            "project_source": "none", "command": "scan",
            "session_pid": os.getpid(),
        })
        sessions.ledger_record_start(d, pid=os.getpid(),
                                     pin_project=None, record_pin=True)
        save_json(d / RUN_METADATA_FILE, {
            "status": "interrupted", "project": "pinned",
            "project_source": "argv", "command": "scan",
            "session_pid": os.getpid(),
        })
        _frozen_pins.clear()
        other = os.getpid() + 1  # resuming session has no own witness
        with patch.object(sessions, "resolve_session_pid",
                          return_value=other):
            resume_run(d)
        meta = load_json(d / RUN_METADATA_FILE)
        self.assertIsNone(meta["project"])
        self.assertEqual(meta["project_source"], "none")

    def test_forged_pid_at_unregistered_ledger_reads_not_found(self):
        # An explicit pid with no registered/verified entry must not
        # read an orphan ledger as authority.
        sessions.record_session("pinned", pid=os.getpid())
        d = self.root / "out" / "standalone" / "scan_w"
        d.mkdir(parents=True)
        ledger = Path(sessions.SESSIONS_DIR) / "999999.run"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text(
            f"pin 100 scan_w attacker:argv {d.resolve()}\n",
            encoding="utf-8")
        found, _p, _s = sessions.ledger_pin_witness(d, pid=999999)
        self.assertFalse(found)
