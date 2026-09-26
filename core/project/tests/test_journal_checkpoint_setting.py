"""The project ``journal-checkpoint`` setting: registry validation
and run-start consumption.

Plain on/off configuration (not a trust grant — the automatic
checkpoint tiers are spend-safe by the compactor's loss contract
either way). Pinned here:

* registry validation — ``on``/``off`` round-trip; junk is refused
  listing the valid values; schema validation agrees.
* the reader (``active_project_journal_checkpoint``) — resolves the
  RUN PIN's project (a mid-session /project switch never moves an
  in-flight run's configuration); pinned-to-none is authoritative;
  no setting is ``None``.
* the resolver (``core.audit.pipeline._resolve_journal_checkpoint``)
  — explicit per-run choice wins in BOTH directions; else the
  project setting (only ``off`` disables); else default ON; a
  hand-edited bogus label fails toward the default.

Hermetic: temp projects dir via patched ``PROJECTS_DIR``; run pins
are marker files in per-test temp run dirs.
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.audit.pipeline import AuditPipelineOpts, _resolve_journal_checkpoint
from core.project.project import (
    SETTINGS_REGISTRY,
    VALID_JOURNAL_CHECKPOINT,
    ProjectManager,
)
from core.project.schema import _validate_project
from core.project.trust import active_project_journal_checkpoint


class JournalCheckpointSettingFixture(unittest.TestCase):
    """Temp projects dir with one active project."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.root = root
        self.projects_dir = root / "projects"
        target = root / "code"
        target.mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("p", str(target), output_dir=str(root / "out"))
        self.mgr.set_active("p")
        patcher = patch("core.project.project.PROJECTS_DIR",
                        self.projects_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _set(self, label):
        self.mgr.update_setting("p", "journal-checkpoint", label)

    def _pinned_run_dir(self, name: str, project="p") -> Path:
        """A run dir carrying a project pin marker, as start_run
        writes it — the reader resolves the pin, never the ambient
        active project, when a run dir is in hand."""
        run_dir = self.root / name
        run_dir.mkdir()
        (run_dir / ".raptor-run.json").write_text(json.dumps({
            "command": "audit",
            "status": "completed",
            "project": project,
            "project_source": "argv",
        }))
        return run_dir


class TestRegistryValidation(JournalCheckpointSettingFixture):
    def test_registry_lists_the_key(self):
        self.assertIn("journal-checkpoint", SETTINGS_REGISTRY)

    def test_valid_labels_round_trip(self):
        proj = self.mgr.load("p")
        for label in VALID_JOURNAL_CHECKPOINT:
            proj.set_setting("journal-checkpoint", label)
            self.assertEqual(
                proj.get_setting("journal-checkpoint"), label)
        self.assertTrue(proj.unset_setting("journal-checkpoint"))
        self.assertIsNone(proj.get_setting("journal-checkpoint"))
        self.assertFalse(proj.unset_setting("journal-checkpoint"))

    def test_junk_is_refused_listing_valid_values(self):
        proj = self.mgr.load("p")
        for bad in ("true", "enabled", "1"):
            with self.assertRaises(ValueError) as cm:
                proj.set_setting("journal-checkpoint", bad)
            for label in VALID_JOURNAL_CHECKPOINT:
                self.assertIn(label, str(cm.exception))
        # Empty values are refused by the shared non-empty guard
        # before the per-key vocabulary check.
        with self.assertRaises(ValueError):
            proj.set_setting("journal-checkpoint", "")

    def test_settings_view_includes_the_key(self):
        proj = self.mgr.load("p")
        self.assertIn("journal-checkpoint", proj.settings_view())
        proj.set_setting("journal-checkpoint", "off")
        self.assertEqual(
            proj.settings_view()["journal-checkpoint"], "off")

    def test_schema_accepts_valid_and_rejects_invalid(self):
        base = {"version": 4, "name": "p", "target": "/t",
                "output_dir": "/o"}
        for label in VALID_JOURNAL_CHECKPOINT:
            ok, errs = _validate_project(
                {**base, "settings": {"journal-checkpoint": label}})
            self.assertTrue(ok, errs)
        for bad in ("true", "", 1, None):
            ok, errs = _validate_project(
                {**base, "settings": {"journal-checkpoint": bad}})
            self.assertFalse(ok, bad)
            self.assertTrue(
                any("journal-checkpoint" in e for e in errs))


class TestReader(JournalCheckpointSettingFixture):
    def test_pinned_run_reads_the_setting(self):
        self._set("off")
        run_dir = self._pinned_run_dir("run-a")
        self.assertEqual(
            active_project_journal_checkpoint(run_dir=run_dir), "off")

    def test_no_setting_is_none(self):
        run_dir = self._pinned_run_dir("run-b")
        self.assertIsNone(
            active_project_journal_checkpoint(run_dir=run_dir))

    def test_pinned_to_none_ignores_active_project(self):
        # Bound-to-none is authoritative: an explicitly projectless
        # run never inherits the ambient project's setting.
        self._set("off")
        run_dir = self._pinned_run_dir("run-c", project=None)
        self.assertIsNone(
            active_project_journal_checkpoint(run_dir=run_dir))

    def test_ambient_active_project_when_no_run_dir(self):
        self._set("on")
        self.assertEqual(active_project_journal_checkpoint(), "on")


class TestResolver(JournalCheckpointSettingFixture):
    def _opts(self, run_name: str, explicit=None, project="p"):
        return AuditPipelineOpts(
            out_dir=self._pinned_run_dir(run_name, project=project),
            journal_checkpoint=explicit,
        )

    def test_explicit_off_wins_over_project_on(self):
        self._set("on")
        self.assertFalse(_resolve_journal_checkpoint(
            self._opts("run-a", explicit=False)))

    def test_explicit_on_wins_over_project_off(self):
        self._set("off")
        self.assertTrue(_resolve_journal_checkpoint(
            self._opts("run-b", explicit=True)))

    def test_project_off_disables_with_notice(self):
        self._set("off")
        with self.assertLogs("core.audit.pipeline",
                             level="INFO") as logs:
            resolved = _resolve_journal_checkpoint(self._opts("run-c"))
        self.assertFalse(resolved)
        self.assertTrue(
            any("disabled by the project" in m for m in logs.output),
            logs.output)

    def test_project_on_keeps_default(self):
        self._set("on")
        self.assertTrue(_resolve_journal_checkpoint(self._opts("run-d")))

    def test_no_project_defaults_on(self):
        self.assertTrue(_resolve_journal_checkpoint(
            self._opts("run-e", project=None)))

    def test_bogus_on_disk_label_fails_toward_default(self):
        # Hand-edited project file: never guess — only the exact
        # ``off`` label disables, anything else keeps the default ON.
        proj = self.mgr.load("p")
        proj.settings["journal-checkpoint"] = "sometimes"
        self.mgr._save(proj)
        self.assertTrue(_resolve_journal_checkpoint(self._opts("run-f")))

    def test_orchestrator_config_default_is_on(self):
        from core.audit.orchestrator import OrchestratorConfig
        config = OrchestratorConfig(
            target_path=self.root / "code", out_dir=self.root / "out")
        self.assertTrue(config.journal_checkpoint)


if __name__ == "__main__":
    unittest.main()
