"""CLI surface for trust markers and settings — hermetic smoke tests.

Drives ``core.project.cli.main`` with a temp projects dir (patched
``PROJECTS_DIR``) and captured stdout/stderr. No network, no external
binaries.
"""

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.cli import main
from core.project.project import ProjectManager


class TrustSettingsCliTest(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.target = root / "code"
        self.target.mkdir()
        self.out_dir = root / "out"
        mgr = ProjectManager(projects_dir=self.projects_dir)
        mgr.create("myapp", str(self.target),
                   output_dir=str(self.out_dir / "myapp"))
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

    def _project_json(self):
        return json.loads(
            (self.projects_dir / "myapp.json").read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # trust / untrust
    # ------------------------------------------------------------------

    def test_trust_list_shows_markers_and_binaries_count(self):
        code, out, _ = self._run("trust")
        self.assertEqual(code, 0)
        for marker in ("config", "build", "dynamic"):
            self.assertIn(marker, out)
        self.assertIn("not set", out)
        self.assertIn("binaries 0 persisted", out)

    def test_trust_set_persists_timestamp(self):
        code, out, _ = self._run("trust", "build")
        self.assertEqual(code, 0)
        self.assertIn("build", out)
        data = self._project_json()
        self.assertIn("build", data["trust"])
        self.assertRegex(data["trust"]["build"], r"^\d{4}-\d{2}-\d{2}T")
        # And the list view reflects it.
        _, out, _ = self._run("trust")
        self.assertIn("set " + data["trust"]["build"], out)

    def test_trust_build_prints_independence_note(self):
        _, out, _ = self._run("trust", "build")
        self.assertIn("does not imply config", out)
        # ...and really does not set config.
        self.assertNotIn("config", self._project_json()["trust"])

    def test_trust_unknown_marker_errors_with_valid_list(self):
        code, out, err = self._run("trust", "bogus")
        self.assertEqual(code, 1)
        combined = out + err
        self.assertIn("config", combined)
        self.assertIn("build", combined)
        self.assertIn("dynamic", combined)
        self.assertEqual(self._project_json()["trust"], {})

    def test_untrust_removes_marker(self):
        self._run("trust", "dynamic")
        code, out, _ = self._run("untrust", "dynamic")
        self.assertEqual(code, 0)
        self.assertIn("removed", out)
        self.assertEqual(self._project_json()["trust"], {})

    def test_untrust_not_set_is_not_an_error(self):
        code, out, _ = self._run("untrust", "config")
        self.assertEqual(code, 0)
        self.assertIn("was not set", out)

    def test_untrust_unknown_marker_errors(self):
        code, _, _ = self._run("untrust", "everything")
        self.assertEqual(code, 1)

    def test_trust_named_project_positional(self):
        code, out, _ = self._run("trust", "myapp")
        self.assertEqual(code, 0)
        self.assertIn("myapp", out)
        self.assertIn("binaries 0 persisted", out)

    # ------------------------------------------------------------------
    # set / unset / get
    # ------------------------------------------------------------------

    def test_set_list_when_no_args(self):
        code, out, _ = self._run("set")
        self.assertEqual(code, 0)
        for key in ("description", "notes", "threat-model",
                    "target-kind", "build-command"):
            self.assertIn(key, out)
        self.assertIn("(unset)", out)

    def test_set_and_get_round_trip(self):
        code, _, _ = self._run("set", "target-kind", "library")
        self.assertEqual(code, 0)
        code, out, _ = self._run("get", "target-kind")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "library")
        self.assertEqual(self._project_json()["settings"]["target-kind"],
                         "library")

    def test_get_unset_exits_1_with_empty_stdout(self):
        code, out, _ = self._run("get", "build-command")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_get_unknown_key_exits_1(self):
        code, _, _ = self._run("get", "api-key")
        self.assertEqual(code, 1)

    def test_set_unknown_key_rejected_listing_valid(self):
        code, out, err = self._run("set", "api-key", "hunter2")
        self.assertEqual(code, 1)
        self.assertIn("build-command", out + err)
        self.assertNotIn("api-key", self._project_json()["settings"])

    def test_set_identity_field_rejected(self):
        for key in ("name", "target", "output_dir", "created"):
            code, _, _ = self._run("set", key, "x")
            self.assertEqual(code, 1, key)

    def test_set_without_value_errors(self):
        code, _, err = self._run("set", "target-kind")
        self.assertEqual(code, 1)
        self.assertIn("requires a value", err)

    def test_build_command_language_slots(self):
        self._run("set", "build-command", "make")
        self._run("set", "build-command.cpp", "cmake --build build")
        code, out, _ = self._run("get", "build-command.cpp")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "cmake --build build")
        code, out, _ = self._run("get", "build-command")
        self.assertEqual(out.strip(), "make")
        self._run("unset", "build-command.cpp")
        code, _, _ = self._run("get", "build-command.cpp")
        self.assertEqual(code, 1)

    def test_unset_round_trip(self):
        self._run("set", "notes", "reviewed")
        code, out, _ = self._run("unset", "notes")
        self.assertEqual(code, 0)
        self.assertIn("Unset", out)
        code, _, _ = self._run("get", "notes")
        self.assertEqual(code, 1)

    def test_description_maps_to_field(self):
        self._run("set", "description", "a daemon")
        self.assertEqual(self._project_json()["description"], "a daemon")
        self.assertNotIn("description",
                         self._project_json()["settings"])

    # ------------------------------------------------------------------
    # status blocks
    # ------------------------------------------------------------------

    def test_status_shows_trust_and_settings_blocks(self):
        code, out, _ = self._run("status")
        self.assertEqual(code, 0)
        self.assertIn("Trust: none", out)
        self.assertIn("Settings: (defaults)", out)
        self._run("trust", "build")
        self._run("set", "target-kind", "hybrid")
        _, out, _ = self._run("status")
        self.assertIn("Trust: build (", out)
        self.assertIn("target-kind=hybrid", out)

    # ------------------------------------------------------------------
    # no active project
    # ------------------------------------------------------------------

    def test_trust_without_project_exits_1(self):
        mgr = ProjectManager(projects_dir=self.projects_dir)
        mgr.set_active(None)
        code, _, err = self._run("trust")
        self.assertEqual(code, 1)
        self.assertIn("No project", err)


if __name__ == "__main__":
    unittest.main()
