"""The project ``sandbox-floor`` setting: registry validation and
run-start consumption.

The setting is the project surface of the untrusted containment-floor
consent chain (per-run ``--sandbox-floor`` flag > this setting >
legacy env var > default-refuse). Pinned here:

* registry validation — the four consentable tier labels round-trip;
  ``none`` is refused with a message naming the real sandbox-off
  surface (a standing bare floor is never a project-consentable
  value); junk is refused; schema validation agrees.
* consumption — ``apply_project_sandbox_floor`` plumbs the label into
  ``core.sandbox`` state with a banner (trust-marker precedent), only
  when the run's target matches the project's target (one-target
  rule), and stays silent-but-applied when a per-run flag is present
  (the sandbox side banners disagreements).
* fail-closed — an invalid on-disk label is ignored loudly, never
  guessed.

Hermetic: temp projects dir via patched ``PROJECTS_DIR``; sandbox
module state snapshotted per test.
"""

import argparse
import contextlib
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.project import (
    SETTINGS_REGISTRY,
    VALID_SANDBOX_FLOORS,
    ProjectManager,
)
from core.project.schema import _validate_project
from core.project.trust import apply_project_sandbox_floor
from core.sandbox import state as _sandbox_state


def _ns(**kw):
    base = {"sandbox_floor": None}
    base.update(kw)
    return argparse.Namespace(**base)


class SandboxFloorFixture(unittest.TestCase):
    """Temp projects dir with one active project + sandbox state guard.

    The sandbox-side plumbing (``set_project_sandbox_floor``) accepts
    the Linux tier vocabulary and refuses it on macOS, so the
    consumption tests pin the LINUX behaviour through the cli
    module's ``sys`` seam (the established SimpleNamespace idiom) —
    they bind identically on a macOS runner instead of failing on the
    real platform check. The darwin fail-closed contract has its own
    emulated test below.
    """

    def setUp(self):
        import types as _types

        import core.sandbox.cli as _sandbox_cli
        cli_sys = patch.object(
            _sandbox_cli, "sys", _types.SimpleNamespace(platform="linux"))
        cli_sys.start()
        self.addCleanup(cli_sys.stop)
        self._sandbox_cli = _sandbox_cli
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        target = root / "code"
        target.mkdir()
        self.target = target
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("p", str(target), output_dir=str(root / "out"))
        self.mgr.set_active("p")
        patcher = patch("core.project.project.PROJECTS_DIR",
                        self.projects_dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Guard the sandbox consent slots — these tests write them.
        saved_cli = _sandbox_state._cli_sandbox_floor
        saved_proj = _sandbox_state._project_sandbox_floor

        def _restore():
            _sandbox_state._cli_sandbox_floor = saved_cli
            _sandbox_state._project_sandbox_floor = saved_proj
        self.addCleanup(_restore)
        _sandbox_state._cli_sandbox_floor = None
        _sandbox_state._project_sandbox_floor = None

    def _apply(self, ns=None, target=None, banner=True):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            applied = apply_project_sandbox_floor(
                ns if ns is not None else _ns(),
                banner=banner,
                target_path=target or self.target)
        return applied, out.getvalue()

    def _set_floor(self, label):
        self.mgr.update_setting("p", "sandbox-floor", label)


class TestRegistryValidation(SandboxFloorFixture):
    def test_registry_lists_the_key(self):
        self.assertIn("sandbox-floor", SETTINGS_REGISTRY)

    def test_valid_labels_round_trip(self):
        proj = self.mgr.load("p")
        for label in VALID_SANDBOX_FLOORS:
            proj.set_setting("sandbox-floor", label)
            self.assertEqual(proj.get_setting("sandbox-floor"), label)
        self.assertTrue(proj.unset_setting("sandbox-floor"))
        self.assertIsNone(proj.get_setting("sandbox-floor"))
        self.assertFalse(proj.unset_setting("sandbox-floor"))

    def test_none_is_refused_naming_the_real_surface(self):
        """Never-BARE through the project surface: a standing bare
        floor cannot even be STORED."""
        proj = self.mgr.load("p")
        with self.assertRaises(ValueError) as cm:
            proj.set_setting("sandbox-floor", "none")
        self.assertIn("--sandbox none", str(cm.exception))
        self.assertIn("never runs bare by consent", str(cm.exception))

    def test_junk_is_refused_listing_valid_values(self):
        proj = self.mgr.load("p")
        with self.assertRaises(ValueError) as cm:
            proj.set_setting("sandbox-floor", "seatbelt")
        for label in VALID_SANDBOX_FLOORS:
            self.assertIn(label, str(cm.exception))

    def test_settings_view_includes_the_key(self):
        proj = self.mgr.load("p")
        self.assertIn("sandbox-floor", proj.settings_view())
        proj.set_setting("sandbox-floor", "landlock")
        self.assertEqual(proj.settings_view()["sandbox-floor"],
                         "landlock")

    def test_schema_accepts_valid_and_rejects_invalid(self):
        base = {"version": 4, "name": "p", "target": "/t",
                "output_dir": "/o"}
        for label in VALID_SANDBOX_FLOORS:
            ok, errs = _validate_project(
                {**base, "settings": {"sandbox-floor": label}})
            self.assertTrue(ok, errs)
        for bad in ("none", "seatbelt", "", 3):
            ok, errs = _validate_project(
                {**base, "settings": {"sandbox-floor": bad}})
            self.assertFalse(ok, bad)
            self.assertTrue(any("sandbox-floor" in e for e in errs))


class TestConsumption(SandboxFloorFixture):
    def test_setting_applied_and_bannered(self):
        self._set_floor("landlock")
        applied, out = self._apply()
        self.assertEqual(applied, "landlock")
        self.assertEqual(_sandbox_state._project_sandbox_floor,
                         "landlock")
        self.assertIn("project sandbox-floor: landlock", out)
        self.assertIn("--sandbox-floor overrides", out)

    def test_no_setting_is_a_noop(self):
        applied, out = self._apply()
        self.assertIsNone(applied)
        self.assertIsNone(_sandbox_state._project_sandbox_floor)
        self.assertEqual(out, "")

    def test_one_target_rule_drops_with_notice(self):
        """Floor consent is asserted for ONE target: a run against a
        different tree ignores the setting, loudly."""
        self._set_floor("landlock")
        other = Path(self._tmp.name) / "elsewhere"
        other.mkdir()
        applied, out = self._apply(target=other)
        self.assertIsNone(applied)
        self.assertIsNone(_sandbox_state._project_sandbox_floor)
        self.assertIn("IGNORED", out)

    def test_per_run_flag_suppresses_the_banner_not_the_state(self):
        """With a per-run flag present the project value still lands
        in state (context resolves precedence and banners the
        disagreement); the entry banner stays quiet to avoid claiming
        a consent the flag may override."""
        self._set_floor("mountless-ns")
        applied, out = self._apply(_ns(sandbox_floor="landlock"))
        self.assertEqual(applied, "mountless-ns")
        self.assertEqual(_sandbox_state._project_sandbox_floor,
                         "mountless-ns")
        self.assertNotIn("project sandbox-floor:", out)

    def test_invalid_on_disk_label_fails_closed(self):
        """Schema drift / hand-edited project file: never guess a
        consent — the default floor stays in force."""
        proj = self.mgr.load("p")
        proj.settings["sandbox-floor"] = "bogus-tier"
        # Bypass set_setting validation deliberately (hand-edit shape).
        self.mgr._save(proj)
        applied, _out = self._apply()
        self.assertIsNone(applied)
        self.assertIsNone(_sandbox_state._project_sandbox_floor)

    def test_operator_disable_skips_the_consent(self):
        """--sandbox none / --no-sandbox is globally authoritative: a
        floor consent is moot under it, and the banner must not claim
        a consent the disable overrides."""
        self._set_floor("landlock")
        _sandbox_state._cli_sandbox_disabled = True
        try:
            applied, out = self._apply()
        finally:
            _sandbox_state._cli_sandbox_disabled = False
        self.assertIsNone(applied)
        self.assertIsNone(_sandbox_state._project_sandbox_floor)
        self.assertEqual(out, "")

    def test_darwin_consumption_fails_closed(self):
        """A stored Linux tier consumed on macOS is IGNORED loudly,
        never guessed and never a crash: the setter refuses the label
        (cross-platform tier comparability is refused, not fudged),
        the consumption catches it, warns, and the run proceeds at
        the fail-closed default floor with no banner claiming a
        consent that did not land."""
        import types as _types
        self._set_floor("landlock")
        with patch.object(self._sandbox_cli, "sys",
                          _types.SimpleNamespace(platform="darwin")):
            with self.assertLogs("core.project.trust",
                                 level="WARNING") as logs:
                applied, out = self._apply()
        self.assertIsNone(applied)
        self.assertIsNone(_sandbox_state._project_sandbox_floor)
        self.assertNotIn("project sandbox-floor:", out)
        self.assertTrue(any("not applied" in m for m in logs.output),
                        logs.output)

    def test_no_active_project_is_a_noop(self):
        self.mgr.set_active(None)
        applied, out = self._apply()
        self.assertIsNone(applied)
        self.assertIsNone(_sandbox_state._project_sandbox_floor)
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
