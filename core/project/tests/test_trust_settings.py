"""Schema-v4 trust markers and settings — model + schema validation.

Hermetic: no network, no external binaries, no home-dir writes.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.project import (
    _PROJECT_SCHEMA_VERSION,
    SETTINGS_REGISTRY,
    VALID_TARGET_KINDS,
    VALID_TRUST_MARKERS,
    Project,
    split_setting_key,
)
from core.project.schema import _validate_project as validate_project


def _project(**kw):
    base = {"name": "t", "target": "./target", "output_dir": "out/t"}
    base.update(kw)
    return Project(**base)


class TestTrustMarkers(unittest.TestCase):

    def test_valid_markers_exact(self):
        self.assertEqual(VALID_TRUST_MARKERS, ("config", "build", "dynamic"))

    def test_set_trust_stamps_timestamp(self):
        p = _project()
        ts = p.set_trust("build")
        self.assertEqual(p.trust["build"], ts)
        # ISO-8601 shape (starts with a date)
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T")

    def test_unknown_marker_rejected_with_valid_list(self):
        p = _project()
        with self.assertRaises(ValueError) as ctx:
            p.set_trust("root")
        msg = str(ctx.exception)
        for marker in VALID_TRUST_MARKERS:
            self.assertIn(marker, msg)

    def test_clear_trust(self):
        p = _project()
        p.set_trust("dynamic")
        self.assertTrue(p.clear_trust("dynamic"))
        self.assertNotIn("dynamic", p.trust)
        self.assertFalse(p.clear_trust("dynamic"))

    def test_clear_unknown_marker_rejected(self):
        p = _project()
        with self.assertRaises(ValueError):
            p.clear_trust("everything")

    def test_build_marker_does_not_imply_config(self):
        """Project-layer pin of the traced-build / pack-config trust
        independence: setting ``build`` must not set ``config``."""
        p = _project()
        p.set_trust("build")
        self.assertIn("build", p.trust)
        self.assertNotIn("config", p.trust)


class TestSettingsRegistry(unittest.TestCase):

    def test_unknown_key_rejected_with_valid_list(self):
        p = _project()
        with self.assertRaises(ValueError) as ctx:
            p.set_setting("api-key", "x")
        msg = str(ctx.exception)
        for key in SETTINGS_REGISTRY:
            self.assertIn(key, msg)

    def test_identity_fields_not_settable(self):
        p = _project()
        for key in ("name", "target", "output_dir", "created"):
            with self.assertRaises(ValueError):
                p.set_setting(key, "x")

    def test_description_and_notes_map_to_fields(self):
        p = _project()
        p.set_setting("description", "a daemon")
        p.set_setting("notes", "reviewed auth")
        self.assertEqual(p.description, "a daemon")
        self.assertEqual(p.notes, "reviewed auth")
        self.assertEqual(p.get_setting("description"), "a daemon")
        # Mapped keys don't leak into the persisted settings dict.
        self.assertNotIn("description", p.settings)
        self.assertNotIn("notes", p.settings)

    def test_target_kind_enum(self):
        p = _project()
        for kind in VALID_TARGET_KINDS:
            p.set_setting("target-kind", kind)
            self.assertEqual(p.get_setting("target-kind"), kind)
        with self.assertRaises(ValueError):
            p.set_setting("target-kind", "kernel")

    def test_build_command_default_slot(self):
        p = _project()
        p.set_setting("build-command", "make -j4")
        self.assertEqual(p.settings["build-command"], {"default": "make -j4"})
        self.assertEqual(p.get_setting("build-command"), "make -j4")

    def test_build_command_per_language(self):
        p = _project()
        p.set_setting("build-command", "make")
        p.set_setting("build-command.cpp", "cmake --build build")
        self.assertEqual(p.get_setting("build-command.cpp"),
                         "cmake --build build")
        self.assertEqual(p.get_setting("build-command"), "make")
        self.assertTrue(p.unset_setting("build-command.cpp"))
        self.assertIsNone(p.get_setting("build-command.cpp"))
        # Default slot survives per-language unset.
        self.assertEqual(p.get_setting("build-command"), "make")

    def test_build_command_bad_lang_slot(self):
        p = _project()
        with self.assertRaises(ValueError):
            p.set_setting("build-command.c;rm -rf /", "make")

    def test_empty_value_rejected(self):
        p = _project()
        with self.assertRaises(ValueError):
            p.set_setting("notes", "   ")

    def test_threat_model_requires_existing_path(self):
        p = _project()
        with self.assertRaises(ValueError):
            p.set_setting("threat-model", "/nonexistent/tm.json")
        with TemporaryDirectory() as d:
            tm = Path(d) / "tm.json"
            tm.write_text("{}", encoding="utf-8")
            p.set_setting("threat-model", str(tm))
            self.assertEqual(p.threat_model_path, str(tm.resolve()))
            self.assertTrue(p.threat_model_updated)
            self.assertTrue(p.unset_setting("threat-model"))
            self.assertEqual(p.threat_model_path, "")
            self.assertEqual(p.threat_model_updated, "")

    def test_unset_unknown_key_rejected(self):
        p = _project()
        with self.assertRaises(ValueError):
            p.unset_setting("nope")

    def test_get_unknown_key_rejected(self):
        p = _project()
        with self.assertRaises(ValueError):
            p.get_setting("nope")

    def test_split_setting_key(self):
        self.assertEqual(split_setting_key("notes"), ("notes", None))
        self.assertEqual(split_setting_key("build-command.rust"),
                         ("build-command", "rust"))
        with self.assertRaises(ValueError):
            split_setting_key("build.command")


class TestSchemaRoundTrip(unittest.TestCase):

    def test_v3_file_loads_with_defaults_and_upgrades_on_write(self):
        v3 = {
            "version": 3,
            "name": "legacy",
            "target": "./target",
            "output_dir": "out/legacy",
            "created": "2026-01-01T00:00:00+00:00",
            "binaries": ["/tmp/bin"],
            "threat_model_path": "",
            "threat_model_updated": "",
        }
        p = Project.from_dict(v3)
        self.assertEqual(p.trust, {})
        self.assertEqual(p.settings, {})
        out = p.to_dict()
        self.assertEqual(out["version"], _PROJECT_SCHEMA_VERSION)
        self.assertEqual(out["trust"], {})
        self.assertEqual(out["settings"], {})
        # Pre-existing fields survive the upgrade.
        self.assertEqual(out["binaries"], ["/tmp/bin"])

    def test_v4_round_trip_preserves_trust_and_settings(self):
        p = _project()
        p.set_trust("build")
        p.set_trust("dynamic")
        p.set_setting("target-kind", "hybrid")
        p.set_setting("build-command", "make")
        p.set_setting("build-command.go", "go build ./...")
        p2 = Project.from_dict(p.to_dict())
        self.assertEqual(p2.trust, p.trust)
        self.assertEqual(p2.settings, p.settings)
        self.assertEqual(p2.version, _PROJECT_SCHEMA_VERSION)

    def test_to_dict_copies_are_independent(self):
        p = _project()
        p.set_setting("build-command", "make")
        d = p.to_dict()
        d["settings"]["build-command"]["default"] = "evil"
        d["trust"]["config"] = "forged"
        self.assertEqual(p.get_setting("build-command"), "make")
        self.assertNotIn("config", p.trust)

    def test_lenient_load_drops_invalid_entries(self):
        p = Project.from_dict({
            "version": 4, "name": "x", "target": "./t",
            "output_dir": "out/x",
            "trust": {"config": "2026-01-01T00:00:00+00:00",
                      "root": "2026-01-01T00:00:00+00:00",
                      "build": 123},
            "settings": {"target-kind": "kernel",
                         "build-command": {"default": "make", "bad;lang": "x"},
                         "api-key": "hunter2"},
        })
        self.assertEqual(p.trust, {"config": "2026-01-01T00:00:00+00:00"})
        self.assertEqual(p.settings, {"build-command": {"default": "make"}})

    def test_legacy_string_build_command_upgrades_to_default_slot(self):
        p = Project.from_dict({
            "version": 4, "name": "x", "target": "./t",
            "output_dir": "out/x",
            "settings": {"build-command": "make"},
        })
        self.assertEqual(p.get_setting("build-command"), "make")


class TestSchemaValidator(unittest.TestCase):

    def _valid(self):
        return {
            "version": 4, "name": "t", "target": "./target",
            "output_dir": "out/t", "created": "2026-01-01",
        }

    def test_trust_and_settings_accepted(self):
        d = self._valid()
        d["trust"] = {"config": "2026-01-01T00:00:00+00:00"}
        d["settings"] = {"target-kind": "library",
                         "build-command": {"default": "make"}}
        valid, errors = validate_project(d)
        self.assertTrue(valid, errors)

    def test_trust_must_be_dict(self):
        d = self._valid()
        d["trust"] = ["config"]
        valid, errors = validate_project(d)
        self.assertFalse(valid)
        self.assertIn("trust must be a dict", errors)

    def test_unknown_trust_marker_flagged(self):
        d = self._valid()
        d["trust"] = {"root": "2026-01-01T00:00:00+00:00"}
        valid, errors = validate_project(d)
        self.assertFalse(valid)
        self.assertTrue(any("root" in e for e in errors))

    def test_trust_timestamp_must_be_string(self):
        d = self._valid()
        d["trust"] = {"config": None}
        valid, _errors = validate_project(d)
        self.assertFalse(valid)

    def test_unknown_settings_key_flagged(self):
        d = self._valid()
        d["settings"] = {"api-key": "x"}
        valid, errors = validate_project(d)
        self.assertFalse(valid)
        self.assertTrue(any("api-key" in e for e in errors))

    def test_bad_target_kind_flagged(self):
        d = self._valid()
        d["settings"] = {"target-kind": "kernel"}
        valid, _errors = validate_project(d)
        self.assertFalse(valid)

    def test_bad_build_command_flagged(self):
        d = self._valid()
        d["settings"] = {"build-command": {"cpp": ""}}
        valid, _errors = validate_project(d)
        self.assertFalse(valid)


if __name__ == "__main__":
    unittest.main()
