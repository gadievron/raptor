"""Tests for project and run metadata schema validation."""

import unittest

from core.project.schema import (
    _validate_project as validate_project,
    _validate_run_metadata as validate_run_metadata,
    VALID_RUN_STATUSES,
)


class TestValidateProject(unittest.TestCase):

    def _valid(self):
        # ``target`` here is opaque to the schema validator — it just
        # checks the field is a non-empty string. Relative path keeps
        # the fixture portable and avoids hardcoded host paths.
        return {
            "version": 1, "name": "test", "target": "./target",
            "output_dir": "out/test", "created": "2026-04-06",
        }

    def test_valid(self):
        valid, errors = validate_project(self._valid())
        self.assertTrue(valid)
        self.assertEqual(errors, [])

    def test_missing_name(self):
        d = self._valid()
        del d["name"]
        valid, errors = validate_project(d)
        self.assertFalse(valid)
        self.assertIn("missing required field: name", errors)

    def test_missing_target(self):
        d = self._valid()
        del d["target"]
        valid, errors = validate_project(d)
        self.assertFalse(valid)

    def test_empty_name(self):
        d = self._valid()
        d["name"] = ""
        valid, errors = validate_project(d)
        self.assertFalse(valid)

    def test_version_must_be_int(self):
        d = self._valid()
        d["version"] = "1"
        valid, errors = validate_project(d)
        self.assertFalse(valid)

    def test_optional_fields(self):
        d = self._valid()
        d["description"] = "desc"
        d["notes"] = "notes"
        d["threat_model_path"] = "out/test/threat-model.json"
        d["threat_model_updated"] = "2026-06-05T08:00:00+00:00"
        valid, errors = validate_project(d)
        self.assertTrue(valid)

    def test_threat_model_fields_must_be_strings(self):
        d = self._valid()
        d["threat_model_path"] = 123
        d["threat_model_updated"] = []
        valid, errors = validate_project(d)
        self.assertFalse(valid)
        self.assertIn("threat_model_path must be a string", errors)
        self.assertIn("threat_model_updated must be a string", errors)

    def test_description_must_be_string(self):
        d = self._valid()
        d["description"] = 123
        valid, errors = validate_project(d)
        self.assertFalse(valid)

    def test_not_a_dict(self):
        valid, errors = validate_project("not a dict")
        self.assertFalse(valid)


class TestValidateRunMetadata(unittest.TestCase):

    def _valid(self):
        return {
            "version": 1, "command": "scan",
            "timestamp": "2026-04-06T10:00:00Z", "status": "completed",
        }

    def test_valid(self):
        valid, errors = validate_run_metadata(self._valid())
        self.assertTrue(valid)

    def test_all_statuses_valid(self):
        for status in VALID_RUN_STATUSES:
            d = self._valid()
            d["status"] = status
            valid, _ = validate_run_metadata(d)
            self.assertTrue(valid, f"status '{status}' should be valid")

    def test_invalid_status(self):
        d = self._valid()
        d["status"] = "paused"
        valid, errors = validate_run_metadata(d)
        self.assertFalse(valid)

    def test_missing_command(self):
        d = self._valid()
        del d["command"]
        valid, errors = validate_run_metadata(d)
        self.assertFalse(valid)

    def test_extra_must_be_dict(self):
        d = self._valid()
        d["extra"] = "not a dict"
        valid, errors = validate_run_metadata(d)
        self.assertFalse(valid)

    def test_extra_dict_accepted(self):
        d = self._valid()
        d["extra"] = {"duration_seconds": 45.2, "findings_count": 12}
        valid, errors = validate_run_metadata(d)
        self.assertTrue(valid)

    def test_not_a_dict(self):
        valid, errors = validate_run_metadata([])
        self.assertFalse(valid)


if __name__ == "__main__":
    unittest.main()
