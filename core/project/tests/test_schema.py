"""Tests for project and run metadata schema validation."""

import unittest

from core.project.schema import validate_project, validate_run_metadata, VALID_RUN_STATUSES


class TestValidateProject(unittest.TestCase):

    def _valid(self):
        return {
            "version": 1, "name": "test", "target": "/tmp/code",
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
        valid, errors = validate_project(d)
        self.assertTrue(valid)

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
