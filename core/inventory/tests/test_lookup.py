#!/usr/bin/env python3
"""Tests for function lookup from inventory checklist."""

import unittest
from core.inventory.lookup import lookup_function, normalise_path


CHECKLIST = {
    "files": [
        {
            "path": "src/handler.py",
            "functions": [
                {"name": "setup", "line_start": 5, "line_end": 15,
                 "metadata": {"class_name": None, "visibility": "public"}},
                {"name": "process_request", "line_start": 20, "line_end": 50,
                 "metadata": {"class_name": "Handler", "visibility": "public",
                              "attributes": ["app.route('/api')"]}},
                {"name": "cleanup", "line_start": 55, "line_end": 60,
                 "metadata": {"class_name": "Handler", "visibility": "private"}},
            ],
        },
        {
            "path": "src/utils/helpers.py",
            "functions": [
                {"name": "validate", "line_start": 10, "line_end": 30},
            ],
        },
        {
            "path": "src/legacy.py",
            "functions": [
                # No line_end — tests fuzzy matching
                {"name": "old_handler", "line_start": 1},
                {"name": "another_handler", "line_start": 50},
            ],
        },
    ]
}


class TestNormalisePath(unittest.TestCase):

    def test_relative_unchanged(self):
        self.assertEqual(normalise_path("src/handler.py", "/repo"), "src/handler.py")

    def test_absolute_to_relative(self):
        self.assertEqual(normalise_path("/repo/src/handler.py", "/repo"), "src/handler.py")

    def test_file_uri_stripped(self):
        self.assertEqual(normalise_path("file://src/handler.py", "/repo"), "src/handler.py")

    def test_absolute_file_uri(self):
        self.assertEqual(normalise_path("file:///repo/src/handler.py", "/repo"), "src/handler.py")

    def test_dot_slash_stripped(self):
        self.assertEqual(normalise_path("./src/handler.py", "/repo"), "src/handler.py")


class TestLookupFunction(unittest.TestCase):

    def test_exact_match(self):
        """Line within function range returns that function."""
        result = lookup_function(CHECKLIST, "src/handler.py", 30)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "process_request")

    def test_exact_match_at_start(self):
        """Line at function start."""
        result = lookup_function(CHECKLIST, "src/handler.py", 20)
        self.assertEqual(result["name"], "process_request")

    def test_exact_match_at_end(self):
        """Line at function end."""
        result = lookup_function(CHECKLIST, "src/handler.py", 50)
        self.assertEqual(result["name"], "process_request")

    def test_fuzzy_match_no_line_end(self):
        """No line_end — picks closest function starting before."""
        result = lookup_function(CHECKLIST, "src/legacy.py", 25)
        self.assertEqual(result["name"], "old_handler")

    def test_fuzzy_match_second_function(self):
        """Closer to second function."""
        result = lookup_function(CHECKLIST, "src/legacy.py", 75)
        self.assertEqual(result["name"], "another_handler")

    def test_no_match_before_first_function(self):
        """Line before any function (module-level code)."""
        result = lookup_function(CHECKLIST, "src/handler.py", 1)
        self.assertIsNone(result)

    def test_no_match_gap_between_functions(self):
        """Line between two functions that both have line_end — no match."""
        result = lookup_function(CHECKLIST, "src/handler.py", 17)
        self.assertIsNone(result)

    def test_no_match_after_last_function(self):
        """Line after last function's line_end."""
        result = lookup_function(CHECKLIST, "src/handler.py", 65)
        self.assertIsNone(result)

    def test_no_match_wrong_file(self):
        result = lookup_function(CHECKLIST, "src/nonexistent.py", 10)
        self.assertIsNone(result)

    def test_different_dirs_same_filename(self):
        """src/handler.py != src/utils/helpers.py."""
        result = lookup_function(CHECKLIST, "src/utils/helpers.py", 15)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "validate")

    def test_absolute_path_match(self):
        """Absolute path normalised to match relative checklist path."""
        result = lookup_function(CHECKLIST, "/repo/src/handler.py", 30, repo_root="/repo")
        self.assertEqual(result["name"], "process_request")

    def test_file_uri_match(self):
        result = lookup_function(CHECKLIST, "file://src/handler.py", 30)
        self.assertEqual(result["name"], "process_request")

    def test_metadata_preserved(self):
        """Function dict includes metadata from checklist."""
        result = lookup_function(CHECKLIST, "src/handler.py", 30)
        meta = result.get("metadata", {})
        self.assertEqual(meta["class_name"], "Handler")
        self.assertIn("app.route('/api')", meta["attributes"])

    def test_empty_checklist(self):
        self.assertIsNone(lookup_function({}, "src/handler.py", 10))

    def test_none_checklist(self):
        self.assertIsNone(lookup_function(None, "src/handler.py", 10))

    def test_missing_line(self):
        self.assertIsNone(lookup_function(CHECKLIST, "src/handler.py", 0))

    def test_missing_file_path(self):
        self.assertIsNone(lookup_function(CHECKLIST, "", 10))


class TestMetadataInVulnerabilityContext(unittest.TestCase):
    """Test that metadata flows through VulnerabilityContext to_dict()."""

    def test_metadata_round_trips(self):
        from packages.llm_analysis.agent import VulnerabilityContext
        from pathlib import Path

        finding = {
            "finding_id": "TEST-001",
            "rule_id": "test-rule",
            "file": "src/handler.py",
            "startLine": 30,
            "message": "test",
            "metadata": {
                "class_name": "Handler",
                "visibility": "public",
                "attributes": ["@app.route('/api')"],
            },
        }
        vuln = VulnerabilityContext(finding, Path("/tmp"))
        result = vuln.to_dict()
        self.assertEqual(result["metadata"]["class_name"], "Handler")
        self.assertIn("@app.route('/api')", result["metadata"]["attributes"])

    def test_no_metadata_omitted(self):
        from packages.llm_analysis.agent import VulnerabilityContext
        from pathlib import Path

        finding = {
            "finding_id": "TEST-002",
            "rule_id": "test-rule",
            "file": "src/handler.py",
            "startLine": 30,
            "message": "test",
        }
        vuln = VulnerabilityContext(finding, Path("/tmp"))
        result = vuln.to_dict()
        self.assertNotIn("metadata", result)


if __name__ == "__main__":
    unittest.main()
