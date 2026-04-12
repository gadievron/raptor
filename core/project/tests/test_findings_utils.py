"""Tests for findings_utils — dedup keys, semantic grouping, bug counting."""

import unittest

from core.project.findings_utils import count_vulns, dedup_key, group_findings, group_key


class TestDedupKey(unittest.TestCase):

    def test_basic(self):
        f = {"file": "a.c", "function": "main", "line": 10}
        self.assertEqual(dedup_key(f), ("a.c", "main", 10))

    def test_missing_fields(self):
        self.assertEqual(dedup_key({}), ("", "", 0))


class TestGroupKey(unittest.TestCase):

    def test_basic(self):
        f = {"file": "a.c", "function": "main", "vuln_type": "buffer_overflow"}
        self.assertEqual(group_key(f), ("a.c", "main", "buffer_overflow"))

    def test_missing_vuln_type(self):
        f = {"file": "a.c", "function": "main", "line": 10}
        self.assertEqual(group_key(f), ("a.c", "main", ""))


class TestGroupFindings(unittest.TestCase):

    def test_toctou_grouped(self):
        """Two TOCTOU findings at different lines in same function = 1 group."""
        findings = [
            {"file": "10_toctou.c", "function": "main", "line": 7, "vuln_type": "race_condition"},
            {"file": "10_toctou.c", "function": "main", "line": 10, "vuln_type": "race_condition"},
        ]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 1)
        key = ("10_toctou.c", "main", "race_condition")
        self.assertEqual(len(groups[key]), 2)

    def test_different_vuln_types_separate(self):
        """Different vuln_types in same function = separate groups."""
        findings = [
            {"file": "a.c", "function": "main", "line": 5, "vuln_type": "buffer_overflow"},
            {"file": "a.c", "function": "main", "line": 10, "vuln_type": "format_string"},
        ]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 2)

    def test_different_functions_separate(self):
        findings = [
            {"file": "a.c", "function": "foo", "line": 5, "vuln_type": "buffer_overflow"},
            {"file": "a.c", "function": "bar", "line": 10, "vuln_type": "buffer_overflow"},
        ]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 2)

    def test_unique_findings_one_per_group(self):
        findings = [
            {"file": "a.c", "function": "main", "line": 5, "vuln_type": "buffer_overflow"},
            {"file": "b.c", "function": "foo", "line": 10, "vuln_type": "format_string"},
        ]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 2)
        for group in groups.values():
            self.assertEqual(len(group), 1)

    def test_empty(self):
        self.assertEqual(group_findings([]), {})


class TestCountVulns(unittest.TestCase):

    def test_no_grouping_needed(self):
        findings = [
            {"file": "a.c", "function": "main", "line": 5, "vuln_type": "buffer_overflow"},
            {"file": "b.c", "function": "foo", "line": 10, "vuln_type": "format_string"},
        ]
        self.assertEqual(count_vulns(findings), 2)

    def test_toctou_counts_as_one(self):
        findings = [
            {"file": "10_toctou.c", "function": "main", "line": 7, "vuln_type": "race_condition"},
            {"file": "10_toctou.c", "function": "main", "line": 10, "vuln_type": "race_condition"},
        ]
        self.assertEqual(count_vulns(findings), 1)

    def test_mixed(self):
        """10 unique vulns + 1 TOCTOU (2 findings) = 10 vulns from 11 findings."""
        findings = [
            {"file": f"{i:02d}.c", "function": "main", "line": 5, "vuln_type": f"type_{i}"}
            for i in range(9)
        ] + [
            {"file": "10_toctou.c", "function": "main", "line": 7, "vuln_type": "race_condition"},
            {"file": "10_toctou.c", "function": "main", "line": 10, "vuln_type": "race_condition"},
        ]
        self.assertEqual(len(findings), 11)
        self.assertEqual(count_vulns(findings), 10)

    def test_empty(self):
        self.assertEqual(count_vulns([]), 0)


if __name__ == "__main__":
    unittest.main()
