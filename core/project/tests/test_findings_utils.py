"""Tests for findings_utils — dedup keys, semantic grouping, bug counting."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.findings_utils import (
    count_vulns,
    dedup_key,
    group_findings,
    group_key,
    load_sca_findings_from_dir,
    merge_sca_findings,
)


def _sca_row(finding_id, name, *, severity="high", run_tag=""):
    """A minimal SCA finding row in the canonical shape SCA writes."""
    return {
        "id": finding_id,
        "finding_id": finding_id,
        "vuln_type": "sca:supply_chain:slopsquat_suspect",
        "tool": "sca",
        "file": "package.json",
        "function": name,
        "line": 0,
        "severity": severity,
        "title": f"Slopsquat suspect: {name}{run_tag}",
        "sca": {"kind": "slopsquat_suspect", "ecosystem": "npm", "name": name},
    }


def _write_sca_findings(run_dir: Path, rows):
    sca_dir = run_dir / "sca"
    sca_dir.mkdir(parents=True, exist_ok=True)
    (sca_dir / "findings.json").write_text(json.dumps(rows), encoding="utf-8")


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


class TestLoadScaFindings(unittest.TestCase):

    def test_reads_sca_subdir(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca_findings(run_dir, [_sca_row("SCA-1", "lodahs")])
            out = load_sca_findings_from_dir(run_dir)
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["function"], "lodahs")

    def test_absent_subdir_returns_empty(self):
        with TemporaryDirectory() as d:
            # No sca/ subdir at all.
            self.assertEqual(load_sca_findings_from_dir(Path(d)), [])

    def test_does_not_read_top_level_findings(self):
        """The SCA loader must look ONLY in sca/, not the top-level
        findings.json (that's load_findings_from_dir's job)."""
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            (run_dir / "findings.json").write_text(
                json.dumps([{"id": "CODE-1", "file": "a.c"}]), encoding="utf-8")
            self.assertEqual(load_sca_findings_from_dir(run_dir), [])


class TestMergeScaFindings(unittest.TestCase):

    def test_dedup_latest_run_wins(self):
        with TemporaryDirectory() as d1, TemporaryDirectory() as d2:
            r1, r2 = Path(d1), Path(d2)
            _write_sca_findings(r1, [_sca_row("SCA-1", "lodahs", run_tag=" (run1)")])
            _write_sca_findings(r2, [_sca_row("SCA-1", "lodahs", run_tag=" (run2)")])
            # run_dirs ordered: later overrides earlier.
            merged = merge_sca_findings([r1, r2])
            self.assertEqual(len(merged), 1)
            self.assertIn("(run2)", merged[0]["title"])

    def test_distinct_ids_kept(self):
        with TemporaryDirectory() as d1, TemporaryDirectory() as d2:
            r1, r2 = Path(d1), Path(d2)
            _write_sca_findings(r1, [_sca_row("SCA-1", "lodahs")])
            _write_sca_findings(r2, [_sca_row("SCA-2", "expresss")])
            merged = merge_sca_findings([r1, r2])
            self.assertEqual(len(merged), 2)

    def test_empty_when_no_sca(self):
        with TemporaryDirectory() as d:
            self.assertEqual(merge_sca_findings([Path(d)]), [])

    def test_idless_distinct_findings_same_package_not_collapsed(self):
        """Regression: two id-less findings on the SAME package but
        different classes (slopsquat vs CVE) must NOT collide. Both have
        file=package.json, function=lodash, line=0 — dedup_key would
        merge them; group_key (vuln_type) keeps them distinct."""
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            slop = _sca_row("", "lodash")  # empty id → fallback path
            slop.pop("id")
            slop.pop("finding_id")
            cve = dict(slop)
            cve["vuln_type"] = "sca:vulnerable_dependency"
            _write_sca_findings(run_dir, [slop, cve])
            merged = merge_sca_findings([run_dir])
            self.assertEqual(len(merged), 2)


if __name__ == "__main__":
    unittest.main()
