"""Tests for findings merge across runs."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.merge import merge_findings, merge_runs, verify_merge


class TestMergeFindings(unittest.TestCase):

    def _make_run(self, tmpdir, name, findings):
        run_dir = Path(tmpdir) / name
        run_dir.mkdir()
        # Support both bare list and envelope format
        if isinstance(findings, list):
            data = findings
        else:
            data = findings
        (run_dir / "findings.json").write_text(json.dumps(data))
        return run_dir

    def test_dedup_by_location(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
                {"id": "F-002", "file": "b.c", "function": "foo", "line": 20, "ruling": {"status": "confirmed"}},
            ])
            b = self._make_run(d, "b", [
                {"id": "F-100", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "exploitable"}},
                {"id": "F-003", "file": "c.c", "function": "bar", "line": 30, "ruling": {"status": "confirmed"}},
            ])
            merged = merge_findings([a, b])
            self.assertEqual(len(merged), 3)  # a.c:main:10 deduped, b.c + c.c unique

    def test_latest_wins(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [{"id": "F-001", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}}])
            b = self._make_run(d, "b", [{"id": "F-100", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "exploitable"}}])
            merged = merge_findings([a, b])
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["ruling"]["status"], "exploitable")

    def test_empty_runs(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [])
            b = self._make_run(d, "b", [])
            merged = merge_findings([a, b])
            self.assertEqual(merged, [])

    def test_single_run(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [{"id": "F-001", "file": "a.c", "function": "main", "line": 10}])
            merged = merge_findings([a])
            self.assertEqual(len(merged), 1)

    def test_finding_id_field(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [{"finding_id": "SARIF-001", "is_exploitable": True}])
            b = self._make_run(d, "b", [{"finding_id": "SARIF-001", "is_exploitable": False}])
            merged = merge_findings([a, b])
            self.assertEqual(len(merged), 1)
            self.assertFalse(merged[0]["is_exploitable"])

    def test_envelope_format(self):
        with TemporaryDirectory() as d:
            a = Path(d) / "a"
            a.mkdir()
            (a / "findings.json").write_text(json.dumps({
                "stage": "D", "findings": [
                    {"id": "F-001", "file": "a.c", "function": "main", "line": 10},
                    {"id": "F-002", "file": "b.c", "function": "foo", "line": 20},
                ]
            }))
            merged = merge_findings([a])
            self.assertEqual(len(merged), 2)


    def test_higher_status_wins_over_later_run(self):
        """A confirmed finding from an older run beats not_disproven from a newer run."""
        with TemporaryDirectory() as d:
            old = self._make_run(d, "old", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10,
                 "status": "confirmed", "final_status": "confirmed"},
            ])
            new = self._make_run(d, "new", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10,
                 "status": "not_disproven"},
            ])
            merged = merge_findings([old, new])
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["final_status"], "confirmed")

    def test_equal_status_latest_wins(self):
        """Same status rank — later run's finding is used."""
        with TemporaryDirectory() as d:
            old = self._make_run(d, "old", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10,
                 "status": "confirmed", "detail": "from_old"},
            ])
            new = self._make_run(d, "new", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10,
                 "status": "confirmed", "detail": "from_new"},
            ])
            merged = merge_findings([old, new])
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["detail"], "from_new")

    def test_findings_without_status_rank_zero(self):
        """Findings with no status (e.g. from scan/codeql) don't override validated findings."""
        with TemporaryDirectory() as d:
            validated = self._make_run(d, "validated", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10,
                 "status": "confirmed", "final_status": "confirmed"},
            ])
            scan = self._make_run(d, "scan", [
                {"id": "SARIF-001", "file": "a.c", "function": "main", "line": 10,
                 "description": "scan finding with no status"},
            ])
            merged = merge_findings([validated, scan])
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["final_status"], "confirmed")

    def test_exploitable_beats_confirmed(self):
        """Exploitable (rank 7) beats confirmed (rank 5)."""
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10,
                 "final_status": "exploitable"},
            ])
            b = self._make_run(d, "b", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10,
                 "final_status": "confirmed"},
            ])
            merged = merge_findings([a, b])
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["final_status"], "exploitable")

    def test_ruled_out_beats_not_disproven(self):
        """ruled_out (rank 4) beats not_disproven (rank 2)."""
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10,
                 "final_status": "ruled_out"},
            ])
            b = self._make_run(d, "b", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10,
                 "status": "not_disproven"},
            ])
            merged = merge_findings([a, b])
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["final_status"], "ruled_out")


class TestVerifyMerge(unittest.TestCase):

    def test_valid_merge(self):
        merged = [{"id": "F-001"}, {"id": "F-002"}, {"id": "F-003"}]
        self.assertTrue(verify_merge(merged, 5, 3))

    def test_empty_merge_fails(self):
        self.assertFalse(verify_merge([], 5, 3))

    def test_fewer_than_unique_fails(self):
        merged = [{"id": "F-001", "file": "a.c", "function": "main", "line": 10}]
        self.assertFalse(verify_merge(merged, 5, 3))


class TestMergeRuns(unittest.TestCase):

    def _make_run(self, tmpdir, name, findings, extra_files=None):
        run_dir = Path(tmpdir) / name
        run_dir.mkdir()
        (run_dir / "findings.json").write_text(json.dumps(findings))
        for fname, content in (extra_files or {}).items():
            (run_dir / fname).write_text(content)
        return run_dir

    def test_basic_merge(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [{"id": "F-001", "file": "a.c", "function": "main", "line": 10}])
            b = self._make_run(d, "b", [{"id": "F-002", "file": "b.c", "function": "foo", "line": 20}])
            out = Path(d) / "merged"
            stats = merge_runs([a, b], out)
            self.assertEqual(stats["runs_merged"], 2)
            self.assertEqual(stats["unique_findings"], 2)
            self.assertTrue((out / "findings.json").exists())

    def test_unknown_artefacts_preserved(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [{"id": "F-001", "file": "a.c", "function": "main", "line": 10}],
                               extra_files={"my_notes.txt": "hello"})
            b = self._make_run(d, "b", [{"id": "F-002", "file": "b.c", "function": "foo", "line": 20}],
                               extra_files={"screenshot.png": "img"})
            out = Path(d) / "merged"
            stats = merge_runs([a, b], out)
            self.assertTrue((out / "my_notes.txt").exists())
            self.assertTrue((out / "screenshot.png").exists())
            self.assertGreater(stats.get("artefacts_preserved", 0), 0)

    def test_artefact_collision_renamed(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [{"id": "F-001", "file": "a.c", "function": "main", "line": 10}],
                               extra_files={"notes.txt": "from a"})
            b = self._make_run(d, "b", [{"id": "F-002", "file": "b.c", "function": "foo", "line": 20}],
                               extra_files={"notes.txt": "from b"})
            out = Path(d) / "merged"
            merge_runs([a, b], out)
            # Both should exist (one renamed)
            txt_files = list(out.glob("notes*.txt"))
            self.assertGreaterEqual(len(txt_files), 2)

    def test_merge_creates_output_dir(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [{"id": "F-001", "file": "a.c", "function": "main", "line": 10}])
            out = Path(d) / "new" / "dir" / "merged"
            merge_runs([a], out)
            self.assertTrue(out.exists())


class TestSarifMerge(unittest.TestCase):

    def _make_run(self, tmpdir, name, findings, sarif=None):
        run_dir = Path(tmpdir) / name
        run_dir.mkdir()
        (run_dir / "findings.json").write_text(json.dumps(findings))
        if sarif is not None:
            (run_dir / "results.sarif").write_text(json.dumps(sarif))
        return run_dir

    def test_sarif_files_merged(self):
        minimal_sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [{"id": "F-001", "file": "a.c", "function": "main", "line": 10}], sarif=minimal_sarif)
            b = self._make_run(d, "b", [{"id": "F-002", "file": "b.c", "function": "foo", "line": 20}], sarif=minimal_sarif)
            out = Path(d) / "merged"
            merge_runs([a, b], out)
            self.assertTrue((out / "merged.sarif").exists())


if __name__ == "__main__":
    unittest.main()
