"""Tests for coverage record builder."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.semgrep.coverage import to_coverage_record
from packages.semgrep.models import SemgrepResult


class TestToCoverageRecord:
    def test_empty_results(self):
        assert to_coverage_record([]) is None

    def test_no_files_examined(self):
        results = [SemgrepResult(name="r1")]
        assert to_coverage_record(results) is None

    def test_basic_record(self):
        results = [
            SemgrepResult(
                name="injection",
                files_examined=["a.py", "b.py"],
                semgrep_version="1.79.0",
            ),
        ]
        record = to_coverage_record(results)
        assert record is not None
        assert record["tool"] == "semgrep"
        assert "timestamp" in record
        assert sorted(record["files_examined"]) == ["a.py", "b.py"]
        assert record["rules_applied"] == ["injection"]
        assert record["version"] == "1.79.0"

    def test_merges_files_across_results(self):
        results = [
            SemgrepResult(name="r1", files_examined=["a.py", "b.py"]),
            SemgrepResult(name="r2", files_examined=["b.py", "c.py"]),
        ]
        record = to_coverage_record(results)
        assert record["files_examined"] == ["a.py", "b.py", "c.py"]
        assert record["rules_applied"] == ["r1", "r2"]

    def test_explicit_rules_applied_overrides_derived(self):
        results = [
            SemgrepResult(name="r1", files_examined=["a.py"]),
        ]
        record = to_coverage_record(results, rules_applied=["my-group"])
        assert record["rules_applied"] == ["my-group"]

    def test_rules_preserve_insertion_order(self):
        results = [
            SemgrepResult(name="zz_late", files_examined=["a.py"]),
            SemgrepResult(name="aa_early", files_examined=["a.py"]),
            SemgrepResult(name="zz_late", files_examined=["b.py"]),
        ]
        record = to_coverage_record(results)
        assert record["rules_applied"] == ["zz_late", "aa_early"]

    def test_files_failed_from_json_errors(self):
        results = [
            SemgrepResult(
                name="r1",
                files_examined=["a.py"],
                files_failed=[{"path": "broken.py", "reason": "parse error"}],
            ),
        ]
        record = to_coverage_record(results)
        assert record["files_failed"] == [{
            "rule": "r1",
            "path": "broken.py",
            "reason": "parse error",
        }]

    def test_files_failed_includes_runner_errors(self):
        # Runner-level errors (timeout, OSError) populate result.errors,
        # not result.files_failed. Both should land in files_failed of the
        # coverage record.
        results = [
            SemgrepResult(
                name="r1",
                files_examined=["a.py"],
                errors=["Timeout after 60s"],
            ),
        ]
        record = to_coverage_record(results)
        assert {"rule": "r1", "reason": "Timeout after 60s"} in record["files_failed"]

    def test_no_failures_key_when_clean(self):
        results = [
            SemgrepResult(name="r1", files_examined=["a.py"]),
        ]
        record = to_coverage_record(results)
        assert "files_failed" not in record

    def test_no_version_key_when_unknown(self):
        results = [
            SemgrepResult(name="r1", files_examined=["a.py"]),
        ]
        record = to_coverage_record(results)
        assert "version" not in record
