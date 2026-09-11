"""Tests for coverage record builder."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.semgrep.coverage import to_coverage_record
from packages.semgrep.models import SemgrepResult


class TestToCoverageRecord:
    def test_empty_results(self):
        assert to_coverage_record([]) is None

    def test_no_files_but_pack_ran_still_records(self):
        # A pack that ran (or failed) with nothing scanned is still
        # signal — matching core.coverage.record's builders, which only
        # skip when there is no signal at all.
        results = [SemgrepResult(name="r1")]
        record = to_coverage_record(results)
        assert record is not None
        assert record["files_examined"] == []
        assert record["rules_applied"] == ["r1"]

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
        # Engine-level errors are path-bearing too (pack name as path,
        # mirroring build_from_cocci's rule-as-path) so consumers that
        # key on "path" don't drop them.
        assert {
            "rule": "r1", "path": "r1", "reason": "Timeout after 60s",
        } in record["files_failed"]

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


class TestTotalFailureRuns:
    def test_total_failure_run_yields_record(self):
        # Rule-schema failure before any file scanned: the record must
        # still exist — a None here made engine failure read as
        # verified silence in coverage summaries.
        results = [
            SemgrepResult(
                name="pack1",
                errors=["InvalidRuleSchemaError: bad"],
                returncode=7,
            ),
        ]
        record = to_coverage_record(results)
        assert record is not None
        assert record["files_examined"] == []
        assert record["rules_applied"] == ["pack1"]
        assert record["files_failed"] == [{
            "rule": "pack1",
            "path": "pack1",
            "reason": "InvalidRuleSchemaError: bad",
        }]

    def test_no_signal_at_all_still_none(self):
        # Two-direction: nothing scanned, no names, no errors.
        results = [SemgrepResult(name="", files_examined=[], errors=[])]
        assert to_coverage_record(results) is None


class TestErrorDoubleCounting:
    def test_path_bearing_error_level_entry_counted_once(self):
        # parse_json_output routes a path-bearing error-level entry into
        # BOTH files_failed and errors; the coverage record must fold it
        # into a single failure, not two.
        results = [
            SemgrepResult(
                name="pack1",
                files_examined=["a.c"],
                files_failed=[{"path": "a.c", "reason": "boom"}],
                errors=["SemgrepError: boom"],
            ),
        ]
        record = to_coverage_record(results)
        assert record["files_failed"] == [
            {"rule": "pack1", "path": "a.c", "reason": "boom"}
        ]

    def test_distinct_engine_error_still_recorded(self):
        # Two-direction: an engine error unrelated to any per-file
        # failure must NOT be deduped away.
        results = [
            SemgrepResult(
                name="pack1",
                files_examined=["a.c"],
                files_failed=[{"path": "a.c", "reason": "boom"}],
                errors=["SemgrepError: boom", "Timeout after 60s"],
            ),
        ]
        record = to_coverage_record(results)
        assert len(record["files_failed"]) == 2
        assert {
            "rule": "pack1", "path": "pack1", "reason": "Timeout after 60s",
        } in record["files_failed"]
