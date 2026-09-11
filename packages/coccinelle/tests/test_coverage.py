"""Tests for coverage record builder."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.coccinelle.coverage import to_coverage_record
from packages.coccinelle.models import SpatchMatch, SpatchResult


class TestToCoverageRecord:
    def test_empty_results(self):
        assert to_coverage_record([]) is None

    def test_no_files_but_rule_ran_still_records(self):
        # A rule that ran (or failed to run) with nothing examined is
        # still signal — matching core.coverage.record.build_from_cocci,
        # which only skips when there are no files AND no rules.
        results = [SpatchResult(rule="r1")]
        record = to_coverage_record(results)
        assert record is not None
        assert record["files_examined"] == []
        assert record["rules_applied"] == ["r1"]

    def test_basic_record(self):
        results = [
            SpatchResult(
                rule="unchecked_return",
                files_examined=["a.c", "b.c"],
                matches=[SpatchMatch(file="a.c", line=10)],
            ),
        ]
        record = to_coverage_record(results)
        assert record is not None
        assert record["tool"] == "coccinelle"
        assert "timestamp" in record
        assert sorted(record["files_examined"]) == ["a.c", "b.c"]
        assert record["rules_applied"] == ["unchecked_return"]

    def test_merges_files_across_results(self):
        results = [
            SpatchResult(rule="r1", files_examined=["a.c", "b.c"]),
            SpatchResult(rule="r2", files_examined=["b.c", "c.c"]),
        ]
        record = to_coverage_record(results)
        assert record["files_examined"] == ["a.c", "b.c", "c.c"]
        assert record["rules_applied"] == ["r1", "r2"]

    def test_rules_preserve_insertion_order(self):
        results = [
            SpatchResult(rule="zz_late", files_examined=["a.c"]),
            SpatchResult(rule="aa_early", files_examined=["a.c"]),
            SpatchResult(rule="zz_late", files_examined=["b.c"]),
        ]
        record = to_coverage_record(results)
        assert record["rules_applied"] == ["zz_late", "aa_early"]

    def test_includes_failures(self):
        results = [
            SpatchResult(
                rule="r1",
                files_examined=["a.c"],
                errors=["parse error at line 5"],
            ),
        ]
        record = to_coverage_record(results)
        # Path-bearing failure entries (rule name as path), matching
        # build_from_cocci — consumers key and dedupe on "path".
        assert record["files_failed"] == [
            {"rule": "r1", "path": "r1", "reason": "parse error at line 5"}
        ]

    def test_no_failures_key_when_clean(self):
        results = [
            SpatchResult(rule="r1", files_examined=["a.c"]),
        ]
        record = to_coverage_record(results)
        assert "files_failed" not in record


class TestTotalFailureRuns:
    def test_total_failure_run_yields_record(self):
        # Every rule failed to parse, nothing examined: the record must
        # still exist (rules_applied + files_failed) — a None here made
        # engine failure read as verified silence in /project coverage.
        results = [
            SpatchResult(rule="myrule", errors=["spatch parse error"], returncode=2),
        ]
        record = to_coverage_record(results)
        assert record is not None
        assert record["files_examined"] == []
        assert record["rules_applied"] == ["myrule"]
        assert record["files_failed"] == [
            {"rule": "myrule", "path": "myrule", "reason": "spatch parse error"}
        ]

    def test_no_signal_at_all_still_none(self):
        # Two-direction: with no files, no rule names, and no errors
        # there is genuinely nothing to record.
        results = [SpatchResult(rule="", errors=[], files_examined=[])]
        assert to_coverage_record(results) is None

    def test_empty_rule_failures_dropped(self):
        # A failure with no rule name would emit an empty path —
        # filtered, matching build_from_cocci.
        results = [
            SpatchResult(rule="", errors=["boom"]),
            SpatchResult(rule="ok_rule", files_examined=["a.c"]),
        ]
        record = to_coverage_record(results)
        assert record is not None
        assert "files_failed" not in record
