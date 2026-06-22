"""Phase 15 — baseline parity report generator tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from core.dataflow.sanitizer_cut_parity import (
    LABEL_SHOULD_NOT_SUPPRESS,
    LABEL_SHOULD_SUPPRESS,
    VERDICT_SUPPRESS,
    parity_criterion_met,
)
from core.dataflow.sanitizer_cut_parity_report import (
    build_baseline_records,
    build_baseline_summary,
    render_baseline_report,
)


@pytest.fixture(autouse=True)
def _flag_on(monkeypatch):
    # The baseline's sanitizer-cut fixtures need the value-bound gate
    # consulted to suppress, which requires the flag.
    monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
    monkeypatch.delenv("RAPTOR_SANITIZER_CUT_PARITY_LOG", raising=False)


class TestBaselineRecords:
    def test_all_fixtures_resolve_to_records(self):
        records = build_baseline_records()
        assert len(records) == 7
        assert all(r.label in (LABEL_SHOULD_SUPPRESS,
                               LABEL_SHOULD_NOT_SUPPRESS) for r in records)

    def test_validator_fixture_lexical_suppresses(self):
        records = {r.finding_id: r for r in build_baseline_records()}
        # The guard-and-exit validator fixture: lexical fires.
        assert records["validator_guard_safe"].lexical_suppressed is True

    def test_sanitizer_cut_safe_value_bound_suppresses(self):
        records = {r.finding_id: r for r in build_baseline_records()}
        r = records["sanitizer_cut_safe"]
        assert r.value_bound_verdict == VERDICT_SUPPRESS
        assert r.value_bound_suppressed is True
        # ...and lexical does NOT fire on this shape.
        assert r.lexical_suppressed is False

    def test_helper_fixture_inter_proc_suppresses(self):
        records = {r.finding_id: r for r in build_baseline_records()}
        # Phase 14 inter-proc binding should make the helper case suppress.
        assert records["sanitizer_cut_helper"].value_bound_suppressed is True

    def test_wrong_variable_not_suppressed(self):
        records = {r.finding_id: r for r in build_baseline_records()}
        assert records["sanitizer_cut_wrong_variable"].value_bound_suppressed \
            is False


class TestBaselineSummary:
    def test_complementary_coverage_fails_removal_gate(self):
        # The headline result: lexical and value-bound are
        # complementary (each covers a shape the other doesn't), so
        # the no-regression guard fails and removal is NOT yet safe.
        s = build_baseline_summary()
        assert s.lexical_only > 0
        assert s.value_bound_only > 0
        assert s.no_lexical_regression is False
        assert parity_criterion_met(s) is False

    def test_no_bug_hidden_by_either_method(self):
        s = build_baseline_summary()
        assert s.lexical.bug_hiding.rate == 0.0
        assert s.value_bound.bug_hiding.rate == 0.0

    def test_report_renders_and_states_gate_no(self):
        report = render_baseline_report()
        assert "Safe to remove lexical (Phase 16 gate): NO" in report


class TestCommittedReportInSync:
    def test_committed_report_matches_generator(self):
        """The committed first-report.md must match the generator
        output. If this fails, regenerate:
            RAPTOR_SANITIZER_CUT=1 core/dataflow/scripts/sanitizer-cut-parity-report \\
                > docs/sanitizer-cut-parity/first-report.md
        """
        repo_root = Path(__file__).resolve().parents[3]
        committed = repo_root / "docs" / "sanitizer-cut-parity" / "first-report.md"
        assert committed.exists(), "first-report.md missing"
        generated = render_baseline_report() + "\n"
        assert committed.read_text(encoding="utf-8") == generated, (
            "Committed first-report.md is stale — regenerate it."
        )
