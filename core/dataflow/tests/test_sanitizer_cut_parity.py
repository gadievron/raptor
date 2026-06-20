"""Phase 15 — parity telemetry + A/B aggregation tests."""
from __future__ import annotations

from core.dataflow.sanitizer_cut_parity import (
    LABEL_SHOULD_NOT_SUPPRESS,
    LABEL_SHOULD_SUPPRESS,
    VERDICT_CANDIDATE_ONLY,
    VERDICT_NO_SUPPRESS,
    VERDICT_SUPPRESS,
    ParityRecord,
    aggregate_parity,
    append_parity_record,
    build_parity_record,
    parity_criterion_met,
    read_parity_records,
    render_parity_report,
    wilson_interval,
)


def _rec(
    *, fid="f", lexical, verdict, label=None, kind="charset",
):
    return build_parity_record(
        finding_id=fid, file="app.py", cwe="CWE-79", language="python",
        source_line=1, sink_line=3, kind=kind,
        lexical_suppressed=lexical, value_bound_verdict=verdict, label=label,
    )


# ---------------------------------------------------------------------------
# Record construction + serialisation
# ---------------------------------------------------------------------------


class TestRecord:
    def test_value_bound_suppressed_derived_from_verdict(self):
        r = _rec(lexical=False, verdict=VERDICT_SUPPRESS)
        assert r.value_bound_suppressed is True
        r2 = _rec(lexical=False, verdict=VERDICT_CANDIDATE_ONLY)
        assert r2.value_bound_suppressed is False

    def test_agree_property(self):
        assert _rec(lexical=True, verdict=VERDICT_SUPPRESS).agree is True
        assert _rec(lexical=True, verdict=VERDICT_NO_SUPPRESS).agree is False

    def test_roundtrip_json(self):
        r = _rec(lexical=True, verdict=VERDICT_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS)
        d = r.to_json()
        r2 = ParityRecord.from_json(d)
        assert r2 == r

    def test_jsonl_append_and_read(self, tmp_path):
        log = tmp_path / "parity.jsonl"
        r1 = _rec(fid="a", lexical=True, verdict=VERDICT_SUPPRESS)
        r2 = _rec(fid="b", lexical=False, verdict=VERDICT_NO_SUPPRESS)
        append_parity_record(log, r1)
        append_parity_record(log, r2)
        got = read_parity_records(log)
        assert len(got) == 2
        assert {g.finding_id for g in got} == {"a", "b"}

    def test_read_missing_file_returns_empty(self, tmp_path):
        assert read_parity_records(tmp_path / "nope.jsonl") == []

    def test_read_skips_malformed_lines(self, tmp_path):
        log = tmp_path / "parity.jsonl"
        log.write_text(
            '{"finding_id": "a", "lexical_suppressed": true, '
            '"value_bound_suppressed": true}\n'
            "not json at all\n"
            '{"missing": "required"}\n',
            encoding="utf-8",
        )
        got = read_parity_records(log)
        assert len(got) == 1
        assert got[0].finding_id == "a"


# ---------------------------------------------------------------------------
# Wilson interval
# ---------------------------------------------------------------------------


class TestWilson:
    def test_zero_total_is_max_uncertainty(self):
        assert wilson_interval(0, 0) == (0.0, 1.0)

    def test_all_successes_high_near_one_low_below_one(self):
        low, high = wilson_interval(10, 10)
        assert high == 1.0 or high > 0.9
        assert low < 1.0  # never collapses to a point

    def test_half_centred(self):
        low, high = wilson_interval(50, 100)
        assert low < 0.5 < high

    def test_bounds_clamped(self):
        low, high = wilson_interval(1, 3)
        assert 0.0 <= low <= high <= 1.0


# ---------------------------------------------------------------------------
# Aggregation + criterion
# ---------------------------------------------------------------------------


class TestAggregation:
    def test_agreement_matrix(self):
        records = [
            _rec(fid="1", lexical=True, verdict=VERDICT_SUPPRESS),    # both
            _rec(fid="2", lexical=True, verdict=VERDICT_NO_SUPPRESS),  # lex only
            _rec(fid="3", lexical=False, verdict=VERDICT_SUPPRESS),  # vb only
            _rec(fid="4", lexical=False, verdict=VERDICT_NO_SUPPRESS),  # neither
        ]
        s = aggregate_parity(records)
        assert s.both_suppress == 1
        assert s.lexical_only == 1
        assert s.value_bound_only == 1
        assert s.neither == 1
        assert s.total == 4

    def test_duplicate_finding_id_counts_once_keeping_last(self):
        # Review #3: a retried finding appends the same finding_id twice.
        # aggregate_parity must count it ONCE, keeping the latest verdict
        # (here the retry flipped from suppress→no-suppress), so the
        # window isn't biased.
        records = [
            _rec(fid="dup", lexical=True, verdict=VERDICT_SUPPRESS),   # 1st
            _rec(fid="dup", lexical=False, verdict=VERDICT_NO_SUPPRESS),  # retry
            _rec(fid="u", lexical=True, verdict=VERDICT_SUPPRESS),
        ]
        s = aggregate_parity(records)
        assert s.total == 2  # dup collapsed, not 3
        # The kept "dup" record is the retry (neither suppresses).
        assert s.neither == 1
        assert s.both_suppress == 1  # only the unique "u"
        assert s.lexical_only == 0
        assert s.value_bound_only == 0

    def test_value_bound_strictly_better_meets_criterion(self):
        # 2 safe findings: value-bound suppresses both, lexical neither.
        # 2 real findings: neither suppresses.
        records = [
            _rec(fid="s1", lexical=False, verdict=VERDICT_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS),
            _rec(fid="s2", lexical=False, verdict=VERDICT_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS),
            _rec(fid="b1", lexical=False, verdict=VERDICT_NO_SUPPRESS,
                 label=LABEL_SHOULD_NOT_SUPPRESS),
            _rec(fid="b2", lexical=False, verdict=VERDICT_CANDIDATE_ONLY,
                 label=LABEL_SHOULD_NOT_SUPPRESS),
        ]
        s = aggregate_parity(records)
        assert s.value_bound.noise_suppression.rate == 1.0
        assert s.lexical.noise_suppression.rate == 0.0
        assert s.value_bound.bug_hiding.rate == 0.0
        assert s.lexical.bug_hiding.rate == 0.0
        assert parity_criterion_met(s) is True

    def test_value_bound_misses_noise_fails_criterion(self):
        # Lexical suppresses a safe finding the value-bound gate misses.
        records = [
            _rec(fid="s1", lexical=True, verdict=VERDICT_NO_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS),
            _rec(fid="b1", lexical=False, verdict=VERDICT_NO_SUPPRESS,
                 label=LABEL_SHOULD_NOT_SUPPRESS),
        ]
        s = aggregate_parity(records)
        # value-bound noise-suppression (0) < lexical (1) → criterion fails
        assert parity_criterion_met(s) is False

    def test_equal_rates_but_complementary_coverage_fails_gate(self):
        # The subtle case: lexical and value-bound each suppress one
        # distinct safe finding (equal aggregate noise-suppression of
        # 0.5), but value-bound abandons the population lexical covers.
        # The rate criterion passes; the no-regression guard fails, so
        # the gate is NOT safe-to-remove.
        records = [
            # lexical suppresses this safe one, value-bound doesn't
            _rec(fid="lex_safe", lexical=True, verdict=VERDICT_NO_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS),
            # value-bound suppresses this safe one, lexical doesn't
            _rec(fid="vb_safe", lexical=False, verdict=VERDICT_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS),
            # one real finding neither suppresses
            _rec(fid="bug", lexical=False, verdict=VERDICT_NO_SUPPRESS,
                 label=LABEL_SHOULD_NOT_SUPPRESS),
        ]
        s = aggregate_parity(records)
        assert s.rate_criterion_met is True            # 0.5 >= 0.5, 0 <= 0
        assert s.no_lexical_regression is False        # lexical_only == 1
        assert parity_criterion_met(s) is False        # gate NOT cleared

    def test_value_bound_hides_bug_fails_criterion(self):
        # Value-bound wrongly suppresses a real finding lexical kept.
        records = [
            _rec(fid="s1", lexical=True, verdict=VERDICT_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS),
            _rec(fid="b1", lexical=False, verdict=VERDICT_SUPPRESS,
                 label=LABEL_SHOULD_NOT_SUPPRESS),
        ]
        s = aggregate_parity(records)
        # value-bound bug-hiding (1) > lexical (0) → criterion fails
        assert parity_criterion_met(s) is False

    def test_empty_axis_not_met(self):
        # Only should_suppress findings — no bug axis → criterion not met
        records = [
            _rec(fid="s1", lexical=False, verdict=VERDICT_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS),
        ]
        s = aggregate_parity(records)
        assert parity_criterion_met(s) is False

    def test_unlabelled_records_count_in_matrix_not_rates(self):
        records = [
            _rec(fid="u", lexical=True, verdict=VERDICT_SUPPRESS),  # no label
            _rec(fid="s", lexical=False, verdict=VERDICT_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS),
            _rec(fid="b", lexical=False, verdict=VERDICT_NO_SUPPRESS,
                 label=LABEL_SHOULD_NOT_SUPPRESS),
        ]
        s = aggregate_parity(records)
        assert s.total == 3
        assert s.labelled_total == 2

    def test_by_kind_breakdown(self):
        records = [
            _rec(fid="1", lexical=True, verdict=VERDICT_SUPPRESS,
                 kind="charset"),
            _rec(fid="2", lexical=False, verdict=VERDICT_SUPPRESS,
                 kind="charset_sub"),
        ]
        s = aggregate_parity(records)
        assert s.by_kind["charset"]["both_suppress"] == 1
        assert s.by_kind["charset_sub"]["value_bound_only"] == 1


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


class TestReport:
    def test_report_contains_criterion_verdict(self):
        records = [
            _rec(fid="s1", lexical=False, verdict=VERDICT_SUPPRESS,
                 label=LABEL_SHOULD_SUPPRESS),
            _rec(fid="b1", lexical=False, verdict=VERDICT_NO_SUPPRESS,
                 label=LABEL_SHOULD_NOT_SUPPRESS),
        ]
        s = aggregate_parity(records)
        report = render_parity_report(s)
        assert "Safe to remove lexical" in report
        assert "Noise-suppression" in report
        assert "Agreement matrix" in report

    def test_report_renders_with_empty_window(self):
        s = aggregate_parity([])
        report = render_parity_report(s)
        assert "Records in window: **0**" in report
