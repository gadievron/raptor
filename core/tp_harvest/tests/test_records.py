"""Tests for core.tp_harvest.records."""

from __future__ import annotations

from pathlib import Path

from core.staleness import hash_span
from core.tp_harvest.records import (
    HARVEST_STATUSES,
    SKIP_MISSING_LOCATION,
    SKIP_STATUS_INCONCLUSIVE,
    SKIP_STATUS_INTERMEDIATE,
    SKIP_STATUS_NEGATIVE,
    SKIP_STATUS_NOT_CONFIRMED,
    SKIP_STATUS_UNVERIFIED,
    build_record,
    classify_finding,
    harvest_identity,
)

from .conftest import SINK_LINE, make_finding


class TestClassifyFinding:
    def test_confirmed_tiers_harvest(self):
        for status in sorted(HARVEST_STATUSES):
            ok, reason = classify_finding(
                make_finding(status=status, final_status=status))
            assert ok, status
            assert reason == ""

    def test_negative_statuses_skip(self):
        for status in ("ruled_out", "disproven", "false_positive"):
            ok, reason = classify_finding(
                make_finding(status=status, final_status=status))
            assert not ok
            assert reason == SKIP_STATUS_NEGATIVE

    def test_unverified_confirmation_skips(self):
        ok, reason = classify_finding(make_finding(
            status="confirmed_unverified", final_status="confirmed_unverified"))
        assert not ok
        assert reason == SKIP_STATUS_UNVERIFIED

    def test_intermediate_and_inconclusive_skip(self):
        ok, reason = classify_finding(make_finding(
            status="poc_success", final_status="poc_success"))
        assert (ok, reason) == (False, SKIP_STATUS_INTERMEDIATE)
        ok, reason = classify_finding(make_finding(
            status="not_disproven", final_status="not_disproven"))
        assert (ok, reason) == (False, SKIP_STATUS_INCONCLUSIVE)

    def test_below_confirmation_tiers_skip(self):
        # Two-direction guard: these sit ABOVE negative but BELOW hard
        # confirmation — widening HARVEST_STATUSES to admit them is a
        # deliberate decision, not a drift.
        for status in ("likely_exploitable", "pending", ""):
            ok, reason = classify_finding(
                make_finding(status=status, final_status=status))
            assert not ok, status
            assert reason == SKIP_STATUS_NOT_CONFIRMED

    def test_verdict_booleans_take_precedence(self):
        # is_exploitable True → exploitable regardless of status field
        # (core.project.correlate.get_finding_status semantics reused,
        # never re-derived).
        ok, reason = classify_finding(
            make_finding(status="pending", final_status=None,
                         is_exploitable=True))
        assert ok
        ok, reason = classify_finding(
            make_finding(is_true_positive=False))
        assert not ok
        assert reason == SKIP_STATUS_NEGATIVE

    def test_missing_location_skips(self):
        ok, reason = classify_finding(make_finding(file="", file_path=""))
        assert (ok, reason) == (False, SKIP_MISSING_LOCATION)
        ok, reason = classify_finding(make_finding(line=0))
        assert (ok, reason) == (False, SKIP_MISSING_LOCATION)


class TestHarvestIdentity:
    def test_identity_is_stable_and_cwe_canonical(self):
        a = harvest_identity(make_finding(cwe_id="CWE-121"))
        b = harvest_identity(make_finding(cwe_id="cwe-121"))
        assert a == b
        assert len(a) == 32
        assert set(a) <= set("0123456789abcdef")

    def test_identity_differs_by_location(self):
        a = harvest_identity(make_finding())
        b = harvest_identity(make_finding(line=SINK_LINE + 1))
        assert a != b


class TestBuildRecord:
    def test_record_shape(self, run_dir: Path, target_tree: Path):
        rec = build_record(
            make_finding(), run_dir=run_dir,
            target_path=str(target_tree), command="validate",
            harvested_at="2026-01-01T00:00:00+00:00",
        )
        d = rec.to_dict()
        assert d["schema_version"] == 1
        assert d["finding_id"] == "FIND-1"
        assert d["status"] == "exploitable"
        assert d["cwe"] == "CWE-121"
        assert d["file"] == "src/copy.c"
        assert d["line"] == SINK_LINE
        assert d["flow"] == ["argv[1] -> copy_name(src)", "strcpy(dst, src)"]
        assert d["evidence"]["ruling"]["status"] == "exploitable"
        assert d["evidence"]["has_poc"] is True
        assert d["run_dir"] == str(run_dir)

    def test_span_sha_matches_staleness_convention(
            self, run_dir: Path, target_tree: Path):
        rec = build_record(
            make_finding(), run_dir=run_dir, target_path=str(target_tree))
        expected = hash_span(target_tree / "src" / "copy.c",
                             SINK_LINE, SINK_LINE)
        assert expected  # fixture line must hash
        assert rec.span_sha == expected

    def test_span_sha_empty_when_target_missing(self, run_dir: Path):
        rec = build_record(
            make_finding(), run_dir=run_dir, target_path="/nonexistent/tree")
        assert rec.span_sha == ""

    def test_span_sha_refuses_out_of_target_paths(
            self, run_dir: Path, tmp_path: Path, target_tree: Path):
        # A 12-hex span hash of an arbitrary readable host file is a
        # content oracle — traversal and out-of-target absolute paths
        # must hash to "" (core.paths.confine semantics).
        secret = tmp_path / "secret.txt"
        secret.write_text("s3cret\n", encoding="utf-8")
        for hostile in ("../secret.txt", str(secret)):
            rec = build_record(
                make_finding(file=hostile, line=1),
                run_dir=run_dir, target_path=str(target_tree))
            assert rec.span_sha == "", hostile

    def test_span_sha_allows_in_target_absolute_path(
            self, run_dir: Path, target_tree: Path):
        rec = build_record(
            make_finding(file=str(target_tree / "src" / "copy.c")),
            run_dir=run_dir, target_path=str(target_tree))
        assert rec.span_sha  # confined absolute path is fine

    def test_hostile_row_shapes_degrade_not_crash(self):
        # int-able string line participates normally.
        ok, reason = classify_finding(make_finding(line="4"))
        assert ok
        assert harvest_identity(make_finding(line="4")) == \
            harvest_identity(make_finding(line=4))
        # Non-numeric / bool / dict shapes skip by name, never raise.
        ok, reason = classify_finding(make_finding(line="not-a-number"))
        assert (ok, reason) == (False, SKIP_MISSING_LOCATION)
        ok, reason = classify_finding(make_finding(line=True))
        assert (ok, reason) == (False, SKIP_MISSING_LOCATION)
        ok, reason = classify_finding(make_finding(
            status={"nested": "dict"}, final_status=None))
        assert not ok

    def test_oracle_verified_flag(self, run_dir: Path, target_tree: Path):
        from core.labeled_attempts.view import (
            Oracle,
            OutcomeStatus,
            VerifiedOutcome,
        )
        # No outcomes: the POSITIVE marker stays False — promotion
        # must not infer the evidence tier from an absent key.
        rec = build_record(make_finding(), run_dir=run_dir,
                           target_path=str(target_tree))
        assert rec.oracle_verified is False
        assert "verified_outcomes" not in rec.evidence

        outcome = VerifiedOutcome(
            finding_id="FIND-1", oracle=Oracle.SANDBOX,
            status=OutcomeStatus.VERIFIED, reproducible=True)
        rec = build_record(make_finding(), run_dir=run_dir,
                           target_path=str(target_tree),
                           outcomes=[outcome])
        assert rec.oracle_verified is True
        assert rec.evidence["verified_outcomes"]

    def test_target_derived_text_is_bounded_and_escaped(
            self, run_dir: Path, target_tree: Path):
        hostile = "evil\x1b]0;pwn\x07" + "A" * 1000
        rec = build_record(
            make_finding(message=hostile, proof={"flow": [hostile] * 40}),
            run_dir=run_dir, target_path=str(target_tree),
        )
        assert "\x1b" not in rec.message
        assert len(rec.message) < 600
        assert len(rec.flow) <= 21  # capped + elision marker
        assert all("\x07" not in step for step in rec.flow)
