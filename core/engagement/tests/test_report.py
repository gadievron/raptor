"""Tests for the engagement report (``core.engagement.report``).

Pure-synthesis battery: fixtures plant the artifacts the OTHER layers
write (ledger document, chain verdict records, review-journal rows,
checklist slots, survivor handoffs) and the tests prove the report
only renders them — every attestation gate is exercised in both
directions (a claim that re-verifies renders attesting; the same
claim with any invariant broken downgrades), the M8 wording is pinned
byte-for-byte, N17 advisory strata never enter earned counts, and
every render seam is fed hostile bytes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from core.coverage.journal import ReviewJournalEntry, append_entry
from core.engagement import report as report_mod
from core.engagement.chain_elf import (
    CHAIN_STATE_FILENAME,
    SURVIVORS_FILENAME,
    VERDICT_SCHEMA,
    chain_dir_for,
)
from core.engagement.ledger import LEDGER_FILENAME, checklist_slot_path
from core.engagement.report import (
    ATTESTING,
    FINDINGS_PRESENT,
    NON_ATTESTING,
    NOT_ENGAGED,
    REPORT_JSON_FILENAME,
    REPORT_MD_FILENAME,
    build_report,
    render_markdown,
    render_summary_lines,
    write_report,
)
from core.json import load_json, save_json

ART = "sha256-aabbccdd"
ART2 = "sha256-11223344"

# The M8 fixed verdict-table schema — every table entry must carry
# exactly these coverage-honesty fields (plus identity/status fields).
M8_FIELDS = (
    "policy_depth",
    "reached_depth",
    "degradation_reasons",
    "format_capability_tier_at_run_time",
)


# ── fixtures ─────────────────────────────────────────────────────────

def _row(artifact_id: str = ART, **over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "artifact_id": artifact_id,
        "class": "elf-linux",
        "format_tier": "full",
        "path": "bin/app",
        "size": 8,
        "identity": {"kind": "sha256", "value": "ab" * 32,
                     "anchor": "ab" * 8, "sha256": "ab" * 32},
        "status": {"state": "inventoried",
                   "updated_at": "2026-01-01T00:00:00+00:00"},
    }
    row.update(over)
    return row


def _make_ledger(out: Path, rows: list[dict[str, Any]],
                 **doc_over: Any) -> None:
    out.mkdir(parents=True, exist_ok=True)
    doc: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": "2026-01-01T00:00:00+00:00",
        "target_root": "/target/install",
        "rows": rows,
        "counts": {"rows": len(rows)},
    }
    doc.update(doc_over)
    save_json(out / LEDGER_FILENAME, doc)


def _verdict(**over: Any) -> dict[str, Any]:
    """A chain verdict record whose attesting claim re-verifies."""
    verdict: dict[str, Any] = {
        "schema": VERDICT_SCHEMA,
        "policy_depth": "T3",
        "policy_source": "policy",
        "reached_depth": "T3",
        "degradation_reasons": [],
        "format_capability_tier": "full",
        "journal_verdicts": {"clean": 3},
        "journal_floor": None,
        "attesting": True,
        "wording": "attested at T3 — full chain, journal floor met",
        "at": "2026-01-01T00:00:00+00:00",
    }
    verdict.update(over)
    return verdict


def _plant_verdict(out: Path, artifact_id: str,
                   verdict: dict[str, Any]) -> None:
    chain_dir = chain_dir_for(out, artifact_id)
    chain_dir.mkdir(parents=True, exist_ok=True)
    save_json(chain_dir / CHAIN_STATE_FILENAME, {"verdict": verdict})


def _journal(out: Path, artifact_id: str,
             rows: list[tuple[str, str, str]],
             sub: str = "audit") -> None:
    run_dir = chain_dir_for(out, artifact_id) / sub
    run_dir.mkdir(parents=True, exist_ok=True)
    for file, function, verdict in rows:
        append_entry(run_dir, ReviewJournalEntry(
            ts="2026-01-01T00:00:00+00:00", run_id="test",
            file=file, function=function, verdict=verdict,
            source_hash="d" * 12))


def _plant_survivors(out: Path, artifact_id: str,
                     items: list[dict[str, Any]]) -> None:
    chain_dir = chain_dir_for(out, artifact_id)
    chain_dir.mkdir(parents=True, exist_ok=True)
    save_json(chain_dir / SURVIVORS_FILENAME, {"survivors": items})


def _plant_checklist(out: Path, artifact_id: str) -> None:
    slot = checklist_slot_path(out, artifact_id)
    slot.parent.mkdir(parents=True, exist_ok=True)
    save_json(slot, {
        "total_items": 2,
        "files": [{"path": "binary:app", "items": [
            {"name": "main", "kind": "function",
             "line_start": 1, "line_end": 20},
            {"name": "gets_len", "kind": "function",
             "line_start": 30, "line_end": 60},
        ]}],
    })


def _entry(report: dict[str, Any],
           artifact_id: str = ART) -> dict[str, Any]:
    for entry in report["verdict_table"]:
        if entry["artifact_id"] == artifact_id:
            return entry
    raise AssertionError(f"no table entry for {artifact_id}")


# ── build refusal ────────────────────────────────────────────────────

class TestBuildRefusal:
    def test_no_ledger_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            build_report(tmp_path)

    def test_non_dict_ledger_raises(self, tmp_path: Path) -> None:
        save_json(tmp_path / LEDGER_FILENAME, ["not", "a", "doc"])
        with pytest.raises(FileNotFoundError):
            build_report(tmp_path)

    def test_ledger_present_builds(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        assert report["schema"] == "engagement-report/1"


# ── M8 fixed schema + attesting path ─────────────────────────────────

class TestVerdictTable:
    def test_every_entry_carries_m8_fields(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [
            _row(),
            _row(ART2, **{"class": "pe-exe", "format_tier": "core"}),
        ])
        _plant_verdict(tmp_path, ART, _verdict())
        report = build_report(tmp_path)
        for entry in report["verdict_table"]:
            for field in M8_FIELDS:
                assert field in entry, (entry["artifact_id"], field)
            assert "attestation" in entry
            assert "wording" in entry

    def test_valid_claim_renders_attesting(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict())
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["attestation"] == ATTESTING
        assert entry["wording"].startswith("attested at T3")
        assert entry["tier_provenance"] == "at_run_time"
        assert report["attestation_totals"] == {ATTESTING: 1}

    def test_findings_render_findings_present(self,
                                              tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            journal_verdicts={"clean": 2, "finding": 1},
            attesting=False, wording="1 finding-grade survivor"))
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["attestation"] == FINDINGS_PRESENT
        assert entry["journal_verdicts"]["finding"] == 1
        # SF-5: the rendered wording is DERIVED from the computed
        # status; the record's own prose stays in record_wording.
        assert entry["wording"] == (
            "findings present — 1 finding row(s) recorded at "
            "verdict time")
        assert entry["record_wording"] == "1 finding-grade survivor"

    def test_snake_case_in_json(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        att = _entry(report)["attestation"]
        assert att == att.lower()
        assert " " not in att


class TestDowngradeOnly:
    """The report may DOWNGRADE an attestation claim, never mint one.

    Each case plants a record that CLAIMS ``attesting`` while one
    invariant is broken — every one must render non-attesting with the
    report-side degradation named."""

    @pytest.mark.parametrize("broken", [
        {"degradation_reasons": [{"stage": "study",
                                  "reason": "llm_unavailable"}]},
        {"reached_depth": "T2"},
        {"format_capability_tier": "core"},
        {"journal_floor": {"required": "journal_rows",
                           "observed": "none"}},
        {"journal_verdicts": {}},
    ])
    def test_broken_claim_downgrades(self, tmp_path: Path,
                                     broken: dict[str, Any]) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(**broken))
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["attestation"] == NON_ATTESTING
        reasons = [d.get("reason")
                   for d in entry["degradation_reasons"]]
        assert "verdict_recheck_failed" in reasons
        assert "failed the report re-check" in entry["wording"]

    def test_findings_beat_attesting_claim(self,
                                           tmp_path: Path) -> None:
        # A record claiming attestation WITH findings is a
        # contradiction — findings win (never hidden by the claim).
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            journal_verdicts={"finding": 2}))
        report = build_report(tmp_path)
        assert _entry(report)["attestation"] == FINDINGS_PRESENT

    def test_never_upgrades_a_non_claim(self, tmp_path: Path) -> None:
        # All invariants pass but the chain itself did NOT claim
        # attestation — the report must not mint one.
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            attesting=False, wording="chain declined"))
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["attestation"] == NON_ATTESTING
        # No report-side degradation: nothing was claimed, so
        # nothing failed a re-check.
        assert entry["degradation_reasons"] == []
        # SF-5: the rendered wording is derived, never the record's
        # prose; the prose survives in record_wording only.
        assert entry["wording"] == (
            "non-attesting — the chain did not claim attestation")
        assert entry["record_wording"] == "chain declined"

    def test_string_claim_is_not_a_claim(self, tmp_path: Path) -> None:
        # ``attesting`` must be boolean True — the STRING "false"
        # (truthy) and the STRING "true" both fail the ``is True``
        # gate and render non-attesting without a report-side
        # degradation (nothing boolean was claimed).
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(attesting="false"))
        entry = _entry(build_report(tmp_path))
        assert entry["attestation"] == NON_ATTESTING
        assert entry["degradation_reasons"] == []

    def test_bool_count_satisfies_no_floor(self, tmp_path: Path) -> None:
        # ``{"clean": true}`` is not a countable row —
        # ``isinstance(True, int)`` holds in Python, so the count
        # floor must exclude bools explicitly.
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            journal_verdicts={"clean": True}))
        entry = _entry(build_report(tmp_path))
        assert entry["attestation"] == NON_ATTESTING
        reasons = [d.get("reason")
                   for d in entry["degradation_reasons"]]
        assert "verdict_recheck_failed" in reasons
        # The filtered counts also never leak the bool downstream.
        assert entry["journal_verdicts"] == {}

    def test_negative_finding_count_is_garbage(self,
                                               tmp_path: Path) -> None:
        # A negative finding count is garbage, not zero findings —
        # it must neither render findings-present nor re-verify an
        # attesting claim.
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            journal_verdicts={"clean": 3, "finding": -1}))
        entry = _entry(build_report(tmp_path))
        assert entry["attestation"] == NON_ATTESTING
        reasons = [d.get("reason")
                   for d in entry["degradation_reasons"]]
        assert "verdict_recheck_failed" in reasons


# ── M8 wording for rows without a chain verdict ──────────────────────

class TestNotEngagedWording:
    def test_sub_full_tier_catalogs_pending(self,
                                            tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row(**{"format_tier": "core"})])
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["attestation"] == NOT_ENGAGED
        assert entry["wording"] == (
            "no findings within core capability — catalogs pending")
        assert entry["tier_provenance"] == "current_table"

    def test_full_tier_not_engaged_wording(self,
                                           tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row(policy={"tier": "T2",
                                             "basis": "signal"})])
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["attestation"] == NOT_ENGAGED
        assert entry["wording"] == (
            "not engaged — no analysis chain has run (policy depth T2)")

    def test_wrong_schema_verdict_ignored(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            schema="hand-planted/1"))
        report = build_report(tmp_path)
        assert _entry(report)["attestation"] == NOT_ENGAGED

    def test_hostile_artifact_id_never_reaches_disk(
            self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row(artifact_id="../../etc/passwd")])
        report = build_report(tmp_path)
        entry = report["verdict_table"][0]
        assert entry["attestation"] == NOT_ENGAGED

    def test_policy_depth_display_order(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [
            _row(policy={"tier": "T1"}),
            _row(ART2, status={"state": "analysed",
                               "depth": "T2-behavioural"}),
            _row("sha256-55667788"),
        ])
        report = build_report(tmp_path)
        assert _entry(report, ART)["policy_depth"] == "T1"
        assert _entry(report, ART2)["policy_depth"] == "T2"
        assert _entry(report,
                      "sha256-55667788")["policy_depth"] == "unassigned"


# ── M3d strata ───────────────────────────────────────────────────────

class TestM3dStrata:
    def test_verified_vs_scored_low_split(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [
            _row(policy={"tier": "T0", "low_exposure_verified": True}),
            _row(ART2, policy={"tier": "T1"}),
            _row("sha256-55667788", policy={"tier": "T3"}),
        ])
        report = build_report(tmp_path)
        residual = report["residual_map"]
        assert residual["verified_low_exposure"] == [ART]
        assert residual["scored_low_unverified"] == [ART2]

    def test_truthy_non_true_flag_stays_scored_low(
            self, tmp_path: Path) -> None:
        # The flag is a verified assertion, not a truthy hint — only
        # the boolean True from the exposure pass counts.
        _make_ledger(tmp_path, [_row(policy={
            "tier": "T0", "low_exposure_verified": "yes"})])
        report = build_report(tmp_path)
        residual = report["residual_map"]
        assert residual["scored_low_unverified"] == [ART]
        assert residual["verified_low_exposure"] == []

    def test_strata_rendered_in_markdown(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [
            _row(policy={"tier": "T0", "low_exposure_verified": True}),
            _row(ART2, policy={"tier": "T1"}),
        ])
        md = render_markdown(build_report(tmp_path))
        assert "Scored Low (unverified — never analysed at depth): 1" \
            in md
        assert ("Verified Low Exposure (full mechanical exposure "
                "pass ran): 1") in md


# ── Coverage synthesis (earned journal rows; N17 advisory) ──────────

class TestCoverageSynthesis:
    def test_journal_rows_are_earned_coverage(self,
                                              tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _journal(tmp_path, ART, [("binary:app", "main", "clean"),
                                 ("binary:app", "gets_len", "clean")])
        _journal(tmp_path, ART, [("binary:app", "gets_len", "finding")],
                 sub="audit-rereview")
        report = build_report(tmp_path)
        earned = report["coverage"]["earned_journal_rows_total"]
        assert earned == {"clean": 2, "finding": 1}
        per = report["coverage"]["per_artifact"][0]
        assert per["journal_verdict_rows"] == {"clean": 2, "finding": 1}
        assert per["journal_load_complete"] is True

    def test_no_artifacts_no_coverage_rows(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        assert report["coverage"]["per_artifact"] == []
        assert report["coverage"]["earned_journal_rows_total"] == {}

    def test_overlay_absent_checklist_declared(self,
                                               tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _journal(tmp_path, ART, [("binary:app", "main", "clean")])
        report = build_report(tmp_path)
        overlay = report["coverage"]["per_artifact"][0]["overlay"]
        assert overlay == {"consumed": False,
                           "reason": "checklist_slot_absent"}

    def test_overlay_no_run_dirs_declared(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_checklist(tmp_path, ART)
        _plant_verdict(tmp_path, ART, _verdict())
        report = build_report(tmp_path)
        overlay = report["coverage"]["per_artifact"][0]["overlay"]
        assert overlay == {"consumed": False, "reason": "no_run_dirs"}

    def test_overlay_consumed_with_advisory_stratum(
            self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_checklist(tmp_path, ART)
        _journal(tmp_path, ART, [("binary:app", "main", "clean")])
        report = build_report(tmp_path)
        overlay = report["coverage"]["per_artifact"][0]["overlay"]
        assert overlay["consumed"] is True
        assert overlay["checklist_items"] == 2
        # N17: the advisory stratum is present, LABELED, and bounded
        # to its own keys — never folded into earned counts.
        assert "advisory_llm_extent_including_reads" in overlay
        assert "advisory stratum" in overlay["advisory_note"]
        earned = report["coverage"]["earned_journal_rows_total"]
        assert earned == {"clean": 1}

    def test_overlay_consume_is_read_only(self, tmp_path: Path) -> None:
        # The ephemeral store path must never materialise on disk.
        _make_ledger(tmp_path, [_row()])
        _plant_checklist(tmp_path, ART)
        _journal(tmp_path, ART, [("binary:app", "main", "clean")])
        build_report(tmp_path)
        chain_dir = chain_dir_for(tmp_path, ART)
        assert not (chain_dir / "coverage-synth.json").exists()

    def test_divergence_flagged_when_rows_vanish(
            self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            journal_verdicts={"clean": 12, "suspicious": 1}))
        report = build_report(tmp_path)
        per = report["coverage"]["per_artifact"][0]
        assert per["journal_rows_absent_since_verdict"] is True
        assert per["journal_verdict_rows_at_verdict_time"] == {
            "clean": 12, "suspicious": 1}
        md = render_markdown(report)
        assert "rows absent since verdict" in md
        assert "the live journal differs" in md

    def test_no_divergence_when_rows_match(self,
                                           tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            journal_verdicts={"clean": 1}))
        _journal(tmp_path, ART, [("binary:app", "main", "clean")])
        report = build_report(tmp_path)
        per = report["coverage"]["per_artifact"][0]
        assert per["journal_rows_absent_since_verdict"] is False
        md = render_markdown(report)
        assert "rows absent since verdict" not in md

    def test_earned_note_states_n17(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        note = report["coverage"]["earned_note"]
        assert "journal verdict rows" in note
        assert "advisory" in note


# ── divergence: per-label comparison (never summed totals) ──────────

class TestDivergencePerLabel:
    """The verdict-vs-live journal comparison is PER LABEL. Summed
    totals let a swapped composition mask itself behind an equal
    total — both review lenses reproduced that masking."""

    def test_equal_totals_swapped_composition_flags(
            self, tmp_path: Path) -> None:
        # D1: record {clean: 3}; live {clean: 2, suspicious: 1}.
        # Totals equal — the r1 summed comparison stayed silent.
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict())
        _journal(tmp_path, ART, [("binary:app", "f", "clean"),
                                 ("binary:app", "g", "clean"),
                                 ("binary:app", "h", "suspicious")])
        report = build_report(tmp_path)
        per = report["coverage"]["per_artifact"][0]
        assert per["journal_rows_absent_since_verdict"] is True
        md = render_markdown(report)
        assert "rows absent since verdict" in md

    def test_cross_artifact_masking_flags_both(
            self, tmp_path: Path) -> None:
        # D2: A1 recorded {clean: 2, suspicious: 1}, live {clean: 3};
        # A2 recorded {clean: 3}, live {clean: 2, suspicious: 1}.
        # Global totals AND per-artifact totals all match — only the
        # per-label comparison sees either swap.
        _make_ledger(tmp_path, [_row(), _row(ART2)])
        _plant_verdict(tmp_path, ART, _verdict(
            attesting=False,
            journal_verdicts={"clean": 2, "suspicious": 1}))
        _plant_verdict(tmp_path, ART2, _verdict(
            journal_verdicts={"clean": 3}))
        _journal(tmp_path, ART, [("a.c", "f", "clean"),
                                 ("a.c", "g", "clean"),
                                 ("a.c", "h", "clean")])
        _journal(tmp_path, ART2, [("b.c", "f", "clean"),
                                  ("b.c", "g", "clean"),
                                  ("b.c", "h", "suspicious")])
        report = build_report(tmp_path)
        flags = {c["artifact_id"]: c["journal_rows_absent_since_verdict"]
                 for c in report["coverage"]["per_artifact"]}
        assert flags == {ART: True, ART2: True}
        assert "rows absent since verdict" in render_markdown(report)

    def test_exactly_one_vanished_row_flags(self,
                                            tmp_path: Path) -> None:
        # Boundary: recorded 3 clean, live 2 clean — a single vanished
        # row must flag (a `>` weakened to `> live + 1` must fail).
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            journal_verdicts={"clean": 3}))
        _journal(tmp_path, ART, [("a.c", "f", "clean"),
                                 ("a.c", "g", "clean")])
        report = build_report(tmp_path)
        per = report["coverage"]["per_artifact"][0]
        assert per["journal_rows_absent_since_verdict"] is True

    def test_rows_appeared_renders_composition_divergence(
            self, tmp_path: Path) -> None:
        # The other direction: a finding row APPEARED since an
        # attesting verdict. No row vanished, so the absent flag
        # stays False — but the disagreement is knowable and must
        # render (provenance-labeled; the record's attestation is
        # not re-adjudicated).
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict())
        _journal(tmp_path, ART, [("a.c", "f", "clean"),
                                 ("a.c", "g", "clean"),
                                 ("a.c", "h", "clean"),
                                 ("a.c", "i", "finding")])
        report = build_report(tmp_path)
        per = report["coverage"]["per_artifact"][0]
        assert per["journal_rows_absent_since_verdict"] is False
        assert per["journal_composition_diverged_since_verdict"] is True
        assert _entry(report)["attestation"] == ATTESTING
        md = render_markdown(report)
        assert "composition diverged since verdict" in md
        assert "the live journal differs" in md

    def test_zero_entry_recorded_is_agreement(self,
                                              tmp_path: Path) -> None:
        # {"finding": 0} recorded against a live journal without the
        # label is agreement, not divergence (zero-normalised both
        # sides).
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            journal_verdicts={"clean": 1, "finding": 0}))
        _journal(tmp_path, ART, [("a.c", "f", "clean")])
        report = build_report(tmp_path)
        per = report["coverage"]["per_artifact"][0]
        assert per["journal_rows_absent_since_verdict"] is False
        assert per["journal_composition_diverged_since_verdict"] \
            is False


# ── tier divergence (SF-4: rendered, never adjudicated) ─────────────

class TestTierDivergence:
    def test_record_tier_vs_current_tier_rendered(
            self, tmp_path: Path) -> None:
        # The ledger row's CURRENT tier dropped to symbol_only after
        # the run recorded full. Both shown, provenance-labeled; the
        # attestation still follows the record (downgrade-only rule
        # unchanged).
        _make_ledger(tmp_path,
                     [_row(**{"format_tier": "symbol_only"})])
        _plant_verdict(tmp_path, ART, _verdict())
        _journal(tmp_path, ART, [("a.c", "f", "clean"),
                                 ("a.c", "g", "clean"),
                                 ("a.c", "h", "clean")])
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["attestation"] == ATTESTING
        assert entry["format_capability_tier_at_run_time"] == "full"
        assert entry["format_capability_tier_current"] == "symbol_only"
        assert entry["tier_diverged_from_current"] is True
        md = render_markdown(report)
        assert "full (record; current symbol_only)" in md

    def test_matching_tiers_render_plain(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict())
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["tier_diverged_from_current"] is False
        assert "(record; current" not in render_markdown(report)


# ── overlay provenance (SF-2: consume-if-present, target-gated) ─────

class TestOverlayProvenance:
    def _fixture(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_checklist(tmp_path, ART)
        _journal(tmp_path, ART, [("binary:app", "main", "clean")])

    def test_planted_store_wrong_target_dropped(
            self, tmp_path: Path) -> None:
        # A pre-existing store at the synthesis path arrived from
        # OUTSIDE this report (nothing here writes it) — recorded
        # for another target, it must not enrich the numbers.
        from core.coverage.store import CoverageStore
        self._fixture(tmp_path)
        plant = chain_dir_for(tmp_path, ART) / "coverage-synth.json"
        store = CoverageStore(plant, target="/some/OTHER/target")
        store.mark("binary:app", 1, 60, "audit")
        store.set_file_meta("binary:app", total_lines=60, sloc=60)
        store.save()
        report = build_report(tmp_path)
        overlay = report["coverage"]["per_artifact"][0]["overlay"]
        assert overlay == {
            "consumed": False,
            "reason": "overlay_store_target_mismatch",
            "recorded_target": "/some/OTHER/target",
        }
        assert ("coverage.per_artifact.overlay.recorded_target"
                in report["derived_from_target"])
        assert "Overlay Store Target Mismatch" \
            in render_markdown(report)

    def test_planted_store_matching_target_consumed(
            self, tmp_path: Path) -> None:
        # Consume-if-present: a store recorded for THIS engagement's
        # target seeds the view.
        from core.coverage.store import CoverageStore
        self._fixture(tmp_path)
        plant = chain_dir_for(tmp_path, ART) / "coverage-synth.json"
        store = CoverageStore(plant, target="/target/install")
        store.mark("binary:app", 1, 60, "audit")
        store.set_file_meta("binary:app", total_lines=60, sloc=60)
        store.save()
        report = build_report(tmp_path)
        overlay = report["coverage"]["per_artifact"][0]["overlay"]
        assert overlay["consumed"] is True

    def test_unparseable_planted_store_dropped(
            self, tmp_path: Path) -> None:
        self._fixture(tmp_path)
        plant = chain_dir_for(tmp_path, ART) / "coverage-synth.json"
        plant.write_text("{not json", encoding="utf-8")
        report = build_report(tmp_path)
        overlay = report["coverage"]["per_artifact"][0]["overlay"]
        assert overlay["consumed"] is False
        assert overlay["reason"] == "overlay_store_target_mismatch"
        assert overlay["recorded_target"] is None

    def test_empty_engagement_target_never_matches(
            self, tmp_path: Path) -> None:
        # A ledger without a target_root cannot vouch for ANY
        # pre-existing store (fail-closed, never fail-open on "").
        from core.coverage.store import CoverageStore
        _make_ledger(tmp_path, [_row()], target_root="")
        _plant_checklist(tmp_path, ART)
        _journal(tmp_path, ART, [("binary:app", "main", "clean")])
        plant = chain_dir_for(tmp_path, ART) / "coverage-synth.json"
        store = CoverageStore(plant, target="")
        store.mark("binary:app", 1, 60, "audit")
        store.set_file_meta("binary:app", total_lines=60, sloc=60)
        store.save()
        report = build_report(tmp_path)
        overlay = report["coverage"]["per_artifact"][0]["overlay"]
        assert overlay["consumed"] is False
        assert overlay["reason"] == "overlay_store_target_mismatch"


# ── advisory stratum honesty (F2/F3: pinned to the view's fields) ───

class TestAdvisoryStratumHonesty:
    def test_advisory_extent_never_enters_earned(
            self, tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch) -> None:
        # A view claiming a huge llm read-extent must change ONLY the
        # labeled advisory key — earned totals stay journal rows, and
        # reviewed_analysed_depth stays the view's functions_reviewed
        # (never the by_category llm extent).
        import core.coverage.store_summary as summary_mod
        crafted = {
            "total_functions": 2,
            "functions_reviewed": 1,
            "llm_reviewable": 2,
            "functions_by_category": {"llm": 7},
        }
        monkeypatch.setattr(summary_mod, "coverage_view",
                            lambda *a, **k: crafted)
        monkeypatch.setattr(summary_mod, "no_lane_residual",
                            lambda view: [])
        _make_ledger(tmp_path, [_row()])
        _plant_checklist(tmp_path, ART)
        _journal(tmp_path, ART, [("binary:app", "main", "clean")])
        report = build_report(tmp_path)
        assert report["coverage"]["earned_journal_rows_total"] == {
            "clean": 1}
        overlay = report["coverage"]["per_artifact"][0]["overlay"]
        assert overlay["advisory_llm_extent_including_reads"] == 7
        assert overlay["reviewed_analysed_depth"] == 1
        assert overlay["checklist_items"] == 2


# ── depth distinction (F4: reached vs policy in degraded rows) ──────

class TestDepthDistinction:
    def test_degraded_row_keeps_depths_distinct(
            self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            attesting=False,
            reached_depth="T2",
            degradation_reasons=[{"stage": "study",
                                  "reason": "llm_unavailable"}]))
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["policy_depth"] == "T3"
        assert entry["reached_depth"] == "T2"
        md = render_markdown(report)
        # Distinct table cells — policy first, reached second.
        assert "| T3 | T2 |" in md


# ── render injection (probe1 shapes: every foreign slot escaped) ────

class TestRenderInjection:
    HOSTILE_ROWS = "1\x1b]0;pwned\x07\n# ALL CLEAN - AUDIT COMPLETE"
    HOSTILE_CLASS_N = "1\x1b[2J\n## Attestation: Clean Bill"
    HOSTILE_LABEL = "clean\x1b[31m\n## Forged: All Functions Safe"

    def test_ledger_counts_cannot_inject_markdown(
            self, tmp_path: Path) -> None:
        # The ledger's counts block is foreign — hand-edited string
        # values must not smuggle terminal sequences or markdown
        # headings through the summary lines.
        _make_ledger(tmp_path, [_row()], counts={
            "rows": self.HOSTILE_ROWS,
            "by_class": {"elf-linux": self.HOSTILE_CLASS_N},
        })
        md = render_markdown(build_report(tmp_path))
        assert "\x1b" not in md
        assert "\x07" not in md
        assert "\n# ALL CLEAN" not in md
        assert "\n## Attestation" not in md

    def test_ledger_counts_cannot_inject_terminal(
            self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()],
                     counts={"rows": self.HOSTILE_ROWS})
        joined = "\n".join(
            render_summary_lines(build_report(tmp_path)))
        assert "\x1b" not in joined
        assert "\x07" not in joined
        assert "\n# ALL CLEAN" not in joined

    def test_forged_journal_label_renders_escaped(
            self, tmp_path: Path) -> None:
        # append_entry never validates verdict labels — a forged
        # label must render ESCAPED, never title-cased raw into a
        # heading; the known vocabulary keeps Title Case.
        _make_ledger(tmp_path, [_row()])
        _journal(tmp_path, ART, [("a.c", "f", "clean"),
                                 ("a.c", "g", self.HOSTILE_LABEL)])
        md = render_markdown(build_report(tmp_path))
        assert "\x1b" not in md
        assert "\n## Forged" not in md
        assert "Clean 1" in md

    def test_forged_record_label_renders_escaped(
            self, tmp_path: Path) -> None:
        # Same for labels arriving via the chain verdict record's
        # journal_verdicts keys (the at-verdict-time line).
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            attesting=False,
            journal_verdicts={self.HOSTILE_LABEL: 2}))
        md = render_markdown(build_report(tmp_path))
        assert "\x1b" not in md
        assert "\n## Forged" not in md

    def test_title_case_never_mangles_escape_markers(
            self, tmp_path: Path) -> None:
        # N6 ordering: case change BEFORE escaping. Escaping first
        # would let str.title() rewrite the \xHH markers themselves
        # (\x1b -> \X1B), corrupting the sanitiser's own encoding.
        _make_ledger(tmp_path, [_row()], residuals=[
            {"kind": "member_skipped\x1b[31m",
             "message": "quoted member"}])
        md = render_markdown(build_report(tmp_path))
        assert "\\x1b" in md
        assert "\\X1b" not in md and "\\X1B" not in md


# ── record prose containment (SF-5) ─────────────────────────────────

class TestRecordProseContainment:
    def test_clean_bill_prose_never_rendered(self,
                                             tmp_path: Path) -> None:
        # A record whose prose claims a clean bill while the chain
        # did not attest must not get its prose into the rendering —
        # every rendered wording is derived from the computed status.
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            attesting=False,
            wording="CLEAN BILL: full audit complete — no issues"))
        report = build_report(tmp_path)
        entry = _entry(report)
        assert entry["record_wording"].startswith("CLEAN BILL")
        assert "CLEAN BILL" not in entry["wording"]
        md = render_markdown(report)
        assert "CLEAN BILL" not in md
        assert "verdict_table.record_wording" \
            in report["derived_from_target"]
        assert "verdict_table.wording" \
            in report["derived_from_target"]

    def test_attesting_wording_is_derived_too(self,
                                              tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        _plant_verdict(tmp_path, ART, _verdict(
            wording="operator-facing prose the chain wrote"))
        entry = _entry(build_report(tmp_path))
        assert entry["attestation"] == ATTESTING
        assert entry["wording"] == (
            "attested at T3 — attesting claim re-verified from the "
            "record's own fields")
        assert entry["record_wording"] == (
            "operator-facing prose the chain wrote")


# ── survivors + verified outcomes ────────────────────────────────────

class TestSurvivors:
    def test_collected_across_chains(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row(), _row(ART2)])
        _plant_survivors(tmp_path, ART, [
            {"file": "binary:app", "function": "gets_len",
             "run": "audit"}])
        _plant_survivors(tmp_path, ART2, [
            {"file": "binary:lib", "function": "parse_hdr",
             "run": "audit-rereview"}])
        report = build_report(tmp_path)
        assert report["survivors"]["total"] == 2
        ids = {s["artifact_id"] for s in report["survivors"]["listed"]}
        assert ids == {ART, ART2}

    def test_bound_states_total(self, tmp_path: Path,
                                monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(report_mod, "_MAX_SURVIVORS_JSON", 2)
        _make_ledger(tmp_path, [_row()])
        _plant_survivors(tmp_path, ART, [
            {"file": "f", "function": f"fn{i}", "run": "audit"}
            for i in range(5)])
        report = build_report(tmp_path)
        assert report["survivors"]["total"] == 5
        assert len(report["survivors"]["listed"]) == 2
        md = render_markdown(report)
        assert "… 3 more in `engagement-report.json`." in md

    def test_malformed_handoff_declared(self, tmp_path: Path) -> None:
        # PN-3: a handoff that EXISTS but is not a survivors document
        # must never render as a silent "0 survivors" — the chain
        # wrote findings this report could not read.
        _make_ledger(tmp_path, [_row()])
        chain_dir = chain_dir_for(tmp_path, ART)
        chain_dir.mkdir(parents=True)
        save_json(chain_dir / SURVIVORS_FILENAME, ["not", "a", "doc"])
        report = build_report(tmp_path)
        assert report["survivors"]["total"] == 0
        assert report["survivors"]["degraded"] == [
            {"artifact_id": ART, "reason": "survivors_malformed"}]
        md = render_markdown(report)
        assert "Handoff degraded for" in md
        assert "Survivors Malformed" in md

    def test_unparseable_handoff_declared(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        chain_dir = chain_dir_for(tmp_path, ART)
        chain_dir.mkdir(parents=True)
        (chain_dir / SURVIVORS_FILENAME).write_text(
            "{not json", encoding="utf-8")
        report = build_report(tmp_path)
        assert report["survivors"]["degraded"] == [
            {"artifact_id": ART, "reason": "survivors_unloadable"}]

    def test_survivor_list_wrong_shape_declared(
            self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        chain_dir = chain_dir_for(tmp_path, ART)
        chain_dir.mkdir(parents=True)
        save_json(chain_dir / SURVIVORS_FILENAME,
                  {"survivors": "none"})
        report = build_report(tmp_path)
        assert report["survivors"]["degraded"] == [
            {"artifact_id": ART, "reason": "survivors_malformed"}]

    def test_absent_handoff_stays_silent(self, tmp_path: Path) -> None:
        # No handoff file at all = that chain handed nothing off —
        # not a degradation.
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        assert report["survivors"]["degraded"] == []
        assert "Handoff degraded" not in render_markdown(report)


class TestVerifiedOutcomes:
    def test_consumed_from_landed_export(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        outcomes = report["verified_outcomes"]
        assert outcomes["consumed"] is True
        assert isinstance(outcomes["count"], int)

    def test_unloadable_backend_declared(
            self, tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch) -> None:
        import core.labeled_attempts.view as view_mod

        def _boom(_: Any) -> Any:
            raise RuntimeError("backend down")

        monkeypatch.setattr(view_mod, "collect_outcomes", _boom)
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        assert report["verified_outcomes"] == {
            "consumed": False, "reason": "backend_unavailable"}


# ── residual map + policy block ──────────────────────────────────────

class TestResidualMap:
    def test_residuals_parked_collisions_amendments(
            self, tmp_path: Path) -> None:
        _make_ledger(
            tmp_path,
            [_row(status={"state": "parked"}), _row(ART2)],
            residuals=[{"kind": "member_skipped",
                        "message": "nested archive depth"}],
            collisions=[{"anchor": "ab" * 8, "paths": ["a", "b"]}],
            policy_amendments=[{"at": "2026-01-01T00:00:00+00:00",
                                "kind": "envelope_raise"}],
            policy={"park": {"reason": "budget"},
                    "envelope": {"max_usd": 5.0}},
        )
        report = build_report(tmp_path)
        residual = report["residual_map"]
        assert residual["ledger_residuals_total"] == 1
        assert residual["identity_collisions"] == 1
        assert residual["parked_artifacts"] == [ART]
        assert report["policy"]["engagement_parked"] is True
        assert report["policy"]["amendment_count"] == 1
        md = render_markdown(report)
        assert "Engagement policy: Parked, 1 amendment(s)" in md

    def test_not_parked_without_park_record(self,
                                            tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        assert report["policy"]["engagement_parked"] is False
        assert "Not Parked" in render_markdown(report)


# ── rendering: escaping, style, bounds, determinism ──────────────────

HOSTILE = "bin/ap\x1b]0;pwned\x07p|`x`"


class TestEscaping:
    def _hostile_report(self, tmp_path: Path) -> dict[str, Any]:
        _make_ledger(
            tmp_path,
            [_row(path=HOSTILE)],
            target_root="/t\x1b[31mgt",
            residuals=[{"kind": "member_skipped",
                        "message": "bad member \x1b[2Jname|here"}],
        )
        _plant_survivors(tmp_path, ART, [
            {"file": HOSTILE, "function": "fn\x1b[0m|`y`",
             "run": "audit"}])
        return build_report(tmp_path)

    def test_json_keeps_raw_with_manifest(self, tmp_path: Path) -> None:
        report = self._hostile_report(tmp_path)
        # Raw values stay in the document; the manifest names every
        # target-derived path so consumers escape at render.
        assert report["verdict_table"][0]["path"] == HOSTILE
        manifest = report["derived_from_target"]
        assert "verdict_table.path" in manifest
        assert "survivors.listed.function" in manifest
        assert "residual_map.ledger_residuals.message" in manifest

    def test_markdown_escapes_every_foreign_value(
            self, tmp_path: Path) -> None:
        md = render_markdown(self._hostile_report(tmp_path))
        assert "\x1b" not in md
        assert "\x07" not in md
        # md_inline entity-escapes pipes so hostile values cannot
        # break out of table cells.
        assert "&#124;" in md

    def test_terminal_summary_escapes(self, tmp_path: Path) -> None:
        lines = render_summary_lines(self._hostile_report(tmp_path))
        joined = "\n".join(lines)
        assert "\x1b" not in joined
        assert "\\x1b" in joined  # escaped, not elided

    def test_provenance_stamped_untrusted(self, tmp_path: Path) -> None:
        report = self._hostile_report(tmp_path)
        prov = report["provenance"]
        assert prov["generator"] == "engage-report"
        assert prov["untrusted"] is True


class TestOutputStyle:
    def test_title_case_never_all_caps(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row(**{"format_tier": "core"})])
        _plant_verdict(tmp_path, ART, _verdict(
            journal_verdicts={"finding": 1}, attesting=False))
        # Second row keeps the sub-full not-engaged path in play.
        md = render_markdown(build_report(tmp_path))
        assert "Findings Present" in md
        assert "FINDINGS_PRESENT" not in md
        assert "NOT_ENGAGED" not in md
        assert "ATTESTING" not in md  # covers NON_ATTESTING too

    def test_no_red_green_indicators(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        md = render_markdown(build_report(tmp_path))
        assert "\U0001f534" not in md and "\U0001f7e2" not in md

    def test_next_steps_name_libexec_routes(self,
                                            tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        md = render_markdown(build_report(tmp_path))
        assert "libexec/raptor-render-diagrams" in md
        assert "libexec/raptor-coverage-summary" in md


class TestBounds:
    def test_table_rows_elided_with_count(
            self, tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(report_mod, "_MAX_TABLE_ROWS_MD", 2)
        rows = [_row(f"sha256-{i:08x}") for i in range(5)]
        _make_ledger(tmp_path, rows)
        md = render_markdown(build_report(tmp_path))
        assert "… 3 more row(s) in `engagement-report.json`." in md

    def test_wording_list_elided(self, tmp_path: Path,
                                 monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(report_mod, "_MAX_WORDING_MD", 1)
        _make_ledger(tmp_path, [_row(), _row(ART2)])
        md = render_markdown(build_report(tmp_path))
        assert "… 1 more in `engagement-report.json`." in md

    def test_residuals_elided(self, tmp_path: Path,
                              monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(report_mod, "_MAX_RESIDUALS_MD", 1)
        _make_ledger(tmp_path, [_row()], residuals=[
            {"kind": "member_skipped", "message": f"m{i}"}
            for i in range(3)])
        md = render_markdown(build_report(tmp_path))
        assert "… 2 more in `engagement-report.json`." in md

    def test_no_elision_under_bounds(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        md = render_markdown(build_report(tmp_path))
        assert "more row(s)" not in md


class TestDeterminism:
    def test_build_deterministic_modulo_timestamps(
            self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row(), _row(ART2)])
        _plant_verdict(tmp_path, ART, _verdict())
        _journal(tmp_path, ART, [("binary:app", "main", "clean")])
        one = build_report(tmp_path)
        two = build_report(tmp_path)
        for doc in (one, two):
            doc.pop("generated_at")
            doc.pop("provenance")
        assert one == two

    def test_render_deterministic(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        assert render_markdown(report) == render_markdown(report)


# ── writers ──────────────────────────────────────────────────────────

class TestWriters:
    def test_write_report_round_trips(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        json_path, md_path = write_report(tmp_path)
        assert json_path == tmp_path / REPORT_JSON_FILENAME
        assert md_path == tmp_path / REPORT_MD_FILENAME
        doc = load_json(json_path)
        assert doc["schema"] == "engagement-report/1"
        assert md_path.read_text(
            encoding="utf-8") == render_markdown(doc)

    def test_prebuilt_report_not_rebuilt(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        report = build_report(tmp_path)
        (tmp_path / LEDGER_FILENAME).unlink()
        json_path, _ = write_report(tmp_path, report)
        assert load_json(json_path)["counts"]["rows"] == 1

    def test_no_temp_droppings(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        write_report(tmp_path)
        names = {p.name for p in tmp_path.iterdir()}
        # The artifact_lock's lock file is expected house residue;
        # nothing ELSE (no orphaned tempfiles) may remain.
        assert names == {LEDGER_FILENAME, REPORT_JSON_FILENAME,
                         REPORT_MD_FILENAME,
                         f"{REPORT_JSON_FILENAME}.lock"}


# ── launcher CLI ─────────────────────────────────────────────────────

_REPO = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO / "libexec" / "raptor-engage-report"


def _run_cli(*args: str, trusted: bool = True,
             ) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDECODE", "_RAPTOR_TRUSTED")}
    if trusted:
        env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(
        [sys.executable, str(_LAUNCHER), *args],
        capture_output=True, text=True, env=env, timeout=120,
        check=False)


class TestLauncherCLI:
    def test_untrusted_refused(self, tmp_path: Path) -> None:
        proc = _run_cli(str(tmp_path), trusted=False)
        assert proc.returncode == 2
        assert "internal dispatch script" in proc.stderr

    def test_missing_dir_rc2(self, tmp_path: Path) -> None:
        proc = _run_cli(str(tmp_path / "nope"))
        assert proc.returncode == 2
        assert "not a directory" in proc.stderr

    def test_no_ledger_rc2(self, tmp_path: Path) -> None:
        proc = _run_cli(str(tmp_path))
        assert proc.returncode == 2
        assert "no engagement ledger" in proc.stderr

    def test_json_mode_ascii_only(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row(path=HOSTILE)])
        proc = _run_cli(str(tmp_path), "--json")
        assert proc.returncode == 0
        assert proc.stdout.isascii()
        doc = json.loads(proc.stdout)
        assert doc["schema"] == "engagement-report/1"
        # JSON mode prints only; nothing written.
        assert not (tmp_path / REPORT_JSON_FILENAME).exists()

    def test_stdout_mode_prints_markdown(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row(path=HOSTILE)])
        proc = _run_cli(str(tmp_path), "--stdout")
        assert proc.returncode == 0
        assert proc.stdout.startswith("# Engagement Report")
        assert "\x1b" not in proc.stdout
        assert not (tmp_path / REPORT_MD_FILENAME).exists()

    def test_default_writes_both(self, tmp_path: Path) -> None:
        _make_ledger(tmp_path, [_row()])
        proc = _run_cli(str(tmp_path))
        assert proc.returncode == 0
        assert (tmp_path / REPORT_JSON_FILENAME).is_file()
        assert (tmp_path / REPORT_MD_FILENAME).is_file()
        assert "Engagement report — target" in proc.stdout
        assert "wrote " in proc.stdout
