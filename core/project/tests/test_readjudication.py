"""Tests for the contradiction-triggered re-adjudication queue.

The queue preserves the cross-adjudication contradiction signal that
the merge fold and the /validate import used to destroy silently.
Both directions of every class are pinned throughout: the signal IS
emitted for a later claim against a recorded disproof and for a later
disproof against a confirmed-tier verdict, and it is NOT emitted for
ordinary validation progression (hypothesis first, disproof later) or
for intra-source pairs — and nothing anywhere overturns a verdict.
"""

import json
import os
from pathlib import Path

from core.json import load_jsonl
from core.project.merge import merge_findings, merge_runs
from core.project.readjudication import (
    CONFIRMED_TIER_STATUSES,
    QUEUE_FILENAME,
    RECORD_CAP,
    SHAPE_CLAIM_AFTER_DISPROOF,
    SHAPE_OVERTURN,
    SITE_RECORD_CAP,
    build_queue_record,
    contradicted_disproof_count,
    detect_contradictions,
    detect_project_contradictions,
    is_confirmed_tier,
    is_disproof,
    queued_count,
    record_shape,
    shape_counts,
    site_key,
    suppressed_count,
    write_queue,
)


def _claim(**overrides) -> dict:
    base = {
        "id": "SCAN-7",
        "file": "src/parse.c",
        "function": "parse_header",
        "line": 42,
        "vuln_type": "buffer_overflow",
        "cwe_id": "CWE-787",
        "status": "not_disproven",
        "description": "unchecked length copy",
    }
    base.update(overrides)
    return base


def _disproof(**overrides) -> dict:
    base = {
        "id": "FIND-1",
        "file": "src/parse.c",
        "function": "parse_header",
        "line": 40,
        "vuln_type": "buffer_overflow",
        "cwe_id": "CWE-787",
        "status": "disproven",
        "disproved_because": {
            "investigated": "traced the length check",
            "conclusion": "len is clamped upstream",
            "would_reconsider_if": "a second entry path bypasses the clamp",
        },
    }
    base.update(overrides)
    return base


class TestPredicates:

    def test_disproof_statuses(self):
        for status in ("disproven", "ruled_out", "false_positive",
                       "dead_code", "mitigated", "unreachable",
                       "test_code"):
            assert is_disproof({"status": status})

    def test_final_status_wins(self):
        assert is_disproof(
            {"status": "not_disproven", "final_status": "ruled_out"})

    def test_ruling_ruled_out_counts(self):
        assert is_disproof(
            {"status": "pending", "ruling": {"status": "ruled_out"}})

    def test_positive_claims_are_not_disproofs(self):
        assert not is_disproof({"status": "not_disproven"})
        assert not is_disproof({"status": "exploitable"})
        assert not is_disproof({})  # status-less scanner row = a claim
        # Non-dict ruling must not crash (LLM-authored shapes).
        assert not is_disproof({"ruling": "confirmed"})

    def test_site_key_function_level(self):
        # Same function, different lines → same site (group_key axis).
        a = site_key({"file": "a.c", "function": "f", "line": 1})
        b = site_key({"file": "a.c", "function": "f", "line": 99})
        assert a == b == ("fn", "a.c", "f")

    def test_site_key_line_fallback_and_none(self):
        assert site_key({"file": "a.c", "line": 7}) == ("line", "a.c", 7)
        assert site_key({"function": "f"}) is None  # no file → no site
        assert site_key({"file": "a.c"}) is None    # no function, no line

    def test_site_key_file_path_alias(self):
        # Orchestrated /agentic rows carry file_path, not file.
        assert site_key({"file_path": "a.c", "function": "f"}) == (
            "fn", "a.c", "f")


class TestDetectContradictions:

    def test_later_claim_queues_against_recorded_disproof(self):
        records = detect_contradictions([
            ("run-1", [_disproof()]),
            ("run-2", [_claim()]),
        ])
        assert queued_count(records) == 1
        rec = records[0]
        assert rec["action"] == "queued"
        assert rec["site"]["file"] == "src/parse.c"
        assert rec["site"]["function"] == "parse_header"
        assert rec["new_claim"]["source"] == "run-2"
        assert rec["new_claim"]["status"] == "not_disproven"
        assert rec["disproof"]["source"] == "run-1"
        assert rec["disproof"]["status"] == "disproven"
        # The disproof's own reconsideration condition rides the record.
        assert rec["disproof"]["would_reconsider_if"] == (
            "a second entry path bypasses the clamp")
        assert rec["mechanism_match"] is True

    def test_reverse_order_is_progression_not_contradiction(self):
        # Hypothesis-tier claim first, disproof later = normal
        # validation flow (the overturn shape only fires when the
        # prior claim is confirmed-tier — see TestOverturnDirection).
        records = detect_contradictions([
            ("run-1", [_claim()]),
            ("run-2", [_disproof()]),
        ])
        assert records == []

    def test_same_source_pair_does_not_queue(self):
        # One run's own claim + disproof is intra-run progression.
        records = detect_contradictions([
            ("run-1", [_claim(), _disproof()]),
        ])
        assert records == []

    def test_mechanism_mismatch_noted_not_gated(self):
        records = detect_contradictions([
            ("run-1", [_disproof()]),
            ("run-2", [_claim(vuln_type="format_string",
                              cwe_id="CWE-134")]),
        ])
        assert queued_count(records) == 1
        rec = records[0]
        assert rec["mechanism_match"] is False
        assert "outside the disproof's recorded scope" in rec["mechanism_note"]

    def test_mechanism_unknown_when_one_side_silent(self):
        records = detect_contradictions([
            ("run-1", [_disproof(vuln_type=None, cwe_id=None)]),
            ("run-2", [_claim()]),
        ])
        assert records[0]["mechanism_match"] is None
        assert "mechanism_note" not in records[0]

    def test_latest_disproof_quoted_with_count(self):
        records = detect_contradictions([
            ("run-1", [_disproof(id="FIND-1")]),
            ("run-2", [_disproof(id="FIND-2", status="ruled_out")]),
            ("run-3", [_claim()]),
        ])
        assert queued_count(records) == 1
        rec = records[0]
        assert rec["disproof"]["id"] == "FIND-2"
        assert rec["prior_disproofs_at_site"] == 2

    def test_pairs_deduplicated(self):
        # Two identical-mechanism claims from the same source at the
        # same site collapse to one record.
        records = detect_contradictions([
            ("run-1", [_disproof()]),
            ("run-2", [_claim(id="SCAN-7"), _claim(id="SCAN-8", line=45)]),
        ])
        assert queued_count(records) == 1

    def test_record_cap_announced_not_silent(self):
        disproofs = [
            _disproof(id=f"FIND-{i}", file=f"f{i}.c", function=f"fn{i}")
            for i in range(RECORD_CAP + 3)
        ]
        claims = [
            _claim(id=f"SCAN-{i}", file=f"f{i}.c", function=f"fn{i}")
            for i in range(RECORD_CAP + 3)
        ]
        records = detect_contradictions([
            ("run-1", disproofs), ("run-2", claims),
        ])
        assert queued_count(records) == RECORD_CAP
        marker = records[-1]
        assert marker["action"] == "truncated"
        assert marker["suppressed"] == 3
        assert "3" in marker["note"]
        assert suppressed_count(records) == 3

    def test_site_cap_flood_cannot_evict_other_sites(self):
        # One matching site flooded with mechanism-varied claims
        # (vuln_type is attacker-influenced free text) must never
        # occupy the global cap: real contradictions at OTHER sites,
        # arriving in a LATER source, must survive.
        disproofs = [
            _disproof(id="D-h", file="hostile.c", function="h"),
            _disproof(id="D-1", file="real_1.c", function="f1"),
            _disproof(id="D-2", file="real_2.c", function="f2"),
        ]
        flood = [
            _claim(id=f"H-{i}", file="hostile.c", function="h",
                   vuln_type=f"vt-{i}", cwe_id=None)
            for i in range(10_000)
        ]
        real = [
            _claim(id="R-1", file="real_1.c", function="f1"),
            _claim(id="R-2", file="real_2.c", function="f2"),
        ]
        records = detect_contradictions([
            ("run-old", disproofs), ("run-hostile", flood),
            ("run-new", real),
        ])
        survivors = {
            r["new_claim"]["id"] for r in records
            if r.get("action") == "queued"
        }
        assert {"R-1", "R-2"} <= survivors
        # The flooded site holds exactly its sub-cap of slots.
        hostile = [r for r in records if r.get("action") == "queued"
                   and r["site"]["file"] == "hostile.c"]
        assert len(hostile) == SITE_RECORD_CAP
        # Every refused record is counted, loudly.
        assert suppressed_count(records) == 10_000 - SITE_RECORD_CAP

    def test_mechanism_entries_capped(self):
        # Uncapped mechanism strings were the one field that bypassed
        # _TEXT_CAP — a 10MB vuln_type must not bloat the record (or
        # the pair-dedup key, which is built from the same set).
        rec = build_queue_record(
            _claim(vuln_type="v" * 10_000_000, cwe_id="CWE-" + "9" * 100_000),
            "s1", _disproof(), "s0",
        )
        assert all(len(m) <= 100 for m in rec["new_claim"]["mechanism"])
        assert len(json.dumps(rec)) < 10_000

    def test_suppressed_count_tolerant_of_hostile_markers(self):
        assert suppressed_count([
            {"action": "truncated", "suppressed": 2},
            {"action": "truncated", "suppressed": "999"},   # str: ignored
            {"action": "truncated", "suppressed": True},    # bool: ignored
            {"action": "truncated"},                        # absent: ignored
            {"action": "queued", "suppressed": 50},         # wrong action
            "junk",
        ]) == 2

    def test_claim_summary_covers_validate_row_fields(self):
        # Real /validate rows carry candidate_reasoning /
        # dataflow_summary, not title/description/message — the
        # summary chain must not render empty on the actual corpus.
        claim = _claim(description=None, title=None)
        del claim["description"]
        claim["candidate_reasoning"] = "unchecked memcpy length"
        rec = build_queue_record(claim, "s1", _disproof(), "s0")
        assert rec["new_claim"]["summary"] == "unchecked memcpy length"

    def test_non_dict_rows_tolerated(self):
        records = detect_contradictions([
            ("run-1", ["junk", _disproof()]),
            ("run-2", [None, _claim()]),
        ])
        assert queued_count(records) == 1

    def test_free_text_fields_capped(self):
        long_text = "x" * 5000
        rec = build_queue_record(
            _claim(description=long_text), "s1",
            _disproof(disproved_because={
                "conclusion": long_text,
                "would_reconsider_if": long_text,
            }),
            "s0",
        )
        assert len(rec["new_claim"]["summary"]) <= 300
        assert len(rec["disproof"]["reason"]) <= 500
        assert len(rec["disproof"]["would_reconsider_if"]) <= 500

    def test_contradicted_disproof_count_distinct(self):
        # Two claims (different mechanisms) against ONE disproof:
        # 2 queued signals, 1 contradicted disproof.
        records = detect_contradictions([
            ("run-1", [_disproof()]),
            ("run-2", [_claim(),
                       _claim(id="SCAN-9", vuln_type="integer_overflow",
                              cwe_id="CWE-190")]),
        ])
        assert queued_count(records) == 2
        assert contradicted_disproof_count(records) == 1


class TestWriteQueue:

    def test_fresh_write_is_idempotent(self, tmp_path):
        records = detect_contradictions([
            ("run-1", [_disproof()]), ("run-2", [_claim()]),
        ])
        path = write_queue(tmp_path, records)
        assert path is not None and path.name == QUEUE_FILENAME
        write_queue(tmp_path, records)  # re-run: fresh, not appended
        loaded = load_jsonl(path)
        assert len(loaded) == 1
        assert loaded[0]["action"] == "queued"

    def test_empty_detection_removes_stale_queue(self, tmp_path):
        path = tmp_path / QUEUE_FILENAME
        path.write_text('{"action":"queued"}\n')
        assert write_queue(tmp_path, []) is None
        assert not path.exists()

    def test_symlinked_queue_path_refused(self, tmp_path):
        victim = tmp_path / "victim.txt"
        victim.write_text("keep")
        link = tmp_path / QUEUE_FILENAME
        os.symlink(victim, link)
        records = [build_queue_record(_claim(), "s1", _disproof(), "s0")]
        assert write_queue(tmp_path, records) is None
        assert victim.read_text() == "keep"  # never written through
        assert link.is_symlink()             # plant left as evidence
        # Empty detection must not unlink through the symlink either.
        assert write_queue(tmp_path, []) is None
        assert victim.read_text() == "keep"

    def test_fifo_queue_path_refused_without_blocking(self, tmp_path):
        # A pre-planted FIFO is a plantable hang: an open on it blocks
        # until a peer appears. The lstat gate must refuse WITHOUT
        # opening — if this regresses, the test itself hangs, which is
        # the loudest possible signal.
        fifo = tmp_path / QUEUE_FILENAME
        os.mkfifo(fifo)
        records = [build_queue_record(_claim(), "s1", _disproof(), "s0")]
        assert write_queue(tmp_path, records) is None
        assert fifo.exists()  # plant left as evidence, never opened
        # Empty-records arm: same gate, no unlink through the special.
        assert write_queue(tmp_path, []) is None
        assert fifo.exists()

    def test_write_is_atomic_no_tempfile_debris(self, tmp_path):
        # Atomic tempfile+rename: concurrent merged-view regenerations
        # replace the file whole. The visible contract here: the write
        # lands complete and no tempfile debris survives.
        records = [build_queue_record(_claim(), "s1", _disproof(), "s0")]
        path = write_queue(tmp_path, records)
        assert path is not None
        assert len(load_jsonl(path)) == 1
        assert not list(tmp_path.glob(".~readj-*"))


def _make_run(base: Path, name: str, findings: list) -> Path:
    run_dir = base / name
    run_dir.mkdir()
    (run_dir / "findings.json").write_text(json.dumps(findings))
    return run_dir


class TestProjectDetection:

    def test_ordered_run_dirs(self, tmp_path):
        a = _make_run(tmp_path, "run-a", [_disproof()])
        b = _make_run(tmp_path, "run-b", [_claim()])
        records = detect_project_contradictions([a, b])
        assert queued_count(records) == 1
        assert records[0]["disproof"]["source"] == "run-a"
        assert records[0]["new_claim"]["source"] == "run-b"

    def test_imported_run_labelled(self, tmp_path):
        a = _make_run(tmp_path, "run-a", [_disproof()])
        b = _make_run(tmp_path, "run-b", [_claim()])
        (b / ".raptor-imported.json").write_text('{"imported": true}')
        records = detect_project_contradictions([a, b])
        # Unsigned-archive provenance is visible on the record — the
        # claim's status is attacker-selectable and readers must be
        # able to weigh the contradiction accordingly.
        assert records[0]["new_claim"]["source"] == "run-b (imported)"


class TestMergeRunsIntegration:

    def test_merge_emits_queue_without_changing_fold(self, tmp_path):
        a = _make_run(tmp_path, "run-a", [_disproof()])
        b = _make_run(tmp_path, "run-b", [_claim()])
        out = tmp_path / "merged"
        stats = merge_runs([a, b], out)
        # Fold behaviour unchanged: the disproof still wins the view.
        merged = merge_findings([a, b])
        by_site = {(f.get("file"), f.get("function")): f for f in merged}
        # (file, function, line, vuln_type) keys differ, both rows
        # survive the raw merge; the point is no status was rewritten.
        assert all(
            f.get("status") in ("disproven", "not_disproven")
            for f in merged
        )
        assert stats["readjudication_queued"] == 1
        loaded = load_jsonl(out / QUEUE_FILENAME)
        assert queued_count(loaded) == 1
        assert by_site  # merged view exists alongside the queue

    def test_merge_without_contradictions_writes_nothing(self, tmp_path):
        a = _make_run(tmp_path, "run-a", [_claim()])
        out = tmp_path / "merged"
        stats = merge_runs([a], out)
        assert stats["readjudication_queued"] == 0
        assert not (out / QUEUE_FILENAME).exists()


class TestReportSection:

    def test_section_rendered_with_counts_and_condition(self):
        from core.project.report import render_grouped_findings_markdown
        records = detect_contradictions([
            ("run-1", [_disproof()]), ("run-2", [_claim()]),
        ])
        md = render_grouped_findings_markdown(
            [_claim()], "proj", readjudication=records)
        assert "## Re-adjudication queue" in md
        assert ("1 recorded disproof(s) contradicted by new signals — "
                "re-adjudication queue") in md
        assert "a second entry path bypasses the clamp" in md
        assert QUEUE_FILENAME in md

    def test_truncation_restated_in_report_section(self):
        from core.project.report import render_grouped_findings_markdown
        records = detect_contradictions([
            ("run-1", [_disproof()]), ("run-2", [_claim()]),
        ])
        records.append({"kind": "readjudication", "action": "truncated",
                        "suppressed": 7, "note": "caps"})
        md = render_grouped_findings_markdown(
            [_claim()], "proj", readjudication=records)
        # A capped queue must never render as complete.
        assert "7 further contradiction(s) not recorded" in md
        assert "bounded sample" in md

    def test_no_section_without_records(self):
        from core.project.report import render_grouped_findings_markdown
        md = render_grouped_findings_markdown([_claim()], "proj")
        assert "Re-adjudication" not in md

    def test_hostile_record_text_sanitised(self):
        from core.project.report import render_grouped_findings_markdown
        records = detect_contradictions([
            ("run-1", [_disproof(disproved_because={
                "would_reconsider_if": "# fake heading\n\x1b[31mANSI",
            })]),
            ("run-2\n# injected", [_claim()]),
        ])
        md = render_grouped_findings_markdown(
            [_claim()], "proj", readjudication=records)
        # Finding-derived text cannot mint headings or carry raw ESC.
        assert "\n# fake heading" not in md
        assert "\n# injected" not in md
        assert "\x1b" not in md


class TestConfirmedTierPredicate:

    def test_confirmed_tier_statuses(self):
        for status in CONFIRMED_TIER_STATUSES:
            assert is_confirmed_tier(_claim(status=status)), status

    def test_hypothesis_and_disproof_statuses_are_not_confirmed_tier(self):
        # poc_success is an intermediate pipeline marker (ranked below
        # the disproof family by the merge vocabulary), not a verdict.
        for status in ("not_disproven", "poc_success", "suspicious",
                       "dark", "disproven", "ruled_out", ""):
            assert not is_confirmed_tier(_claim(status=status)), status

    def test_ruling_ruled_out_wins_the_overlap(self):
        # status claims confirmed, ruling records ruled_out — the row
        # is a disproof, never an overturnable claim.
        row = _claim(status="confirmed", ruling={"status": "ruled_out"})
        assert is_disproof(row)
        assert not is_confirmed_tier(row)


class TestOverturnDirection:
    """Seam: a later run's disproof against an earlier CONFIRMED-TIER
    verdict is overturn-shaped and queues; a later disproof over a
    mere hypothesis is ordinary validation progression and stays
    unqueued. Nothing is ever auto-overturned."""

    def test_disproof_after_confirmed_queues(self):
        records = detect_contradictions([
            ("run-1", [_claim(status="confirmed")]),
            ("run-2", [_disproof(status="ruled_out")]),
        ])
        assert queued_count(records) == 1
        rec = records[0]
        assert rec["shape"] == SHAPE_OVERTURN
        assert rec["action"] == "queued"
        assert rec["new_claim"]["source"] == "run-1"
        assert rec["new_claim"]["status"] == "confirmed"
        assert rec["disproof"]["source"] == "run-2"
        assert rec["disproof"]["status"] == "ruled_out"
        assert rec["mechanism_match"] is True

    def test_every_confirmed_tier_status_queues(self):
        for status in sorted(CONFIRMED_TIER_STATUSES):
            records = detect_contradictions([
                ("run-1", [_claim(status=status)]),
                ("run-2", [_disproof()]),
            ])
            assert queued_count(records) == 1, status
            assert records[0]["shape"] == SHAPE_OVERTURN

    def test_hypothesis_tier_prior_stays_unqueued(self):
        # Negative control: /validate disproving an /audit hypothesis
        # (or an unconcluded poc_success) is the system working —
        # queueing it would mint a record per routine validation pass.
        for status in ("not_disproven", "poc_success", "suspicious",
                       "dark"):
            records = detect_contradictions([
                ("run-1", [_claim(status=status)]),
                ("run-2", [_disproof()]),
            ])
            assert records == [], status

    def test_same_source_disproof_after_confirmed_not_queued(self):
        # In-pipeline refinement inside ONE source never queues here.
        records = detect_contradictions([
            ("run-1", [_claim(status="confirmed"), _disproof()]),
        ])
        assert records == []

    def test_ruling_ruled_out_prior_never_indexes_as_confirmed(self):
        row = _claim(status="confirmed", ruling={"status": "ruled_out"})
        records = detect_contradictions([
            ("run-1", [row]),
            ("run-2", [_disproof()]),
        ])
        assert records == []

    def test_latest_confirmed_quoted_with_count(self):
        records = detect_contradictions([
            ("run-1", [_claim(id="C-1", status="confirmed")]),
            ("run-2", [_claim(id="C-2", status="exploitable")]),
            ("run-3", [_disproof()]),
        ])
        assert queued_count(records) == 1
        rec = records[0]
        assert rec["new_claim"]["id"] == "C-2"
        assert rec["prior_confirmed_at_site"] == 2

    def test_shape_stamped_on_claim_after_disproof_records(self):
        records = detect_contradictions([
            ("run-1", [_disproof()]),
            ("run-2", [_claim()]),
        ])
        assert records[0]["shape"] == SHAPE_CLAIM_AFTER_DISPROOF
        assert record_shape(records[0]) == SHAPE_CLAIM_AFTER_DISPROOF

    def test_record_shape_tolerates_missing_field(self):
        # Pre-shape queue files read as the legacy class.
        assert record_shape({"action": "queued"}) == \
            SHAPE_CLAIM_AFTER_DISPROOF

    def test_overturn_respects_site_cap_announced(self):
        # Mechanism-varied disproofs flooding one confirmed site are
        # bounded by the shared per-site cap, announced.
        flood = [
            _disproof(id=f"D-{i}", vuln_type=f"type-{i}",
                      cwe_id=f"CWE-{900 + i}")
            for i in range(SITE_RECORD_CAP + 4)
        ]
        records = detect_contradictions([
            ("run-1", [_claim(status="confirmed")]),
            ("run-2", flood),
        ])
        assert queued_count(records) == SITE_RECORD_CAP
        assert suppressed_count(records) == 4

    def test_shapes_share_the_site_cap(self):
        # One flooded site cannot annex extra headroom by splitting
        # its records across the two directions.
        claims = [
            _claim(id=f"C-{i}", vuln_type=f"ctype-{i}",
                   cwe_id=f"CWE-{100 + i}")
            for i in range(3)
        ]
        disproofs = [
            _disproof(id=f"D-{i}", vuln_type=f"dtype-{i}",
                      cwe_id=f"CWE-{200 + i}")
            for i in range(3)
        ]
        records = detect_contradictions([
            ("run-1", [_disproof(id="D-base"),
                       _claim(id="C-base", status="confirmed")]),
            ("run-2", claims + disproofs),
        ])
        assert queued_count(records) == SITE_RECORD_CAP
        assert suppressed_count(records) == 1

    def test_headline_count_excludes_overturns(self):
        # contradicted_disproof_count counts contradicted DISPROOFS
        # only; the overturn record's disproof slot holds the NEW
        # signal, not a contradicted disposition.
        records = detect_contradictions([
            ("run-1", [_claim(status="confirmed")]),
            ("run-2", [_disproof()]),
        ])
        assert contradicted_disproof_count(records) == 0
        assert shape_counts(records) == {SHAPE_OVERTURN: 1}
