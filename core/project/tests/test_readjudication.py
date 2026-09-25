"""Tests for the contradiction-triggered re-adjudication queue.

The queue preserves the disproof-vs-later-claim contradiction signal
that the merge fold and the /validate import used to destroy silently.
Two directions are pinned throughout: the signal IS emitted for a
later claim against a recorded disproof, and it is NOT emitted for
ordinary validation progression (claim first, disproof later) or for
intra-source pairs — and nothing anywhere overturns a verdict.
"""

import json
import os
from pathlib import Path

from core.json import load_jsonl
from core.project.merge import merge_findings, merge_runs
from core.project.readjudication import (
    QUEUE_FILENAME,
    RECORD_CAP,
    build_queue_record,
    contradicted_disproof_count,
    detect_contradictions,
    detect_project_contradictions,
    is_disproof,
    queued_count,
    site_key,
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
        # Claim first, disproof later = normal validation flow.
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
        assert "3" in marker["note"]

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
        # Empty detection must not unlink through the symlink either.
        assert write_queue(tmp_path, []) is None
        assert victim.read_text() == "keep"


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
