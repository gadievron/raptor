"""Coverage-record review credit verifies row provenance.

Coverage records are the second durable review-suppression lane
beside the journal: a ``functions_analysed`` row under a review-grade
tool label removes the named function from the gap fold's review
queue, and the records live in target-writable run/project
directories. Pre-fix the fold plain-credited every named row — and
the legacy ``files{...functions{}}`` shape credited under ANY
non-runtime tool label — so one dropped ``coverage-llm.json`` (or a
``coverage-semgrep.json`` in the legacy shape) silenced review of
every function it named, with no stamp, no verdict and no source
evidence.

These tests invert that PoC at the SEAM (``compute_gaps`` with
planted record dicts), plus the producer half: rows are stamped at
CREATION only (builders, mark CLI), a journal row's coverage
projection inherits the journal row's own MAC tier, and record-level
RMW writers never launder a planted row. Zero LLM calls.
"""

from __future__ import annotations

import json

import pytest

from core.audit.gaps import compute_gaps
from core.coverage import journal_mac
from core.coverage.journal import (
    JOURNAL_FILENAME,
    ReviewJournalEntry,
    append_entry,
    now_iso,
)
from core.coverage.record import build_from_journal
from core.staleness import hash_span

_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}
"""

_ITEM = {
    "name": "check_pw",
    "kind": "function",
    "line_start": 1,
    "line_end": 5,
}


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _write_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "auth.c").write_text(_SOURCE, encoding="utf-8")
    return target


def _checklist(target):
    return {
        "target_path": str(target),
        "files": [{
            "path": "auth.c",
            "language": "c",
            "items": [dict(_ITEM)],
        }],
    }


def _record(tool="llm", rows=None, **extra):
    rec = {"tool": tool, "timestamp": now_iso()}
    if rows is not None:
        rec["functions_analysed"] = rows
    rec.update(extra)
    return rec


def _stamped_row(tool="llm", **over):
    row = {"file": "auth.c", "function": "check_pw"}
    row.update(over)
    token = journal_mac.mint_coverage_row(row, tool)
    assert token, "key must be mintable under the isolated XDG home"
    row[journal_mac.TOKEN_KEY] = token
    return row


def _gap_keys(gaps):
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestPlantedRecords:
    def test_planted_hashless_row_resurfaces(self, tmp_path):
        """The PoC: a dropped coverage-llm.json naming a function
        must NOT retire it from the review queue."""
        target = _write_target(tmp_path)
        planted = _record(rows=[{"file": "auth.c",
                                 "function": "check_pw"}])
        gaps = compute_gaps(_checklist(target), [planted])
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_planted_forged_hash_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        planted = _record(rows=[{"file": "auth.c",
                                 "function": "check_pw",
                                 "hash": "f" * 64}])
        gaps = compute_gaps(_checklist(target), [planted])
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_planted_legacy_files_shape_resurfaces(self, tmp_path):
        """The legacy files{} shape credited under ANY non-runtime
        tool — even semgrep. It earns no review credit now."""
        target = _write_target(tmp_path)
        shape = {"files": {"auth.c": {"functions": {"check_pw": {}}}}}
        for tool in ("semgrep", "llm"):
            gaps = compute_gaps(
                _checklist(target), [_record(tool=tool, **shape)])
            assert "auth.c:check_pw" in _gap_keys(gaps), tool

    def test_stamp_is_the_discriminator(self, tmp_path):
        """IDENTICAL row fields: the stamped row suppresses, the
        planted copy (token stripped) resurfaces."""
        target = _write_target(tmp_path)
        stamped = _stamped_row()
        planted = {k: v for k, v in stamped.items()
                   if k != journal_mac.TOKEN_KEY}
        gaps = compute_gaps(_checklist(target),
                            [_record(rows=[stamped])])
        assert "auth.c:check_pw" not in _gap_keys(gaps)
        gaps = compute_gaps(_checklist(target),
                            [_record(rows=[planted])])
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_token_is_tool_bound(self, tmp_path):
        """A row minted for the scanned-tier understand record must
        not verify when replayed into a review-grade llm record."""
        target = _write_target(tmp_path)
        replayed = _stamped_row(tool="understand")
        gaps = compute_gaps(_checklist(target),
                            [_record(tool="llm", rows=[replayed])])
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_tampered_row_resurfaces(self, tmp_path):
        """Editing a stamped row (upgrading an error status) demotes
        it to the unstamped tier."""
        target = _write_target(tmp_path)
        row = _stamped_row(status="error")
        row["status"] = "clean"
        gaps = compute_gaps(_checklist(target), [_record(rows=[row])])
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestLegacyTolerance:
    def test_unstamped_row_with_exact_hash_keeps_credit(self, tmp_path):
        """Pre-MAC legacy records keep credit behind positive source
        evidence — the journal's tolerant-reader compromise."""
        target = _write_target(tmp_path)
        row = {"file": "auth.c", "function": "check_pw",
               "hash": hash_span(target / "auth.c", 1, 5)}
        gaps = compute_gaps(_checklist(target), [_record(rows=[row])])
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_unstamped_row_with_hash_prefix_resurfaces(self, tmp_path):
        """A strict PREFIX of the canonical span digest
        (``hash_span`` = SHA-256[:12]) is not evidence — the gate is
        exact equality against the freshly computed digest."""
        target = _write_target(tmp_path)
        full = hash_span(target / "auth.c", 1, 5)
        assert len(full) == 12
        row = {"file": "auth.c", "function": "check_pw",
               "hash": full[:8]}
        gaps = compute_gaps(_checklist(target), [_record(rows=[row])])
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_unstamped_finding_class_row_never_hash_credits(
        self, tmp_path,
    ):
        """Finding-class rows are excluded from the hash tier even
        with a CURRENT exact hash — only a verified journal row
        re-imports its finding, so hash credit here would retire the
        function while the claimed finding surfaces nowhere. Same
        rule as the journal fold."""
        target = _write_target(tmp_path)
        for status in ("finding", "suspicious"):
            row = {"file": "auth.c", "function": "check_pw",
                   "status": status,
                   "hash": hash_span(target / "auth.c", 1, 5)}
            gaps = compute_gaps(_checklist(target), [_record(rows=[row])])
            assert "auth.c:check_pw" in _gap_keys(gaps), status

    def test_unstamped_row_resurfaces_after_source_drift(self, tmp_path):
        target = _write_target(tmp_path)
        row = {"file": "auth.c", "function": "check_pw",
               "hash": hash_span(target / "auth.c", 1, 5)}
        (target / "auth.c").write_text(
            _SOURCE.replace("strcmp", "memcmp"), encoding="utf-8")
        gaps = compute_gaps(_checklist(target), [_record(rows=[row])])
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestJournalProjection:
    def _entry(self, target, **over):
        fields = {
            "ts": now_iso(),
            "run_id": "run1",
            "file": "auth.c",
            "function": "check_pw",
            "verdict": "clean",
            "source_hash": hash_span(target / "auth.c", 1, 5),
            "line_start": 1,
            "line_end": 5,
            "model": "model-a",
            "body": "review body",
        }
        fields.update(over)
        return fields

    def test_verified_journal_row_projects_stamped(self, tmp_path):
        target = _write_target(tmp_path)
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        append_entry(run_dir, ReviewJournalEntry(**self._entry(target)))
        record = build_from_journal(run_dir)
        rows = record["functions_analysed"]
        assert len(rows) == 1
        assert journal_mac.coverage_row_provenance(
            rows[0], "journal") == journal_mac.ROW_VERIFIED

    def test_planted_journal_row_projects_unstamped(self, tmp_path):
        """A raw journal line (no MAC) must NOT be laundered into a
        verified coverage row by the record builder — it flows
        through unstamped, carrying its hash for the fold's gate."""
        target = _write_target(tmp_path)
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        with (run_dir / JOURNAL_FILENAME).open(
                "a", encoding="utf-8") as fh:
            fh.write(json.dumps(self._entry(target)) + "\n")
        record = build_from_journal(run_dir)
        rows = record["functions_analysed"]
        assert len(rows) == 1
        assert journal_mac.coverage_row_provenance(
            rows[0], "journal") == journal_mac.ROW_UNSTAMPED
        assert rows[0]["hash"] == hash_span(target / "auth.c", 1, 5)


class TestFindingsProjection:
    def test_findings_rows_never_mint_stamps(self, tmp_path):
        """findings.json is LLM-written AND lives in the sandbox-
        writable run dir — stamping its projection would mint
        install-key trust onto attacker-writable input. Rows flow
        through unstamped; a planted findings.json earns no verified
        coverage row."""
        from core.coverage.record import build_from_findings

        findings_path = tmp_path / "findings.json"
        findings_path.write_text(json.dumps({"findings": [
            {"file": "auth.c", "function": "check_pw"},
        ]}), encoding="utf-8")
        record = build_from_findings(findings_path)
        rows = record["functions_analysed"]
        assert len(rows) == 1
        assert journal_mac.coverage_row_provenance(
            rows[0], "llm") == journal_mac.ROW_UNSTAMPED
        # And hashless, so the fold's exact-hash tier refuses too:
        # the function stays in the review queue.
        target = _write_target(tmp_path)
        gaps = compute_gaps(_checklist(target), [record])
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestAnnotationProjection:
    """Annotation .md files are human-editable plaintext with
    forgeable provenance metadata, living in a target-writable
    directory — the builder must not launder them into verified
    rows. Credit rides the exact-hash gate only."""

    def _annotate(self, tmp_path, **metadata):
        from core.annotations import Annotation, write_annotation
        ann_dir = tmp_path / "annotations"
        write_annotation(ann_dir, Annotation(
            file="auth.c", function="check_pw", body="reviewed",
            metadata=metadata))
        return ann_dir

    def test_annotation_rows_never_mint_stamps(self, tmp_path):
        from core.coverage.record import build_from_annotations
        target = _write_target(tmp_path)
        ann_dir = self._annotate(
            tmp_path, status="clean",
            hash=hash_span(target / "auth.c", 1, 5))
        record = build_from_annotations(ann_dir)
        rows = record["functions_analysed"]
        assert len(rows) == 1
        assert journal_mac.coverage_row_provenance(
            rows[0], "annotations") == journal_mac.ROW_UNSTAMPED
        # ...and the fold still credits it via the hash gate.
        gaps = compute_gaps(_checklist(target), [record])
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_planted_hashless_annotation_stays_a_gap(self, tmp_path):
        """A planted note claiming a clean review (no source
        evidence) must not retire the function from review."""
        from core.coverage.record import build_from_annotations
        target = _write_target(tmp_path)
        ann_dir = self._annotate(
            tmp_path, status="clean", source="human",
            provenance="legacy-pre-era")
        record = build_from_annotations(ann_dir)
        gaps = compute_gaps(_checklist(target), [record])
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestNoLaundering:
    def test_planted_row_survives_legit_rmw_unstamped(self, tmp_path):
        """A planted row sitting in the record when a legitimate
        writer saves it back stays unstamped: mixed record with one
        stamped and one planted row — only the stamped row's
        function is suppressed."""
        target = _write_target(tmp_path)
        target2 = target / "other.c"
        target2.write_text("int other_fn(void) { return 0; }\n",
                           encoding="utf-8")
        checklist = _checklist(target)
        checklist["files"].append({
            "path": "other.c", "language": "c",
            "items": [{"name": "other_fn", "kind": "function",
                       "line_start": 1, "line_end": 1}],
        })
        rows = [
            {"file": "auth.c", "function": "check_pw"},  # planted
            _stamped_row(function="other_fn", file="other.c"),
        ]
        gaps = compute_gaps(checklist, [_record(rows=rows)])
        keys = _gap_keys(gaps)
        assert "auth.c:check_pw" in keys
        assert "other.c:other_fn" not in keys
