"""Tests for core.tp_harvest.labels."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.corpus.label import load_label
from core.tp_harvest.labels import (
    BACKLOG_REASON,
    LabelExistsError,
    LabelPinError,
    ProvenanceGateError,
    append_backlog_pointer,
    check_provenance,
    emit_label,
)
from core.tp_harvest.records import build_record

from .conftest import SINK_LINE, make_finding


def _record(target_tree: Path, run_dir: Path, **overrides):
    return build_record(
        make_finding(**overrides), run_dir=run_dir,
        target_path=str(target_tree), command="validate",
    )


def _emit(record, labels_base: Path, **overrides):
    kwargs = dict(
        bug_class="trap",
        rationale="strcpy into fixed 16-byte buffer, attacker argv",
        labeler="operator",
        provenance="public",
        repo="https://example.invalid/upstream.git",
        sha="0" * 40,
        labels_base=labels_base,
        fix_commit="1" * 40,
    )
    kwargs.update(overrides)
    return emit_label(record, **kwargs)


class TestProvenanceGate:
    """Default NOT-labelable; the operator flips it per finding."""

    def test_default_refuses(self):
        with pytest.raises(ProvenanceGateError):
            check_provenance(None)
        with pytest.raises(ProvenanceGateError):
            check_provenance("")

    def test_unknown_value_refuses(self):
        # Tightening direction: only the two documented values pass —
        # near-misses refuse rather than guess.
        for bad in ("Public", "disclosed", "yes", "own_target"):
            with pytest.raises(ProvenanceGateError):
                check_provenance(bad, cve="CVE-2026-0001")

    def test_public_needs_anchor(self):
        with pytest.raises(ProvenanceGateError):
            check_provenance("public")
        check_provenance("public", cve="CVE-2026-0001")
        check_provenance("public", fix_commit="a" * 40)

    def test_whitespace_anchor_is_not_an_anchor(self):
        # Anchors are judged STRIPPED: "  " is an assertion, not
        # evidence of disclosure.
        with pytest.raises(ProvenanceGateError):
            check_provenance("public", cve="   ")
        with pytest.raises(ProvenanceGateError):
            check_provenance("public", fix_commit="\t\n")

    def test_own_target_passes_without_anchor(self):
        # Loosening direction: the operator's own targets are
        # labelable without a public anchor by design.
        check_provenance("own-target")

    def test_gate_runs_before_any_write(
            self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        base = tmp_path / "labels"
        with pytest.raises(ProvenanceGateError):
            _emit(rec, base, provenance=None)
        assert not base.exists()


class TestEmitLabel:
    def test_emitted_label_round_trips_through_corpus_loader(
            self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        path = _emit(rec, tmp_path / "labels")
        assert path.name.endswith(".label.json")
        assert path.parent.name == "trap"
        label = load_label(path)  # corpus-side validation
        assert label.function_id == "src/copy.c:copy_name"
        assert label.expected_status == "finding"
        assert label.cwe == "CWE-121"
        assert label.source.line_start == SINK_LINE
        assert label.source.span_sha == rec.span_sha
        assert label.fix_commit == "1" * 40

    def test_missing_pin_refuses(self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        with pytest.raises(LabelPinError):
            _emit(rec, tmp_path / "labels", sha="")
        with pytest.raises(LabelPinError):
            _emit(rec, tmp_path / "labels", repo="")

    def test_bad_bug_class_refused_by_corpus_schema(
            self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        with pytest.raises(ValueError, match="bug_class"):
            _emit(rec, tmp_path / "labels", bug_class="not-a-class")

    def test_duplicate_refuses(self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        _emit(rec, tmp_path / "labels")
        with pytest.raises(LabelExistsError):
            _emit(rec, tmp_path / "labels")

    def test_filename_is_sanitised(self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir, function="../..:evil")
        path = _emit(rec, tmp_path / "labels")
        assert path.parent == tmp_path / "labels" / "trap"
        assert "/" not in path.name
        assert ".." not in path.name


class TestEmitLabelStripping:
    def test_whitespace_padded_anchor_stored_stripped(
            self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        path = _emit(rec, tmp_path / "labels",
                     cve="  CVE-2026-0001  ", fix_commit="")
        from core.audit.corpus.label import load_label
        label = load_label(path)
        assert label.cve == "CVE-2026-0001"

    def test_whitespace_only_anchor_refused_at_emit(
            self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        with pytest.raises(ProvenanceGateError):
            _emit(rec, tmp_path / "labels", cve=" ", fix_commit="  ")


class TestBacklogPointer:
    def test_pointer_shape_and_append(self, run_dir, target_tree, tmp_path):
        rec = _record(target_tree, run_dir)
        backlog = tmp_path / "tp-harvest" / "disclosure-backlog.jsonl"
        append_backlog_pointer(backlog, rec)
        append_backlog_pointer(backlog, rec)
        lines = backlog.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        row = json.loads(lines[0])
        assert row["harvest_id"] == rec.harvest_id
        assert row["reason"] == BACKLOG_REASON
        assert row["file"] == "src/copy.c"
        # Pointer carries location identity + status only — never the
        # defect narrative (message/flow/evidence stay in the record).
        assert "message" not in row
        assert "flow" not in row
        assert "evidence" not in row

    def test_append_refuses_symlinked_backlog(
            self, run_dir, target_tree, tmp_path):
        # O_NOFOLLOW: a pre-planted symlink at the backlog path is an
        # arbitrary-file-append primitive — the open must refuse
        # loudly and leave the victim untouched.
        rec = _record(target_tree, run_dir)
        victim = tmp_path / "victim.txt"
        victim.write_text("pre-existing\n", encoding="utf-8")
        backlog = tmp_path / "tp-harvest" / "disclosure-backlog.jsonl"
        backlog.parent.mkdir(parents=True)
        backlog.symlink_to(victim)
        with pytest.raises(OSError):
            append_backlog_pointer(backlog, rec)
        assert victim.read_text(encoding="utf-8") == "pre-existing\n"
