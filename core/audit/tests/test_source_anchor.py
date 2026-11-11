"""Portable producer source binding at journal, reuse and correction boundaries."""

from dataclasses import replace

import pytest

from core.coverage import journal_mac
from core.coverage.journal import append_entry
from core.audit.verdict_reuse import outcome_from_entry
from core.audit.backlog_drain import _RowOutcome
from core.audit.collector import append_journal_for_outcome
from core.audit.gaps import _verify_entries_fold
from core.audit.refutation_source import capture_source_identity
from core.audit.verification_results import VerificationScope
from core.coverage.journal import load_entries
from core.staleness import hash_span
from core.audit.source_anchor import parse_source_anchor


def test_bound_source_change_outside_span_cannot_suppress_review(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    target = tmp_path / "target"
    target.mkdir()
    path = target / "a.c"
    path.write_text("#define DEFAULT_VALUE 0\nint f(void) { return DEFAULT_VALUE; }\n", encoding="utf-8")
    scope = VerificationScope("a.c", "f", 2, "owned default value review",
                              capture_source_identity(target, "a.c"))
    outcome = _RowOutcome(file="a.c", function="f", status="clean", line=2,
                          hypothesis=scope.hypothesis, review_result={})
    run = tmp_path / "run"
    appended = append_journal_for_outcome(out_dir=run, target_path=target,
        run_id="owned", outcome=outcome, gap={"line_start": 2, "line_end": 2},
        verification_scope=scope)
    assert appended is not None
    entries = load_entries(run)
    assert len(entries) == 1
    path.write_text("#define DEFAULT_VALUE 1\nint f(void) { return DEFAULT_VALUE; }\n", encoding="utf-8")
    parts = parse_source_anchor(entries[0].source_hash)
    assert hash_span(path, 2, 2) == (parts[1] if parts else entries[0].source_hash)
    assert capture_source_identity(target, "a.c").sha256 != scope.source_identity.sha256
    covered = set()
    _verify_entries_fold(covered, entries, target_path=target,
        current_spans={"a.c:f": (2, 2)}, reuse_sink=None,
        current_strategies_fn=lambda *_: set(), current_model=None, source_label="owned")
    assert not covered, "known producer full-file binding was lost at durable reuse"



@pytest.fixture
def bound_subject(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    target = tmp_path / "target"
    target.mkdir()
    path = target / "a.c"
    path.write_text("#define DEFAULT_VALUE 0\nint f(void) { return DEFAULT_VALUE; }\n", encoding="utf-8")
    scope = VerificationScope("a.c", "f", 2, "owned default value review",
                              capture_source_identity(target, "a.c"))
    outcome = _RowOutcome(file="a.c", function="f", status="clean", line=2,
                          hypothesis=scope.hypothesis, review_result={})
    run = tmp_path / "run"
    entry = append_journal_for_outcome(out_dir=run, target_path=target, run_id="owned",
        outcome=outcome, gap={"line_start": 2, "line_end": 2}, verification_scope=scope)
    assert entry is not None
    entry = load_entries(run)[0]
    assert parse_source_anchor(entry.source_hash) == (scope.source_identity.sha256, hash_span(path, 2, 2))
    assert journal_mac.entry_provenance(entry) == journal_mac.ROW_VERIFIED
    return target, path, run, entry


def fold_bound(target, entries, *, sink=None, stats=None):
    covered = set()
    _verify_entries_fold(covered, entries, target_path=target,
        current_spans={"a.c:f": (2, 2)}, reuse_sink=sink, reuse_stats=stats,
        current_strategies_fn=lambda *_: set(), current_model=None, source_label="owned")
    return covered


def test_unchanged_bound_source_reuses_and_preserves_anchor_through_two_segments(bound_subject, tmp_path):
    target, path, run, entry = bound_subject
    for number in range(2):
        sink = {}
        assert fold_bound(target, [entry], sink=sink) == {"a.c:f"}
        assert sink["a.c:f"] is entry
        outcome = outcome_from_entry(entry)
        assert outcome.reused_source_anchor == entry.source_hash
        assert outcome.evidence_tool.startswith("journal:recall:")
        segment = tmp_path / f"segment-{number}"
        appended = append_journal_for_outcome(out_dir=segment, target_path=target,
            run_id=segment.name, outcome=outcome, gap={"line_start": 2, "line_end": 2})
        assert appended is not None and appended.source_hash == entry.source_hash
        entry = load_entries(segment)[0]
        assert journal_mac.entry_provenance(entry) == journal_mac.ROW_VERIFIED


def test_identical_source_in_another_checkout_keeps_content_binding(bound_subject, tmp_path):
    target, path, run, entry = bound_subject
    moved = tmp_path / "moved"
    moved.mkdir()
    (moved / "a.c").write_bytes(path.read_bytes())
    assert capture_source_identity(target, "a.c").version != capture_source_identity(moved, "a.c").version
    assert fold_bound(moved, [entry]) == {"a.c:f"}


def test_drift_after_fold_before_rejournal_cannot_backfill_a_new_digest(bound_subject, tmp_path):
    target, path, run, entry = bound_subject
    sink = {}
    assert fold_bound(target, [entry], sink=sink) == {"a.c:f"}
    outcome = outcome_from_entry(sink["a.c:f"])
    path.write_text(path.read_text().replace("DEFAULT_VALUE 0", "DEFAULT_VALUE 1"))
    assert append_journal_for_outcome(out_dir=tmp_path / "next", target_path=target,
        run_id="next", outcome=outcome, gap={"line_start": 2, "line_end": 2}) is None
    assert not (tmp_path / "next" / "review-journal.jsonl").exists()


def test_source_drift_during_fold_span_hashing_invalidates_bound_rows(bound_subject, monkeypatch):
    import core.staleness as staleness

    target, path, run, entry = bound_subject
    original = staleness.hash_spans

    def changed(*args, **kwargs):
        hashes = original(*args, **kwargs)
        path.write_text(path.read_text().replace("DEFAULT_VALUE 0", "DEFAULT_VALUE 1"))
        return hashes

    monkeypatch.setattr(staleness, "hash_spans", changed)
    stats = {}
    assert fold_bound(target, [entry], sink={}, stats=stats) == set()
    assert stats == {"a.c:f": "source_binding"}


@pytest.mark.parametrize("value", ["src:", "src:" + "0" * 63 + ":" + "a" * 12,
    "src:" + "A" * 64 + ":" + "a" * 12, "src:" + "0" * 64 + ":short",
    "src:" + "0" * 64 + ":" + "a" * 12 + ":extra"])
def test_malformed_tagged_source_never_falls_back_to_legacy_credit(bound_subject, value):
    target, path, run, entry = bound_subject
    changed = replace(entry, source_hash=value)
    append_entry(run, changed)
    assert journal_mac.entry_provenance(changed) == journal_mac.ROW_VERIFIED
    assert fold_bound(target, [changed], sink={}) == set()


@pytest.mark.parametrize("failure", ["missing-target", "unreadable-source", "missing-spans"])
def test_known_binding_never_uses_hashless_suppression(bound_subject, monkeypatch, failure):
    from core.audit import refutation_source

    target, path, run, entry = bound_subject
    if failure == "missing-target":
        target = None
    elif failure == "unreadable-source":
        monkeypatch.setattr(refutation_source, "capture_source_identity", lambda *a, **kw: None)
    else:
        entry = replace(entry, line_start=0, line_end=None)
        append_entry(run, entry)
        covered = set()
        _verify_entries_fold(covered, [entry], target_path=target, current_spans={},
            reuse_sink={}, current_strategies_fn=lambda *_: set(), current_model=None, source_label="owned")
        assert not covered
        return
    assert fold_bound(target, [entry], sink={}) == set()


def test_mac_covers_source_content_binding(bound_subject):
    target, path, run, entry = bound_subject
    _, span = parse_source_anchor(entry.source_hash)
    entry.source_hash = f"src:{'0' * 64}:{span}"
    assert journal_mac.entry_provenance(entry) == journal_mac.ROW_TAMPERED
    assert fold_bound(target, [entry], sink={}) == set()


def test_legacy_span_hash_does_not_trigger_full_file_reads(bound_subject, monkeypatch):
    from core.audit import refutation_source

    target, path, run, entry = bound_subject
    legacy = replace(entry, source_hash=hash_span(path, 2, 2))
    append_entry(run, legacy)

    def forbidden(*args, **kwargs):
        raise AssertionError("legacy rows must not pay for whole-file binding")

    monkeypatch.setattr(refutation_source, "capture_source_identity", forbidden)
    assert fold_bound(target, [legacy]) == {"a.c:f"}


def test_reader_without_tag_support_resurfaces_instead_of_reusing(bound_subject):
    from core.staleness import CheckItem, check_batch

    target, path, run, entry = bound_subject
    result = check_batch([CheckItem(path, 2, 2, entry.source_hash)], root=target)
    assert result[0].status == "modified"


def test_full_file_read_count_is_per_file_not_per_historical_row(bound_subject, monkeypatch):
    from core.audit import refutation_source

    target, path, run, entry = bound_subject
    capture = refutation_source.capture_source_identity
    calls = []

    def counted(root, file, **kwargs):
        calls.append(file)
        return capture(root, file, **kwargs)

    monkeypatch.setattr(refutation_source, "capture_source_identity", counted)
    assert fold_bound(target, [entry, entry]) == {"a.c:f"}
    assert calls == ["a.c", "a.c"]


def test_source_drift_during_rejournal_span_hashing_retains_old_binding(bound_subject, tmp_path, monkeypatch):
    from core.audit import record

    target, path, run, entry = bound_subject
    outcome = outcome_from_entry(entry)
    compute = record._compute_hash

    def changed(*args, **kwargs):
        value = compute(*args, **kwargs)
        path.write_text(path.read_text().replace("DEFAULT_VALUE 0", "DEFAULT_VALUE 1"))
        return value

    monkeypatch.setattr(record, "_compute_hash", changed)
    assert append_journal_for_outcome(out_dir=tmp_path / "next", target_path=target,
        run_id="next", outcome=outcome, gap={"line_start": 2, "line_end": 2}) is None
    assert outcome.reused_source_anchor == entry.source_hash


def test_unchanged_bound_row_is_not_resume_drift(bound_subject):
    from core.audit.resume import compute_drift

    target, path, run, entry = bound_subject
    assert compute_drift(run, target) == ([], 1)


def test_resume_reports_full_source_drift_outside_the_span(bound_subject):
    from core.audit.resume import compute_drift

    target, path, run, entry = bound_subject
    path.write_text(path.read_text().replace("DEFAULT_VALUE 0", "DEFAULT_VALUE 1"))
    drifted, checked = compute_drift(run, target)
    assert checked == 1 and len(drifted) == 1
    assert drifted[0].stored_hash == entry.source_hash
    assert parse_source_anchor(drifted[0].current_hash)[1] == parse_source_anchor(entry.source_hash)[1]
    assert drifted[0].current_hash != entry.source_hash


@pytest.mark.parametrize("change", ["none", "macro", "missing"])
def test_feedback_keeps_the_producer_binding_instead_of_backfilling(bound_subject, tmp_path, change):
    from core.audit.feedback import import_validation_results
    from core.json import save_json

    target, path, run, entry = bound_subject
    if change == "macro":
        path.write_text(path.read_text().replace("DEFAULT_VALUE 0", "DEFAULT_VALUE 1"))
    elif change == "missing":
        path.unlink()
    annotation = tmp_path / "annotations"
    annotation.mkdir()
    report = tmp_path / "validation.json"
    save_json(report, [{"file": "a.c", "function": "f", "ruling": {
        "status": "ruled_out", "reason": "owned review control", "disqualifier": "D-1"}}])
    result = import_validation_results(validation_report=report, annotations_dir=annotation,
        audit_out_dir=run, target_path=target)
    assert result["updated"] == 1
    correction = load_entries(run, fresh=True)[-1]
    assert correction.source_hash == entry.source_hash
    assert bool(correction.source_drifted) == (change != "none")
    assert journal_mac.entry_provenance(correction) == journal_mac.ROW_VERIFIED
    assert fold_bound(target, [correction]) == ({"a.c:f"} if change == "none" else set())


def test_compaction_does_not_merge_distinct_whole_file_bindings(bound_subject, tmp_path):
    from core.coverage.journal_compact import compact_journal
    from core.audit.source_anchor import make_source_anchor

    target, path, run, entry = bound_subject
    _, span = parse_source_anchor(entry.source_hash)
    other = make_source_anchor("0" * 64, span)
    compact_run = tmp_path / "compact"
    for timestamp, anchor in [("2026-11-08T01:00:01Z", entry.source_hash),
                              ("2026-11-08T01:00:02Z", other)]:
        append_entry(compact_run, replace(entry, ts=timestamp, source_hash=anchor,
            reused=True, cost_usd=0.0))
    compact_journal(compact_run, supersede=True)
    entries = load_entries(compact_run, fresh=True)
    assert {item.source_hash for item in entries} == {entry.source_hash, other}
    assert all(journal_mac.entry_provenance(item) == journal_mac.ROW_VERIFIED for item in entries)


@pytest.mark.parametrize("version", [1, 2, 3])
@pytest.mark.parametrize("change", ["none", "unknown", "primary", "dependency", "manifest"])
def test_resume_context_anchor_requires_current_inputs(bound_subject, tmp_path, version, change):
    from core.audit.resume import compute_drift
    from core.audit.review_context_inputs import context_inputs_from_sources
    from core.audit.reference_inputs import reference_inputs_from_delivery, review_context_digest
    from core.audit.knowledge_context import reference_delivery, reference_sections
    from core.audit.source_anchor import make_context_source_anchor
    from core.language_reference import lookup, ReferenceContext

    target, path, _, entry = bound_subject
    dependency = target / "helper.h"
    dependency.write_text("#define HELPER 1\n")
    primary, span = parse_source_anchor(entry.source_hash)
    sources = context_inputs_from_sources([
        ("target", "a.c", primary),
        ("target", "helper.h", capture_source_identity(target, "helper.h").sha256),
    ])
    if version == 1:
        sources = {**sources, "version": 1,
                   "sources": [{k: v for k, v in row.items() if k != "root"}
                               for row in sources["sources"]]}
    history = {"source_inputs": sources}
    reference = None
    if version == 3:
        answer = lookup("resume-owned", "", ReferenceContext("c"), entry_id="c.integer-promotion")
        reference = reference_inputs_from_delivery(
            reference_delivery((answer,), reference_sections((answer,))), (answer,))
        assert reference["complete"] is True
        history["reference_inputs"] = reference
    digest = review_context_digest(sources, reference)
    assert digest is not None
    anchor = make_context_source_anchor(primary, span, None if change == "unknown" else digest,
                                        context_version=version)
    if change == "primary":
        path.write_text(path.read_text().replace("DEFAULT_VALUE 0", "DEFAULT_VALUE 1"))
    elif change == "dependency":
        dependency.write_text("#define HELPER 2\n")
    elif change == "manifest":
        history = {}
    run = tmp_path / "context-run"
    append_entry(run, replace(entry, source_hash=anchor, review_claims=history))
    drifted, checked = compute_drift(run, target)
    assert checked == 1
    assert bool(drifted) == (change != "none")


def test_resume_reference_anchor_rejects_changed_delivered_rule(tmp_path, monkeypatch):
    from core.audit.tests.test_reference_context_reuse import _journaled_reference
    from core.audit.resume import compute_drift
    from core.language_reference import c_integer

    runtime, outcome, gap = _journaled_reference(tmp_path, monkeypatch)
    try:
        entry = append_journal_for_outcome(out_dir=tmp_path / "out", target_path=tmp_path,
                                          run_id="resume", outcome=outcome, gap=gap)
        assert entry is not None
        assert compute_drift(tmp_path / "out", tmp_path) == ([], 1)
        used = {row["id"] for row in entry.review_claims["reference_inputs"]["entries"]}
        monkeypatch.setattr(c_integer, "ENTRIES", tuple(
            replace(item, rule=item.rule + " Changed conditional rule.")
            if item.entry_id in used else item for item in c_integer.ENTRIES))
        drifted, checked = compute_drift(tmp_path / "out", tmp_path)
        assert checked == 1 and len(drifted) == 1
    finally:
        runtime.close()
