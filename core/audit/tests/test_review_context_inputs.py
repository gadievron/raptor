"""Portable caller-context dependencies constrain reuse, never confer coverage."""

import hashlib

import pytest

from core.audit import review_context_inputs as inputs
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.refutation_source import capture_source_identity


def _origin(root):
    return KnowledgeOrigin("pass", "primary.c", "primary", 1, 1,
                           capture_source_identity(root, "primary.c"))


def _row(file="caller.c", text=b"caller"):
    return {"delivered": True, "role": "context_delivery_not_verification",
            "source_materials": [{"file": file, "sha256": hashlib.sha256(text).hexdigest(),
                                  "source_version": [1, 2, 3]}]}


def _snapshot(file="caller.c", text=b"caller"):
    return {"version": 1, "role": "review-context-inputs", "complete": True,
            "sources": [{"file": file, "sha256": hashlib.sha256(text).hexdigest()}]}


def test_delivery_binds_only_delivered_material_and_primary(tmp_path):
    (tmp_path / "primary.c").write_bytes(b"primary")
    omitted = _row("omitted.c")
    omitted["delivered"] = False
    result = inputs.context_inputs_from_delivery([omitted, _row()], _origin(tmp_path))
    assert result["complete"] is True
    assert [row["file"] for row in result["sources"]] == ["caller.c", "primary.c"]
    assert all(set(row) == {"file", "sha256"} for row in result["sources"])
    assert inputs.context_inputs_from_delivery([omitted], _origin(tmp_path)) is None
    assert inputs.context_inputs_from_delivery([], _origin(tmp_path)) is None


@pytest.mark.parametrize("bad", [None, {}, [None], [{"delivered": "yes"}],
                               [{"delivered": True}],
                               [{"delivered": True, "role": "proof", "source_materials": []}]])
def test_malformed_delivery_is_unknown(tmp_path, bad):
    result = inputs.context_inputs_from_delivery(bad, _origin(tmp_path))
    assert result is not None and result["complete"] is False


def test_bad_material_preserves_valid_sources_and_marks_incomplete(tmp_path):
    (tmp_path / "primary.c").write_bytes(b"primary")
    row = _row()
    row["source_materials"].append({"file": "../escape", "sha256": "f" * 64})
    result = inputs.context_inputs_from_delivery([row], _origin(tmp_path))
    assert result["complete"] is False
    assert {entry["file"] for entry in result["sources"]} == {"caller.c", "primary.c"}


@pytest.mark.parametrize("file", ["/absolute", "../x", "a/../x", "./x", "a//x", "a\\x",
                                  "binary:abc", "a\n.c", "a\x00.c", "x" * 513])
def test_invalid_portable_paths_refuse(file, tmp_path):
    snapshot = _snapshot(file)
    assert inputs.merge_context_inputs(snapshot)["complete"] is False
    assert inputs.context_inputs_current(snapshot, tmp_path)[0] is False


@pytest.mark.parametrize("alter", [{"role": "verification"}, {"version": True},
                                   {"complete": 1}, {"sources": {}},
                                   {"sources": [{"file": "x", "sha256": "A" * 64}]}])
def test_bad_snapshot_shapes_refuse(alter, tmp_path):
    snapshot = _snapshot()
    snapshot.update(alter)
    assert inputs.context_inputs_current(snapshot, tmp_path)[0] is False
    assert inputs.merge_context_inputs(snapshot)["complete"] is False


def test_union_conflict_absence_and_order():
    first, second = _snapshot("a.c"), _snapshot("b.c")
    assert inputs.merge_context_inputs(None, None) is None
    assert inputs.merge_context_inputs(first, None, first) == first
    assert inputs.merge_context_inputs(first, second) == inputs.merge_context_inputs(second, first)
    conflict = _snapshot("a.c", b"different")
    merged = inputs.merge_context_inputs(first, conflict)
    assert merged == inputs.merge_context_inputs(conflict, first)
    assert merged["complete"] is False
    assert inputs.merge_context_inputs(None, {}, first)["complete"] is False


def test_source_and_serialised_caps_mark_incomplete():
    import json

    many = [_snapshot(f"{index:03}.c") for index in range(40)]
    result = inputs.merge_context_inputs(*many)
    assert result["complete"] is False and len(result["sources"]) == 32
    large = [_snapshot(f"{index:03}" + "x" * 505) for index in range(32)]
    result = inputs.merge_context_inputs(*large)
    assert result["complete"] is False
    assert len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()) <= 16384


def test_current_changed_deleted_moved_and_legacy(tmp_path):
    first, moved = tmp_path / "first", tmp_path / "moved"
    first.mkdir()
    moved.mkdir()
    for root in (first, moved):
        (root / "caller.c").write_bytes(b"caller")
    snapshot = _snapshot()
    assert inputs.context_inputs_current(None, None) == (True, "")
    assert inputs.context_inputs_current(snapshot, None)[0] is False
    assert inputs.context_inputs_current(snapshot, first) == (True, "")
    assert inputs.context_inputs_current(snapshot, moved) == (True, "")
    (first / "caller.c").write_bytes(b"changed")
    refused = inputs.context_inputs_current(snapshot, first)
    assert refused == (False, "review_context_inputs_not_current")
    (first / "caller.c").unlink()
    assert inputs.context_inputs_current(snapshot, first) == refused


def test_second_file_read_invalidating_first_fails_interval_barrier(tmp_path, monkeypatch):
    (tmp_path / "a.c").write_bytes(b"caller")
    (tmp_path / "b.c").write_bytes(b"caller")
    original = inputs.capture_source_identity
    changed = False

    def capture(root, file):
        nonlocal changed
        identity = original(root, file)
        if file == "b.c" and not changed:
            changed = True
            (tmp_path / "a.c").write_bytes(b"changed")
        return identity

    monkeypatch.setattr(inputs, "capture_source_identity", capture)
    snapshot = inputs.merge_context_inputs(_snapshot("a.c"), _snapshot("b.c"))
    assert inputs.context_inputs_current(snapshot, tmp_path)[0] is False


def test_containment_refuses_symlink_escape(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "caller.c").write_bytes(b"caller")
    (root / "caller.c").symlink_to(tmp_path / "caller.c")
    assert inputs.context_inputs_current(_snapshot(), root)[0] is False


def test_dependency_digest_is_canonical_and_refuses_unknown():
    a, b = _snapshot("a.c"), _snapshot("b.c")
    left = inputs.merge_context_inputs(a, b)
    right = inputs.merge_context_inputs(b, a)
    assert inputs.context_inputs_digest(left) == inputs.context_inputs_digest(right)
    assert len(inputs.context_inputs_digest(left)) == 64
    assert inputs.context_inputs_digest(None) is None
    assert inputs.context_inputs_digest({}) is None
    assert inputs.context_inputs_digest(inputs.merge_context_inputs(a, _snapshot("a.c", b"changed"))) is None


def test_dependencies_survive_intake_and_capped_history_merges():
    from core.audit.review_claims import begin_review, record_intake, merge_history, read_history
    from core.audit.claims import ClaimRevision
    from core.audit.refutation_source import SourceIdentity

    origin = KnowledgeOrigin("pass", "primary.c", "primary", 1, 1, SourceIdentity("a" * 64, (1, 2, 3)))
    history = begin_review(origin, "attempt")
    history["source_inputs"] = _snapshot()
    revision = ClaimRevision({"mechanism": "candidate"}, pass_id="pass",
                             file="primary.c", function="primary", line_start=1)
    retained = record_intake(history, [revision])
    assert retained["source_inputs"] == _snapshot()
    for index in range(12):
        fresh = begin_review(origin, str(index))
        fresh["source_inputs"] = _snapshot(f"other{index}.c")
        retained = merge_history(retained, fresh)
    assert read_history(retained) is not None
    assert retained["source_inputs"]["complete"] is True
    assert len(retained["source_inputs"]["sources"]) == 13
    assert "contributor-limit" in retained["omissions"]


@pytest.mark.parametrize("bad", [None, {}, {"complete": False}])
def test_invalid_outer_history_cannot_drop_known_dependency_presence(bad):
    from core.audit.review_claims import record_intake, merge_history

    malformed = {"source_inputs": bad}
    intake = record_intake(malformed, [])
    merged = merge_history(None, malformed)
    assert intake["source_inputs"]["complete"] is False
    assert merged["source_inputs"]["complete"] is False


def _journal_case(tmp_path):
    from core.audit.orchestrator import ReviewOutcome
    from core.audit.review_claims import begin_review

    (tmp_path / "primary.c").write_bytes(b"int primary(void) { return 1; }\n")
    (tmp_path / "caller.c").write_bytes(b"caller")
    origin = _origin(tmp_path)
    history = begin_review(origin, "attempt")
    history["source_inputs"] = inputs.context_inputs_from_delivery([_row()], origin)
    outcome = ReviewOutcome("primary.c", "primary", "suspicious", "Retained concern", line=1,
                            hypothesis="candidate", review_result={"review_claims": history})
    return outcome, {"file": "primary.c", "name": "primary", "line_start": 1, "line_end": 1}


def test_collector_journals_portable_context_binding(tmp_path):
    from core.audit.collector import append_journal_for_outcome
    from core.audit.source_anchor import parse_context_source_anchor
    from core.audit.journal import load_entries

    outcome, gap = _journal_case(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    entry = append_journal_for_outcome(out_dir=out, target_path=tmp_path, run_id="run",
                                       outcome=outcome, gap=gap)
    assert entry is not None
    assert parse_context_source_anchor(entry.source_hash)[2] == inputs.context_inputs_digest(
        entry.review_claims["source_inputs"])
    persisted, = load_entries(out, fresh=True)
    assert persisted.review_claims["source_inputs"] == entry.review_claims["source_inputs"]
    (tmp_path / "caller.c").write_bytes(b"changed")
    assert append_journal_for_outcome(out_dir=out, target_path=tmp_path, run_id="run",
                                      outcome=outcome, gap=gap) is None
    assert len(load_entries(out, fresh=True)) == 1


def test_collector_cannot_launder_dependency_drift_during_primary_hash(tmp_path, monkeypatch):
    from core.audit.collector import append_journal_for_outcome
    import core.audit.record as record

    outcome, gap = _journal_case(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    original = record._compute_hash

    def hash_then_change(*args, **kwargs):
        value = original(*args, **kwargs)
        (tmp_path / "caller.c").write_bytes(b"changed after capture")
        return value

    monkeypatch.setattr(record, "_compute_hash", hash_then_change)
    assert append_journal_for_outcome(out_dir=out, target_path=tmp_path, run_id="run",
                                      outcome=outcome, gap=gap) is None
    assert not (out / "review-journal.jsonl").exists()
