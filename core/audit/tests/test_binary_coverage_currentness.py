"""Signed binary review projections still need current module bytes."""
from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from core.audit.collector import Collector
from core.audit.gaps import compute_gaps, load_checklist
from core.audit.tests.test_binary_journal_binding import owned_binary_review as owned_binary_review
from core.coverage import journal_mac
from core.coverage.record import build_from_journal


def test_signed_binary_projection_cannot_suppress_changed_module(owned_binary_review, tmp_path):
    target, out, gap, outcome, runtime, original = owned_binary_review
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap) is not None
    projected = build_from_journal(out)
    assert projected is not None and len(projected["functions_analysed"]) == 1
    row = projected["functions_analysed"][0]
    assert journal_mac.coverage_row_provenance(row, projected["tool"]) == journal_mac.ROW_VERIFIED
    checklist = load_checklist(out)
    checklist["target_path"] = str(target)
    checklist["target_kind"] = "binary"
    checklist["files"][0]["language"] = "binary"
    fresh_run = tmp_path / "fresh-run"
    fresh_run.mkdir()
    assert not any(item["name"] == "f" for item in compute_gaps(checklist, [projected], out_dir=fresh_run))
    target.write_bytes(b"owned changed module, still not executable")
    checklist["files"][0]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    gaps = compute_gaps(checklist, [projected], out_dir=fresh_run)
    assert any(item["name"] == "f" for item in gaps), "signed projection hid the changed binary from review"


def _projected_current_inventory(owned):
    target, out, gap, outcome, runtime, original = owned
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap) is not None
    projected = build_from_journal(out)
    row, = projected["functions_analysed"]
    assert journal_mac.coverage_row_provenance(row, projected["tool"]) == journal_mac.ROW_VERIFIED
    checklist = load_checklist(out)
    checklist.update(target_path=str(target), target_kind="binary")
    checklist["files"][0]["language"] = "binary"
    return projected, checklist


@pytest.mark.parametrize("surface", ["projection", "journal", "both"])
def test_stale_inventory_cannot_revalidate_old_binary_history(owned_binary_review, tmp_path, surface):
    target, out, gap, outcome, runtime, original = owned_binary_review
    projected, checklist = _projected_current_inventory(owned_binary_review)
    target.write_bytes(b"owned changed module without refreshed inventory")
    fresh = tmp_path / "fresh-run"
    fresh.mkdir()
    records = [projected] if surface in ("projection", "both") else []
    run = out if surface in ("journal", "both") else fresh
    assert any(item["name"] == "f" for item in compute_gaps(checklist, records, out_dir=run))


@pytest.mark.parametrize("change", ["address", "size", "missing_digest", "wrong_digest", "missing_target", "directory_target", "wrong_key"])
def test_verified_projection_does_not_fill_unknown_or_changed_binary_inputs(owned_binary_review, tmp_path, change):
    target, out, gap, outcome, runtime, original = owned_binary_review
    projected, checklist = _projected_current_inventory(owned_binary_review)
    current = deepcopy(checklist)
    entry = current["files"][0]
    if change == "address":
        entry["items"][0]["address"] = 8192
    elif change == "size":
        entry["items"][0]["size"] = 64
    elif change == "missing_digest":
        entry.pop("sha256")
    elif change == "wrong_digest":
        other = tmp_path / "other.bin"
        other.write_bytes(b"owned unrelated module")
        entry["sha256"] = hashlib.sha256(other.read_bytes()).hexdigest()
    elif change == "missing_target":
        target.unlink()
    elif change == "directory_target":
        current["target_path"] = str(tmp_path)
    else:
        entry["path"] = "binary:other"
    fresh = tmp_path / "fresh-run"
    fresh.mkdir()
    assert any(item["name"] == "f" for item in compute_gaps(current, [projected], out_dir=fresh))


def test_observed_module_change_during_fold_retires_earlier_projection_credit(owned_binary_review, tmp_path, monkeypatch):
    from core.audit import gaps as gap_module
    target, out, gap, outcome, runtime, original = owned_binary_review
    projected, checklist = _projected_current_inventory(owned_binary_review)
    fold = gap_module._fold_journal_into_covered
    called = []
    def changing_fold(*args, **kwargs):
        result = fold(*args, **kwargs)
        called.append(1)
        target.write_bytes(b"owned changed module during fold")
        return result
    monkeypatch.setattr(gap_module, "_fold_journal_into_covered", changing_fold)
    fresh = tmp_path / "fresh-run"
    fresh.mkdir()
    assert any(item["name"] == "f" for item in compute_gaps(checklist, [projected], out_dir=fresh))
    assert called == [1]


def test_current_unsigned_binary_projection_gains_no_new_authority(owned_binary_review, tmp_path):
    target, out, gap, outcome, runtime, original = owned_binary_review
    projected, checklist = _projected_current_inventory(owned_binary_review)
    projected["functions_analysed"][0].pop(journal_mac.TOKEN_KEY)
    fresh = tmp_path / "fresh-run"
    fresh.mkdir()
    assert any(item["name"] == "f" for item in compute_gaps(checklist, [projected], out_dir=fresh))


def test_observed_binary_change_retires_hashless_manual_credit_but_preserves_record(owned_binary_review, tmp_path, monkeypatch):
    from core.audit import gaps as gap_module
    target, out, gap, outcome, runtime, original = owned_binary_review
    checklist = load_checklist(out)
    checklist.update(target_path=str(target), target_kind="binary")
    row = {"file": outcome.file, "function": outcome.function, "status": "clean"}
    row[journal_mac.TOKEN_KEY] = journal_mac.mint_coverage_row(row, "mark")
    assert journal_mac.coverage_row_provenance(row, "mark") == journal_mac.ROW_VERIFIED
    record = {"tool": "mark", "functions_analysed": [row]}
    before = deepcopy(record)
    fresh = tmp_path / "fresh-run"
    fresh.mkdir()
    assert not any(item["name"] == "f" for item in compute_gaps(checklist, [record], out_dir=fresh))
    fold = gap_module._fold_journal_into_covered
    def changing_fold(*args, **kwargs):
        result = fold(*args, **kwargs)
        target.write_bytes(b"owned changed module during manual-credit fold")
        return result
    monkeypatch.setattr(gap_module, "_fold_journal_into_covered", changing_fold)
    assert any(item["name"] == "f" for item in compute_gaps(checklist, [record], out_dir=fresh))
    assert record == before
