"""Fixture receipts must represent the actual source and rendered reading."""

from copy import deepcopy

import pytest

from core.audit.gaps import _verify_entries_fold
from core.audit.reference_foundation import review_has_current_foundation
from core.audit.tests.reuse_foundation_fixtures import current_foundation_fields, current_review_fields
from core.audit.source_anchor import parse_source_anchor
from core.staleness import hash_span
from core.coverage.journal import ReviewJournalEntry, append_entry, load_entries

_SOURCE = "int f(int x) { return (x + 1 > 2) && x; }\n"


@pytest.fixture
def owned_target(tmp_path, monkeypatch):
    pytest.importorskip("tree_sitter_c")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    target = tmp_path / "target"
    target.mkdir()
    (target / "unit.c").write_text(_SOURCE)
    return target


def _fold(target, tmp_path, fields):
    row = ReviewJournalEntry(ts="2026-11-11T00:00:00Z", run_id="owned",
        file="unit.c", function="f", verdict="clean", line_start=1, line_end=1,
        model="scripted", producer="audit", clean_basis="verdict", body="owned review", **fields)
    append_entry(tmp_path / "run", row)
    covered, sink, stats = set(), {}, {}
    _verify_entries_fold(covered, load_entries(tmp_path / "run", fresh=True),
        target_path=target, current_spans={"unit.c:f": (1, 1)}, reuse_sink=sink,
        current_strategies_fn=lambda *_: set(), current_model=None,
        source_label="owned", reuse_stats=stats, require_c_foundation=True)
    return covered, sink, stats


def test_rendered_source_selected_foundation_reaches_reuse(owned_target, tmp_path):
    fields = current_foundation_fields(owned_target, "unit.c", 1, 1)
    history = fields["review_claims"]
    ids = {entry["id"] for entry in history["reference_inputs"]["entries"]}
    assert {"c.integer-promotion", "c.integer-conversion", "c.integer-usual-conversions",
            "c.integer-definedness", "c.scalar-logical"} <= ids
    assert review_has_current_foundation(history, source=_SOURCE, file="unit.c")
    covered, sink, stats = _fold(owned_target, tmp_path, fields)
    assert covered == {"unit.c:f"}
    assert set(sink) == {"unit.c:f"}
    assert stats == {}


def test_omitted_selected_core_is_not_current(owned_target):
    history = deepcopy(current_foundation_fields(owned_target, "unit.c", 1, 1)["review_claims"])
    history["reference_inputs"]["entries"] = [entry for entry in history["reference_inputs"]["entries"]
                                               if entry["id"] != "c.scalar-logical"]
    assert not review_has_current_foundation(history, source=_SOURCE, file="unit.c")


def test_changed_owned_source_does_not_reuse_receipt(owned_target, tmp_path):
    fields = current_foundation_fields(owned_target, "unit.c", 1, 1)
    (owned_target / "unit.c").write_text(_SOURCE.replace("x + 1", "x + 2"))
    covered, sink, stats = _fold(owned_target, tmp_path, fields)
    assert not covered and not sink
    assert stats == {"unit.c:f": "review_context_inputs"}


@pytest.mark.parametrize("start,end", [(0, 0), (1, None), (50, 51)])
def test_unreadable_geometry_is_never_repaired(owned_target, start, end):
    with pytest.raises(ValueError, match="readable measured source"):
        current_foundation_fields(owned_target, "unit.c", start, end)


def test_requested_measured_site_and_current_hash_are_bound(owned_target):
    (owned_target / "other.c").write_text("// preamble\n" + _SOURCE)
    fields = {"file": "unit.c", "line_start": 1, "line_end": 1}
    overrides = {"file": "other.c", "line_start": 2, "line_end": 2,
                 "source_hash": hash_span(owned_target / "other.c", 2, 2)}
    result = current_review_fields(owned_target, fields, overrides)
    assert result["file"] == "other.c" and result["line_start"] == result["line_end"] == 2
    assert parse_source_anchor(result["source_hash"])[1] == overrides["source_hash"]
    assert review_has_current_foundation(result["review_claims"], source=_SOURCE, file="other.c")


@pytest.mark.parametrize("source_hash", ["", "f" * 12, "0" * 16])
def test_explicit_legacy_or_stale_hash_is_not_upgraded(owned_target, source_hash):
    result = current_review_fields(owned_target,
        {"file": "unit.c", "line_start": 1, "line_end": 1}, {"source_hash": source_hash})
    assert result["source_hash"] == source_hash
    assert "review_claims" not in result
