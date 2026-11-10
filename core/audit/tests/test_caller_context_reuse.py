"""Delivered caller inputs constrain both journal coverage sources."""

from dataclasses import replace
import hashlib

import pytest

from core.audit.gaps import _fold_journal_into_covered, _verify_entries_fold
from core.audit.review_context_inputs import context_inputs_digest
from core.audit.source_anchor import make_context_source_anchor, make_source_anchor
from core.coverage import journal_mac
from core.coverage.journal import (
    CLEAN_BASIS_VERDICT, ReviewJournalEntry, append_entry, load_entries,
    merge_into_index,
)
from core.staleness import hash_span


@pytest.fixture
def subject(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    root = tmp_path / "target"
    root.mkdir()
    (root / "a.c").write_text("int f(void) { return 0; }\n\nint f(void) { return 1; }\n")
    (root / "caller.c").write_text("int caller(void) { return f(); }\n")
    return root


def _entry(root, *, context=True, line=1, ts="2026-11-10T01:00:00Z", **changes):
    source = hashlib.sha256((root / "a.c").read_bytes()).hexdigest()
    span = hash_span(root / "a.c", line or 1, line or 1)
    history = None
    if context:
        snapshot = {"version": 1, "role": "review-context-inputs", "complete": True,
                    "sources": [{"file": "a.c", "sha256": source}, {"file": "caller.c",
                                "sha256": hashlib.sha256((root / "caller.c").read_bytes()).hexdigest()}]}
        history = {"version": 1, "role": "review-history-only", "review": None,
                   "intakes": [], "complete": False, "omissions": [], "source_inputs": snapshot}
        anchor = make_context_source_anchor(source, span, context_inputs_digest(snapshot))
    else:
        anchor = make_source_anchor(source, span)
    entry = ReviewJournalEntry(ts=ts, run_id="owned", file="a.c", function="f",
                              verdict="clean", source_hash=anchor, line_start=line,
                              line_end=line or None, review_claims=history,
                              clean_basis=CLEAN_BASIS_VERDICT)
    return replace(entry, **changes)


def _signed(path, entry):
    append_entry(path, entry)
    loaded = load_entries(path, fresh=True)
    assert len(loaded) == 1
    assert journal_mac.entry_provenance(loaded[0]) == journal_mac.ROW_VERIFIED
    return loaded[0]


def _fold(root, entries, *, reuse):
    covered, sink, stats = set(), {} if reuse else None, {}
    _verify_entries_fold(covered, entries, target_path=root,
                         current_spans={"a.c:f": (1, 1)}, reuse_sink=sink,
                         current_strategies_fn=lambda *_: set(), current_model=None,
                         source_label="owned", reuse_stats=stats)
    return covered, sink, stats


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("change", ["changed", "deleted"])
def test_changed_caller_resurfaces_unchanged_primary(subject, tmp_path, reuse, change):
    row = _signed(tmp_path / "run", _entry(subject))
    assert _fold(subject, [row], reuse=reuse)[0] == {"a.c:f"}
    original = (subject / "a.c").read_bytes()
    if change == "changed":
        (subject / "caller.c").write_text("int caller(void) { return 7; }\n")
    else:
        (subject / "caller.c").unlink()
    covered, sink, stats = _fold(subject, [row], reuse=reuse)
    assert (subject / "a.c").read_bytes() == original
    assert not covered and not sink
    assert stats == {"a.c:f": "review_context_inputs"}


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("bad", ["missing-tag", "missing-summary", "hashless", "unknown", "digest", "incomplete", "primary"])
def test_dependency_pair_required_before_legacy_credit(subject, tmp_path, reuse, bad):
    row = _entry(subject)
    if bad in ("missing-tag", "hashless"):
        row.source_hash = _entry(subject, context=False).source_hash if bad == "missing-tag" else ""
    elif bad == "missing-summary":
        row.review_claims.pop("source_inputs")
    elif bad in ("unknown", "digest"):
        row.source_hash = make_context_source_anchor(hashlib.sha256((subject / "a.c").read_bytes()).hexdigest(),
                            hash_span(subject / "a.c", 1, 1), None if bad == "unknown" else "f" * 64)
    elif bad == "primary":
        row.review_claims["source_inputs"]["sources"] = row.review_claims["source_inputs"]["sources"][1:]
        row.source_hash = make_context_source_anchor(hashlib.sha256((subject / "a.c").read_bytes()).hexdigest(),
                            hash_span(subject / "a.c", 1, 1), context_inputs_digest(row.review_claims["source_inputs"]))
    else:
        row.review_claims["source_inputs"]["complete"] = False
    assert not _fold(subject, [_signed(tmp_path / "run", row)], reuse=reuse)[0]


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("newer_in_project", [False, True])
@pytest.mark.parametrize("old_line", [0, 1])
def test_new_context_blocks_other_source_fallback(subject, tmp_path, reuse, newer_in_project, old_line):
    older = _entry(subject, context=False, line=old_line, ts="2026-11-10T00:00:00Z")
    newer = _entry(subject)
    own, indexed = (older, newer) if newer_in_project else (newer, older)
    own_dir, project = tmp_path / "own", tmp_path / "project"
    _signed(own_dir, own)
    _signed(project / "indexed", indexed)
    merge_into_index(project, project / "indexed")
    (subject / "caller.c").write_text("int caller(void) { return 3; }\n")
    covered, sink, credits = set(), {} if reuse else None, {}
    _fold_journal_into_covered(covered, own_dir, project, target_path=subject,
                              current_spans={"a.c:f": (1, 1)}, credits=credits,
                              reuse_sink=sink, own_run_reuse=reuse,
                              current_strategies_fn=lambda *_: set())
    assert not covered and not sink and not credits


@pytest.mark.parametrize("other_line,newer", [(3, False), (1, True)])
def test_sibling_or_later_independent_review_keeps_credit(subject, tmp_path, other_line, newer):
    own, project = tmp_path / "own", tmp_path / "project"
    _signed(own, _entry(subject))
    _signed(project / "other", _entry(subject, context=False, line=other_line,
            ts="2026-11-10T02:00:00Z" if newer else "2026-11-10T00:00:00Z"))
    merge_into_index(project, project / "other")
    (subject / "caller.c").unlink()
    covered, credits = set(), {}
    _fold_journal_into_covered(covered, own, project, target_path=subject,
                              current_spans={"a.c:f": (1, 1)}, credits=credits)
    assert covered == {"a.c:f"}
    assert credits == {"a.c:f": [other_line]}


def test_portable_inputs_survive_identical_source_relocation(subject, tmp_path):
    row = _signed(tmp_path / "run", _entry(subject))
    moved = tmp_path / "moved"
    moved.mkdir()
    for file in ("a.c", "caller.c"):
        (moved / file).write_bytes((subject / file).read_bytes())
    assert _fold(moved, [row], reuse=True)[0] == {"a.c:f"}


def test_untrusted_context_cannot_invalidate_trusted_other_source(subject, tmp_path):
    trusted = _signed(tmp_path / "run", _entry(subject, context=False, ts="2026-11-10T00:00:00Z"))
    unsigned = _entry(subject)
    unsigned.review_claims["source_inputs"]["complete"] = False
    assert journal_mac.entry_provenance(unsigned) == journal_mac.ROW_UNSTAMPED
    assert _fold(subject, [trusted, unsigned], reuse=False)[0] == {"a.c:f"}


def test_context_review_cannot_be_laundered_into_existence_only_coverage(subject, tmp_path):
    from core.coverage.record import build_from_journal
    from core.coverage.importer import import_journal, import_functions_analysed
    from core.coverage.store import CoverageStore
    from core.audit.gaps import _build_covered_set

    run, project = tmp_path / "run", tmp_path / "project"
    row = _signed(run, _entry(subject))
    record = build_from_journal(run)
    assert record is not None and record["functions_analysed"] == []
    assert merge_into_index(project, run) == 1
    checklist = {"target_path": str(subject), "files": [{"path": "a.c", "items": [
        {"name": "f", "line_start": 1, "line_end": 1}]}]}
    store = CoverageStore(tmp_path / "coverage.json", target="owned")
    assert import_journal(store, project, checklist) == 0
    assert store.who_checked("a.c", 1) == []
    projected = {"file": "a.c", "function": "f", "status": "clean", "hash": row.source_hash}
    projected[journal_mac.TOKEN_KEY] = journal_mac.mint_coverage_row(projected, "journal")
    forged_projection = {"tool": "journal", "functions_analysed": [projected]}
    assert not _build_covered_set([forged_projection], target_path=str(subject), checklist=checklist)
    assert import_functions_analysed(store, forged_projection, {("a.c", "f"): (1, 1)}, {"a.c"}) == 0
    assert store.who_checked("a.c", 1) == []


@pytest.mark.parametrize("reuse", [False, True])
def test_newer_context_review_retires_preexisting_lossy_coverage(subject, tmp_path, reuse):
    run = tmp_path / "run"
    _signed(run, _entry(subject))
    (subject / "caller.c").unlink()
    covered = {"a.c:f", "unrelated.c:g"}
    credits = {}
    sink = {} if reuse else None
    _fold_journal_into_covered(covered, run, None, target_path=subject,
        current_spans={"a.c:f": (1, 1)}, reuse_sink=sink, credits=credits,
        current_strategies_fn=lambda *_: set(), current_model=None, own_run_reuse=reuse)
    assert covered == {"unrelated.c:g"}
    assert not credits and not sink
