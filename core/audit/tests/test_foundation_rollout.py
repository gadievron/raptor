"""Current C reading policy applies before either review-retirement lane."""

from copy import deepcopy
from dataclasses import replace
import hashlib

import pytest

from core.audit.gaps import _build_covered_set, _fold_journal_into_covered, _verify_entries_fold, compute_gaps
from core.audit.knowledge_context import reference_delivery, reference_sections
from core.audit.reference_foundation import foundation_answers
from core.audit.reference_inputs import reference_inputs_from_delivery, review_context_digest
from core.audit.review_context_inputs import context_inputs_from_sources
from core.audit.source_anchor import make_context_source_anchor, make_source_anchor
from core.coverage import journal_mac
from core.coverage.journal import (
    CLEAN_BASIS_VERDICT, ReviewJournalEntry, append_entry, load_entries, merge_into_index,
)
from core.staleness import hash_span


@pytest.fixture(autouse=True)
def isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _target(tmp_path, file="unit.c"):
    root = tmp_path / "target"
    root.mkdir(exist_ok=True)
    (root / file).write_text("int f(void) { return 0; }\n")
    return root


def _record(tool="llm", file="unit.c"):
    row = {"file": file, "function": "f", "status": "clean"}
    token = journal_mac.mint_coverage_row(row, tool)
    assert token
    row[journal_mac.TOKEN_KEY] = token
    return {"tool": tool, "functions_analysed": [row]}


def _checklist(root):
    return {"target_path": str(root), "files": [{"path": "unit.c", "language": "c",
            "items": [{"name": "f", "kind": "function", "line_start": 1, "line_end": 1}]}]}


def _entry(root, *, current=False, partial=False, file="unit.c", **changes):
    digest = hashlib.sha256((root / file).read_bytes()).hexdigest()
    span = hash_span(root / file, 1, 1)
    history = None
    anchor = make_source_anchor(digest, span)
    if current:
        answers = foundation_answers("c", request_id="owned-foundation")
        references = reference_inputs_from_delivery(reference_delivery(answers, reference_sections(answers)), answers)
        if partial:
            references = {**references, "entries": [row for row in references["entries"]
                                                    if row["id"] == "c.integer-promotion"]}
        sources = context_inputs_from_sources([("target", file, digest)])
        history = {"version": 1, "role": "review-history-only", "review": None,
                   "intakes": [], "complete": False, "omissions": [],
                   "source_inputs": sources, "reference_inputs": references}
        anchor = make_context_source_anchor(digest, span, review_context_digest(sources, references), context_version=3)
    return ReviewJournalEntry(ts="2026-11-10T00:00:00Z", run_id="owned", file=file, function="f",
        verdict="clean", source_hash=anchor, line_start=1, line_end=1, review_claims=history,
        clean_basis=CLEAN_BASIS_VERDICT, producer=changes.pop("producer", "audit"),
        model=changes.pop("model", "scripted"), **changes)


def _signed(out, row):
    append_entry(out, row)
    loaded = load_entries(out, fresh=True)
    assert len(loaded) == 1 and journal_mac.entry_provenance(loaded[0]) == journal_mac.ROW_VERIFIED
    return loaded[0]


def _fold(root, rows, *, reuse=False, require=True):
    covered, sink, stats = set(), {} if reuse else None, {}
    spans = {f"{row.file}:f": (1, 1) for row in rows}
    _verify_entries_fold(covered, rows, target_path=root, current_spans=spans, reuse_sink=sink,
                         current_strategies_fn=lambda *_: set(), current_model=None,
                         source_label="owned", reuse_stats=stats, require_c_foundation=require)
    return covered, sink, stats


@pytest.mark.parametrize("tool", ["llm", "audit", "journal", "agentic", "validate"])
def test_stamped_model_projection_cannot_establish_current_c_policy(tool):
    record = _record(tool)
    assert _build_covered_set([record]) == {"unit.c:f"}
    assert not _build_covered_set([record], require_c_foundation=True)


@pytest.mark.parametrize("tool", ["mark", "annotations"])
def test_identifiable_human_review_projection_preserves_existing_authority(tool):
    assert _build_covered_set([_record(tool)], require_c_foundation=True) == {"unit.c:f"}


def test_public_gap_computation_requires_policy_without_a_journal(tmp_path):
    root = _target(tmp_path)
    records = [_record()]
    checklist = _checklist(root)
    assert {row["name"] for row in compute_gaps(checklist, records)} == {"f"}
    assert not compute_gaps(checklist, records, require_c_foundation=False)


@pytest.mark.parametrize("tool", ["semgrep", "gcov"])
def test_scanner_and_runtime_observations_remain_stored_without_review_credit(tool):
    record = _record(tool)
    before = deepcopy(record)
    assert not _build_covered_set([record], require_c_foundation=True)
    assert record == before


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("hashless", [False, True])
def test_legacy_model_review_cannot_retire_c_before_any_credit_path(tmp_path, reuse, hashless):
    root = _target(tmp_path)
    row = _entry(root)
    if hashless:
        row = replace(row, source_hash="")
    signed = _signed(tmp_path / "run", row)
    assert _fold(root, [signed], reuse=reuse, require=False)[0] == {"unit.c:f"}
    covered, sink, stats = _fold(root, [signed], reuse=reuse)
    assert not covered and not sink and stats == {"unit.c:f": "reference_foundation"}


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("source", ["own", "index"])
def test_rollout_guard_reaches_own_and_project_sources(tmp_path, reuse, source):
    root = _target(tmp_path)
    run, project = tmp_path / "run", tmp_path / "project"
    _signed(run, _entry(root))
    merge_into_index(project, run)
    covered, sink = set(), {} if reuse else None
    _fold_journal_into_covered(covered, run if source == "own" else None,
        project if source == "index" else None, target_path=root, current_spans={"unit.c:f": (1, 1)},
        reuse_sink=sink, own_run_reuse=reuse, current_strategies_fn=lambda *_: set(),
        require_c_foundation=True)
    assert not covered and not sink


@pytest.mark.parametrize("reuse", [False, True])
def test_actual_current_foundation_is_reusable_and_partial_bundle_is_not(tmp_path, reuse):
    root = _target(tmp_path)
    current = _signed(tmp_path / "current", _entry(root, current=True))
    assert _fold(root, [current], reuse=reuse)[0] == {"unit.c:f"}
    partial = _signed(tmp_path / "partial", _entry(root, current=True, partial=True))
    assert not _fold(root, [partial], reuse=reuse)[0]


def test_changed_current_foundation_is_not_credited(tmp_path, monkeypatch):
    from core.language_reference import c_integer
    root = _target(tmp_path)
    row = _signed(tmp_path / "current", _entry(root, current=True))
    monkeypatch.setattr(c_integer, "ENTRIES", tuple(replace(entry, rule=entry.rule + " Revised.")
        if entry.entry_id == "c.integer-promotion" else entry for entry in c_integer.ENTRIES))
    assert not _fold(root, [row])[0]


@pytest.mark.parametrize("producer", ["mark", "annotations"])
def test_explicit_operator_journal_review_preserves_authority(tmp_path, producer):
    root = _target(tmp_path)
    row = _signed(tmp_path / "manual", _entry(root, producer=producer, model="operator"))
    assert _fold(root, [row])[0] == {"unit.c:f"}


def test_non_c_review_keeps_legacy_behavior(tmp_path):
    root = _target(tmp_path, "unit.py")
    row = _signed(tmp_path / "other", _entry(root, file="unit.py"))
    assert _fold(root, [row])[0] == {"unit.py:f"}
    assert _build_covered_set([_record(file="unit.py")], require_c_foundation=True) == {"unit.py:f"}


def test_binary_subject_projection_is_not_misclassified_as_c_source():
    from core.coverage.journal import make_function_key
    file = "binary:module.c"
    assert _build_covered_set([_record(file=file)], require_c_foundation=True) == {make_function_key(file, "f")}


def test_operator_model_name_alone_does_not_bypass_model_review_policy(tmp_path):
    root = _target(tmp_path)
    row = _signed(tmp_path / "model", _entry(root, producer="audit", model="operator"))
    assert not _fold(root, [row])[0]


def test_binary_inventory_with_c_filename_does_not_gain_source_language_requirements(tmp_path):
    from core.audit.record import binary_item_hash
    anchor = binary_item_hash({'sha256': 'a'*64}, {'address': 4096, 'size': 16})
    row = ReviewJournalEntry(ts='2026-11-10T00:00:00Z',run_id='owned',file='image.c',function='f',
                             verdict='clean',source_hash=anchor,producer='audit',model='scripted')
    row = _signed(tmp_path/'out', row)
    covered=set()
    _verify_entries_fold(covered,[row],target_path=tmp_path,current_spans={},reuse_sink=None,
        binary_hashes={'image.c:f':anchor},current_strategies_fn=lambda *_:set(),current_model=None,
        source_label='owned-binary',require_c_foundation=True)
    assert covered == {'image.c:f'}
    record = _record('audit', 'image.c')
    item = record['functions_analysed'][0]
    item.pop(journal_mac.TOKEN_KEY)
    item['hash'] = anchor
    item[journal_mac.TOKEN_KEY] = journal_mac.mint_coverage_row(item, 'audit')
    checklist = {'files':[{'path':'image.c','sha256':'a'*64,'items':[{'name':'f','address':4096,'size':16}]}]}
    assert _build_covered_set([record],checklist=checklist,require_c_foundation=True) == {'image.c:f'}
