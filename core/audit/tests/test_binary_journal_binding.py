"""Original binary review inputs remain bound through journal admission."""
from __future__ import annotations

import hashlib

import pytest

from core.audit.binary_context import assemble_binary_context
from core.audit.collector import Collector
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.tests.test_binary_review_availability import _reviewer
from core.inventory import save_checklist
from core.inventory.binary_builder import binary_path_key
from packages.ghidra.model import REDatabase, REFunction


@pytest.fixture
def owned_binary_review(tmp_path):
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    original = b"owned review module, not an executable"
    target.write_bytes(original)
    key = binary_path_key(target)
    gap = {"file": key, "name": "f", "kind": "function", "line_start": 0, "line_end": None,
           "address": 4096, "size": 32}
    checklist = {"files": [{"path": key, "sha256": hashlib.sha256(original).hexdigest(), "items": [gap]}]}
    save_checklist(out, checklist)
    database = REDatabase(source_tool="ghidra", binary_path=str(target), functions=[
        REFunction(name="f", address=4096, size=32, source_tool="ghidra",
                   decompilation="unsigned f(unsigned n) { return n + 1; }")])
    context = assemble_binary_context(target_path=target, file_path=key, function_name="f", db=database)
    reviewer, calls = _reviewer()
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    outcome = runtime.wrap_review(reviewer)(context, OrchestratorConfig(target_path=target, out_dir=out))
    assert len(calls) == 1 and outcome.status == "clean"
    try:
        yield target, out, gap, outcome, runtime, original
    finally:
        runtime.close("test_complete")


def test_module_changed_after_review_cannot_receive_journal_ack(owned_binary_review):
    target, out, gap, outcome, runtime, original = owned_binary_review
    target.write_bytes(b"owned replacement module")
    acknowledgement = Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap)
    assert acknowledgement is None, "journal acknowledged a review after the original module changed"
    assert outcome.cost_usd == .1
    assessments = [event for event in runtime.events() if event["event"] == "review_assessment"]
    assert len(assessments) == 1 and assessments[0]["body"] == outcome.body


def test_healthy_binary_ack_uses_the_full_original_module_digest(owned_binary_review):
    from core.audit.collector import journal_acknowledges_outcome
    target, out, gap, outcome, runtime, original = owned_binary_review
    ack = Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap)
    assert ack is not None and journal_acknowledges_outcome(ack, outcome, gap)
    assert ack.source_hash == f"bin:{hashlib.sha256(original).hexdigest()}:1000:20"
    from dataclasses import replace
    assert not journal_acknowledges_outcome(replace(ack, source_hash="bin:short:1000:20"), outcome, gap)


@pytest.mark.parametrize("change", ["restore_bytes", "replace_inode", "wrong_occurrence", "lost_live_scope", "json_scope"])
def test_original_binary_scope_cannot_be_substituted_or_rebound(owned_binary_review, change):
    target, out, gap, outcome, runtime, original = owned_binary_review
    if change == "restore_bytes":
        target.write_bytes(b"owned changed module")
        target.write_bytes(original)
    elif change == "replace_inode":
        replacement = target.with_suffix(".replacement")
        replacement.write_bytes(original)
        replacement.replace(target)
    elif change == "wrong_occurrence":
        gap = dict(gap, address=8192)
    elif change == "lost_live_scope":
        outcome.binary_publication_scope = None
    else:
        outcome.binary_publication_scope = outcome.binary_publication_scope.record()
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap) is None


def test_module_changed_during_anchor_read_is_refused(owned_binary_review, monkeypatch):
    import core.audit.record as record
    target, out, gap, outcome, runtime, original = owned_binary_review
    read = record.binary_source_hash
    def changing_anchor(*args, **kwargs):
        anchor = read(*args, **kwargs)
        target.write_bytes(b"owned changed module")
        return anchor
    monkeypatch.setattr(record, "binary_source_hash", changing_anchor)
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap) is None


def test_module_changed_after_entry_construction_is_refused_before_append(owned_binary_review, monkeypatch):
    import core.audit.collector as collector
    from core.audit.journal import load_entries
    target, out, gap, outcome, runtime, original = owned_binary_review
    entry_type = collector.ReviewJournalEntry
    class ChangingEntry(entry_type):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            target.write_bytes(b"owned changed module")
    monkeypatch.setattr(collector, "ReviewJournalEntry", ChangingEntry)
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap) is None
    assert load_entries(out, fresh=True) == []


def test_panel_reconstruction_restores_only_the_original_owned_live_scope(owned_binary_review):
    from core.audit.orchestrator import ReviewOutcome, _outcome_to_panel_result
    target, out, gap, outcome, runtime, original = owned_binary_review
    raw = _outcome_to_panel_result(outcome, "captured")
    reconstructed = ReviewOutcome(outcome.file, outcome.function, outcome.status, outcome.body,
                                  review_result=raw)
    assert reconstructed.binary_publication_scope is None
    runtime.bind_review_input_scope(reconstructed)
    assert reconstructed.binary_publication_scope is outcome.binary_publication_scope
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(reconstructed, gap) is not None
    target.write_bytes(b"owned changed module")
    runtime.bind_review_input_scope(reconstructed)
    assert reconstructed.binary_publication_scope is None
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(reconstructed, gap) is None


def test_binary_anchor_does_not_alias_distinct_full_digests():
    from core.audit.record import binary_item_hash
    item = {"address": 4096, "size": 32}
    # A serializer control, not a claim of finding colliding module files.
    left, right = "a" * 12 + "b" * 52, "a" * 12 + "c" * 52
    assert binary_item_hash({"sha256": left}, item) != binary_item_hash({"sha256": right}, item)


def test_legacy_short_binary_anchor_cannot_suppress_a_full_digest_occurrence(tmp_path):
    from core.audit.gaps import compute_gaps
    from core.audit.journal import ReviewJournalEntry, append_entry, merge_into_index, now_iso
    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned stable module")
    key = binary_path_key(target)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    file_entry = {"path": key, "language": "binary", "sha256": digest,
        "items": [{"name": "f", "kind": "function", "address": 4096, "size": 32,
                   "metadata": {"address": 4096, "size": 32}}]}
    checklist = {"target_path": str(target), "target_kind": "binary", "files": [file_entry]}
    project, run = tmp_path / "project", tmp_path / "run"
    project.mkdir()
    run.mkdir()
    append_entry(project, ReviewJournalEntry(ts=now_iso(), run_id="prior", file=key,
        function="f", verdict="clean", source_hash=f"bin:{digest[:12]}:1000:20"))
    merge_into_index(project, project)
    gaps = compute_gaps(checklist, [], out_dir=run, project_dir=project)
    assert any(gap["name"] == "f" for gap in gaps)


@pytest.mark.parametrize("change", ["pass_list", "attempt_dict", "unowned", "source_identity", "false_line", "foreign_intake"])
def test_panel_history_cannot_restore_unowned_or_other_domain_scope(owned_binary_review, change):
    from copy import deepcopy
    from core.audit.orchestrator import ReviewOutcome, _outcome_to_panel_result
    target, out, gap, outcome, runtime, original = owned_binary_review
    raw = deepcopy(_outcome_to_panel_result(outcome, "captured"))
    review = raw["review_claims"]["review"]
    if change == "pass_list":
        review["origin"]["pass_id"] = []
    elif change == "attempt_dict":
        review["attempt_id"] = {}
    elif change == "unowned":
        review["attempt_id"] = "not-an-owned-attempt"
    elif change == "source_identity":
        review["origin"]["source_identity"] = {"sha256": "a" * 64, "version": [1, 2, 3, 4, 5]}
    elif change == "false_line":
        review["origin"]["line_start"] = False
    else:
        foreign = deepcopy(review)
        foreign["origin"]["file"] = "binary:foreign"
        raw["review_claims"]["intakes"].append({"review": foreign, "claims": [],
            "candidate_count": 0, "omitted_count": 0})
    reconstructed = ReviewOutcome(outcome.file, outcome.function, outcome.status, outcome.body,
                                  review_result=raw)
    runtime.bind_review_input_scope(reconstructed)
    assert reconstructed.binary_publication_scope is None
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(reconstructed, gap) is None


def test_projected_gap_uses_exact_checklist_anchor_for_missing_extent_fields(owned_binary_review):
    target, out, gap, outcome, runtime, original = owned_binary_review
    projected = {key: value for key, value in gap.items() if key not in ("address", "size")}
    ack = Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, projected)
    assert ack is not None
    assert ack.source_hash == outcome.binary_publication_scope.anchor()


def test_omitted_gap_extent_cannot_hide_a_different_checklist_occurrence(owned_binary_review):
    from core.audit.gaps import load_checklist
    target, out, gap, outcome, runtime, original = owned_binary_review
    checklist = load_checklist(out)
    checklist["files"][0]["items"][0]["address"] = 8192
    save_checklist(out, checklist)
    projected = {key: value for key, value in gap.items() if key not in ("address", "size")}
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, projected) is None


def test_actual_repeated_review_adapter_preserves_owned_binary_scope(owned_binary_review, monkeypatch):
    from core.audit import orchestrator
    target, out, gap, prior, runtime, original = owned_binary_review
    database = REDatabase(source_tool="ghidra", binary_path=str(target), functions=[
        REFunction(name="f", address=4096, size=32, source_tool="ghidra",
                   decompilation="unsigned f(unsigned n) { return n + 1; }")])
    context = assemble_binary_context(target_path=target, file_path=prior.file, function_name="f", db=database)
    reviewer, calls = _reviewer()
    config = OrchestratorConfig(target_path=target, out_dir=out, review_passes=2)
    monkeypatch.setattr(orchestrator, "_get_llm_client", lambda *args: None)
    outcome = orchestrator._multi_pass_review(runtime.wrap_review(reviewer), context, config, 2,
                                               knowledge_runtime=runtime)
    assert len(calls) == 2 and outcome.status == "clean"
    assert outcome.binary_publication_scope is not None
    assert outcome.binary_publication_scope.module == prior.binary_publication_scope.module
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap) is not None


def test_binary_scope_reconstruction_keeps_caller_and_registry_records_isolated(owned_binary_review):
    from copy import deepcopy
    from core.audit.orchestrator import ReviewOutcome, _outcome_to_panel_result
    target, out, gap, outcome, runtime, original = owned_binary_review
    raw = _outcome_to_panel_result(outcome, "captured")
    before = deepcopy(raw)
    reconstructed = ReviewOutcome(outcome.file, outcome.function, outcome.status, outcome.body,
                                  review_result=raw)
    runtime.bind_review_input_scope(reconstructed)
    assert reconstructed.review_result is not raw
    assert reconstructed.binary_publication_scope is outcome.binary_publication_scope
    assert raw == before
    reconstructed.review_result["binary_review_binding"]["module_sha256"] = "0" * 64
    assert raw == before
    assert outcome.binary_publication_scope.record()["module_sha256"] == hashlib.sha256(original).hexdigest()
    assert Collector(out_dir=out, target_path=target, run_id=out.name).submit(reconstructed, gap) is None
