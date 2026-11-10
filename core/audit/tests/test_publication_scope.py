"""Review publication binds source and occurrence without inventing a claim."""

from dataclasses import FrozenInstanceError, asdict, replace

import pytest

from core.audit import collector, record
from core.audit.orchestrator import ReviewOutcome
from core.audit.refutation_source import capture_source_identity
from core.audit.source_anchor import parse_source_anchor
from core.audit.verification_results import ReviewPublicationScope, VerificationScope
from core.coverage.journal import CLEAN_BASIS_VERDICT, load_entries
from core.staleness import hash_span


@pytest.fixture
def subject(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    target = tmp_path / "target"
    target.mkdir()
    path = target / "owned.c"
    path.write_text("#define VALUE 0\nint f(void) { return VALUE; }\n", encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()
    identity = capture_source_identity(target, path.name)
    assert identity is not None
    scope = ReviewPublicationScope(path.name, "f", 2, 2, identity)
    outcome = ReviewOutcome(file=path.name, function="f", line=2, status="clean",
                            body="No finding established in this review.", hypothesis="",
                            review_result={"status": "clean", "hypothesis": ""})
    return {"target": target, "path": path, "run": run, "scope": scope, "outcome": outcome,
            "gap": {"file": path.name, "name": "f", "line_start": 2, "line_end": 2}}


def append(subject, **kwargs):
    return collector.append_journal_for_outcome(
        out_dir=subject["run"], target_path=subject["target"], run_id="owned-run",
        outcome=subject["outcome"], gap=subject["gap"], **kwargs,
    )


def assert_no_entry(subject):
    assert load_entries(subject["run"], fresh=True) == []


def test_clean_empty_hypothesis_has_source_publication_binding_without_proof(subject):
    scope = subject["scope"]
    entry = append(subject, publication_scope=scope)
    assert entry is not None
    stored, = load_entries(subject["run"], fresh=True)
    assert stored.verdict == "clean" and stored.hypotheses == []
    assert stored.clean_basis == CLEAN_BASIS_VERDICT
    assert stored.evidence_tools == []
    assert subject["outcome"].hypothesis == ""
    assert not subject["outcome"].claim_refutations
    assert parse_source_anchor(stored.source_hash) == (
        scope.source_identity.sha256, hash_span(subject["path"], 2, 2),
    )
    with pytest.raises(FrozenInstanceError):
        scope.function = "other"


@pytest.mark.parametrize("change", [
    {"file": "other.c"}, {"function": "other"},
    {"line_start": 3, "line_end": 3}, {"line_end": 3},
])
def test_publication_scope_cannot_move_to_another_occurrence(subject, change):
    mismatched = replace(subject["scope"], **change)
    assert append(subject, publication_scope=mismatched) is None
    assert_no_entry(subject)


@pytest.mark.parametrize("change", [{"line_start": 1}, {"line_end": 3}])
def test_gap_span_must_match_captured_publication_scope(subject, change):
    subject["gap"].update(change)
    assert append(subject, publication_scope=subject["scope"]) is None
    assert_no_entry(subject)


@pytest.mark.parametrize("malformed", ["mapping", "false"])
def test_model_shaped_publication_binding_does_not_produce_an_acknowledgement(subject, malformed):
    value = asdict(subject["scope"]) if malformed == "mapping" else False
    assert append(subject, publication_scope=value) is None
    assert_no_entry(subject)


@pytest.mark.parametrize("identity", [None, {}, "unknown"])
def test_publication_scope_requires_a_known_typed_source_identity(identity):
    with pytest.raises((TypeError, ValueError)):
        ReviewPublicationScope("owned.c", "f", 2, 2, identity)


def test_change_outside_reviewed_span_refuses_publication(subject):
    old_span = hash_span(subject["path"], 2, 2)
    subject["path"].write_text("#define VALUE 1\nint f(void) { return VALUE; }\n", encoding="utf-8")
    assert hash_span(subject["path"], 2, 2) == old_span
    assert append(subject, publication_scope=subject["scope"]) is None
    assert_no_entry(subject)


def test_source_is_rechecked_after_journal_hashing(subject, monkeypatch):
    original = record._compute_hash
    reached = []

    def change_during_hash(*args, **kwargs):
        reached.append("hash")
        subject["path"].write_text("#define VALUE 1\nint f(void) { return VALUE; }\n", encoding="utf-8")
        return original(*args, **kwargs)

    monkeypatch.setattr(record, "_compute_hash", change_during_hash)
    assert append(subject, publication_scope=subject["scope"]) is None
    assert reached == ["hash"]
    assert_no_entry(subject)


def test_missing_span_hash_cannot_become_a_bound_publication(subject, monkeypatch):
    reached = []

    def no_hash(*args, **kwargs):
        reached.append("hash")
        return None

    monkeypatch.setattr(record, "_compute_hash", no_hash)
    assert append(subject, publication_scope=subject["scope"]) is None
    assert reached == ["hash"]
    assert_no_entry(subject)


def test_publication_binding_does_not_bypass_a_claim_binding(subject):
    # An empty clean assessment has no proposition for VerificationScope.
    # The separate source-only scope cannot turn that into claim evidence.
    verification = VerificationScope("owned.c", "f", 2, "", subject["scope"].source_identity)
    assert append(subject, publication_scope=subject["scope"], verification_scope=verification) is None
    assert_no_entry(subject)


@pytest.mark.parametrize("wrong", [None, "publication", "verification"])
def test_supplied_publication_and_verification_bindings_are_conjunctive(subject, wrong):
    outcome = subject["outcome"]
    outcome.status = "suspicious"
    outcome.hypothesis = "owned concern"
    outcome.review_result = {"status": "suspicious", "hypothesis": outcome.hypothesis}
    publication = subject["scope"]
    verification = VerificationScope("owned.c", "f", 2, outcome.hypothesis, publication.source_identity)
    if wrong == "publication":
        publication = replace(publication, function="other")
    elif wrong == "verification":
        verification = replace(verification, function="other")
    entry = append(subject, publication_scope=publication, verification_scope=verification)
    assert (entry is not None) == (wrong is None)
    if wrong is not None:
        assert_no_entry(subject)


def test_publication_append_failure_has_no_acknowledgement(subject, monkeypatch):
    reached = []

    def fail(directory, entry):
        reached.append((directory, entry.verdict))
        raise OSError("owned append failure")

    monkeypatch.setattr(collector, "append_entry", fail)
    assert append(subject, publication_scope=subject["scope"]) is None
    assert reached == [(subject["run"], "clean")]
    assert_no_entry(subject)


def test_publication_hash_cancellation_propagates(subject, monkeypatch):
    def cancel(*args, **kwargs):
        raise KeyboardInterrupt("owned cancellation")

    monkeypatch.setattr(record, "_compute_hash", cancel)
    with pytest.raises(KeyboardInterrupt, match="owned cancellation"):
        append(subject, publication_scope=subject["scope"])
    assert_no_entry(subject)


def test_legacy_unbound_journal_write_keeps_existing_behaviour(subject):
    entry = append(subject)
    assert entry is not None
    stored, = load_entries(subject["run"], fresh=True)
    assert stored.verdict == "clean" and stored.clean_basis == CLEAN_BASIS_VERDICT
    assert parse_source_anchor(stored.source_hash) is None
    assert stored.source_hash == hash_span(subject["path"], 2, 2)
