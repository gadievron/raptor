"""Review requests gain pipeline identity, never model-provided provenance."""

import pytest

from core.audit.knowledge_requests import KnowledgeOrigin, register_requests
from core.audit.refutation_source import SourceIdentity


def _origin():
    return KnowledgeOrigin("owned-pass", "owned.c", "f", 10, 15,
                           SourceIdentity("a" * 64, (1, 2, 3, 4, 5)))


def test_subject_and_language_topic_are_distinct_with_pipeline_origin():
    origin = _origin()
    review = {
        "reading_list": [{"subject": "foo_t", "resolution": "identifier",
                          "request_id": "forged", "pass_id": "forged", "source_identity": "forged"}],
        "language_reference_requests": [{"topic": "integer promotion", "source_anchor": {"file": "owned.c", "line": 12}}],
    }
    batch = register_requests(review, origin)
    assert not batch.rejected
    assert [r.kind for r in batch.accepted] == ["target_study", "language_reference"]
    assert all(r.origin is origin and r.request_id != "forged" for r in batch.accepted)
    assert batch.accepted[0].request_id != batch.accepted[1].request_id
    review["reading_list"][0]["subject"] = "other_t"
    assert batch.accepted[0].subject == "foo_t"


def test_caller_review_question_is_not_rewritten_as_source_study():
    batch = register_requests({"reading_list": [
        {"question": "does this caller enforce the bound"},
        {"subject": "does this caller enforce the bound", "resolution": "concept"},
        {"subject": "page tables", "resolution": "concept"},
    ]}, _origin())
    assert [r.subject for r in batch.accepted] == ["page tables"]
    assert [r.reason for r in batch.rejected] == ["invalid_request_fields", "study_requires_subject_not_question"]


def test_reference_anchor_must_be_in_supplied_review_scope():
    batch = register_requests({"language_reference_requests": [
        {"topic": "conversion", "source_anchor": {"file": "other.c", "line": 12}},
        {"topic": "conversion", "source_anchor": {"file": "owned.c", "line": 16}},
        {"topic": "conversion", "source_anchor": {"file": "owned.c", "line": True}},
        {"topic": "conversion", "source_anchor": {"file": "owned.c", "line": 10}},
    ]}, _origin())
    assert len(batch.accepted) == 1
    assert batch.accepted[0].source_line == 10
    assert len(batch.rejected) == 3
    assert all(r.reason == "anchor_outside_review_material" for r in batch.rejected)


def test_duplicates_and_overflow_have_explicit_dispositions():
    batch = register_requests({"reading_list": [{"subject": "foo_t"}] * 19}, _origin())
    assert len(batch.accepted) == 1
    assert sum(r.count for r in batch.rejected) == 18
    assert batch.rejected[0].reason == "request_limit"


def test_empty_requests_are_valid_and_unknown_source_is_not_certified():
    origin = KnowledgeOrigin("p", "binary:owned", "f", 0, 0, None)
    empty = register_requests({}, origin)
    assert not empty.accepted and not empty.rejected
    batch = register_requests({"reading_list": [{"subject": "foo_t"}]}, origin)
    assert batch.accepted[0].origin.source_identity is None


def test_distinct_symbols_and_learning_contexts_are_not_lost_as_duplicates():
    batch = register_requests({"reading_list": [
        {"subject": "Foo"}, {"subject": "foo"}, {"subject": "is"},
        {"subject": "Foo", "context": "relationship to the enclosing object"},
    ]}, _origin())
    assert not batch.rejected
    assert len(batch.accepted) == 4


@pytest.mark.parametrize("invalid", ["\ud800", "\udfff"], ids=["high-surrogate", "low-surrogate"])
@pytest.mark.parametrize("field,name,reason", [
    ("reading_list", "subject", "invalid_request_fields"),
    ("reading_list", "context", "invalid_request_fields"),
    ("language_reference_requests", "topic", "invalid_request_fields"),
    ("language_reference_requests", "needed_for", "invalid_request_fields"),
    ("language_reference_requests", "entry_id", "invalid_reference_id"),
])
def test_non_utf8_request_text_is_rejected_without_losing_valid_sibling(field, name, reason, invalid):
    bad = {"subject": "target type", "resolution": "concept"} if field == "reading_list" else {"topic": "conversion"}
    bad[name] = invalid
    valid = {"subject": "other_t"} if field == "reading_list" else {"topic": "integer promotion"}
    batch = register_requests({field: [bad, valid]}, _origin())
    assert len(batch.accepted) == 1
    assert batch.accepted[0].subject == valid.get("subject", valid.get("topic"))
    rejected, = batch.rejected
    assert (rejected.field, rejected.index, rejected.reason) == (field, 0, reason)


def test_valid_unicode_request_text_is_retained_without_repair():
    text = "café 東京 😀"
    context = text + "\nContinued context."
    batch = register_requests({
        "reading_list": [{"subject": text, "resolution": "concept", "context": context}],
        "language_reference_requests": [{"topic": text, "needed_for": context, "entry_id": text}],
    }, _origin())
    assert not batch.rejected
    assert len(batch.accepted) == 2
    assert all(request.subject == text and request.context == context for request in batch.accepted)
    assert batch.accepted[1].entry_id == text
