"""Structured optional omissions retain the request registrar's defaults."""

import pytest

from core.audit.knowledge_requests import register_requests
from core.audit.llm_review import REVIEW_SCHEMA
from core.audit.tests.test_knowledge_requests import _origin
from core.llm.providers import _dict_schema_to_pydantic


def test_structured_omitted_reference_options_reach_request_registrar():
    schema = {"type": "object", "properties": {
        "language_reference_requests": REVIEW_SCHEMA["properties"]["language_reference_requests"]},
        "required": ["language_reference_requests"]}
    parsed = _dict_schema_to_pydantic(schema).model_validate({
        "language_reference_requests": [{"topic": "integer shifts", "needed_for": "Interpret shift preconditions"}]})
    decoded = parsed.model_dump()
    assert decoded["language_reference_requests"][0]["entry_id"] is None
    assert decoded["language_reference_requests"][0]["priority"] is None
    batch = register_requests(decoded, _origin())
    assert not batch.rejected
    request, = batch.accepted
    assert request.priority == "normal" and request.entry_id is None
    assert request.subject == "integer shifts" and request.context == "Interpret shift preconditions"


@pytest.mark.parametrize("field,value,reason", [
    ("topic", None, "invalid_request_fields"),
    ("needed_for", None, "invalid_request_fields"),
    ("priority", "", "invalid_request_fields"),
    ("priority", "urgent", "invalid_request_fields"),
    ("priority", 1, "invalid_request_fields"),
    ("entry_id", 1, "invalid_reference_id"),
    ("source_anchor", {"file": "other.c", "line": 12}, "anchor_outside_review_material"),
])
def test_optional_defaults_do_not_repair_malformed_request_fields(field, value, reason):
    bad = {"topic": "integer shifts", "needed_for": "Interpret shift preconditions", "priority": None, "entry_id": None}
    bad[field] = value
    batch = register_requests({"language_reference_requests": [bad]}, _origin())
    assert batch.accepted == ()
    rejected, = batch.rejected
    assert rejected.reason == reason


def test_structured_study_priority_uses_same_optional_default():
    schema = {"type": "object", "properties": {"reading_list": REVIEW_SCHEMA["properties"]["reading_list"]},
              "required": ["reading_list"]}
    parsed = _dict_schema_to_pydantic(schema).model_validate({"reading_list": [
        {"subject": "owned_type", "resolution": "identifier", "context": "Interpret its representation"}]})
    decoded = parsed.model_dump()
    assert decoded["reading_list"][0]["priority"] is None
    batch = register_requests(decoded, _origin())
    assert not batch.rejected
    request, = batch.accepted
    assert request.priority == "normal" and request.resolution == "identifier"
    assert request.subject == "owned_type" and request.origin == _origin()
