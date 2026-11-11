"""Malformed response fields cannot be converted into candidate facts."""

import hashlib
import json

from core.dataflow import llm_extractor as le
from core.dataflow.sanitizer_evidence import CandidateValidator


def _item():
    return {
        "name": "validate", "qualified_name": "app.validate", "semantics_tag": "other",
        "semantics_text": "Unverified candidate", "confidence": 0.5, "source_line": 1,
    }


def test_malformed_candidate_fields_are_not_coerced_to_facts():
    item = _item()

    def scripted_response(_bundle):
        return json.dumps({"validators": [item]})

    for field, invalid in (
        ("name", None), ("name", 17), ("semantics_text", None), ("semantics_text", []),
        ("qualified_name", 17), ("qualified_name", False), ("qualified_name", []),
        ("confidence", True), ("confidence", False),
    ):
        item = _item()
        item[field] = invalid
        cache = {}
        candidates, errors = le.extract_from_content(
            file_path="app.py", content="pass\n", extractor=scripted_response, cache=cache,
        )
        assert candidates == (), (field, repr(invalid))
        assert any(field in error for error in errors)
        assert not cache


def test_valid_text_and_optional_qualified_names_remain_supported():
    item = _item()

    def scripted_response(_bundle):
        return json.dumps({"validators": [item]})

    for name, optional, confidence in (
        (" validate ", None, 0), ("validate", "", 1),
        ("validate", "  ", 0.5), ("None", "", "0.5"),
    ):
        item = _item()
        item.update(name=name, qualified_name=optional, confidence=confidence)
        candidates, errors = le.extract_from_content(
            file_path="app.py", content="pass\n", extractor=scripted_response,
        )
        assert not errors
        assert candidates[0].name == candidates[0].qualified_name == name.strip()
        assert candidates[0].confidence == float(confidence)


def test_large_confidence_reports_extraction_error():
    item = _item()
    item["confidence"] = 10 ** 400
    candidates, errors = le.extract_from_content(
        file_path="app.py", content="pass\n",
        extractor=lambda _bundle: json.dumps({"validators": [item]}),
    )
    assert candidates == ()
    assert any("confidence" in error for error in errors)


def test_response_policy_change_invalidates_cached_candidate(monkeypatch):
    content = "pass\n"
    key = le.build_cache_key(
        file_content_sha=hashlib.sha256(content.encode()).hexdigest(),
        language="python", model_family="default", file_path="app.py",
    )
    legacy = CandidateValidator.from_dict({
        **_item(), "name": "None", "source_file": "app.py", "extraction_provenance": "llm",
    })
    cache = {key: (legacy,)}
    monkeypatch.setattr(le, "_RESPONSE_SCHEMA_VERSION", le._RESPONSE_SCHEMA_VERSION + 1)
    calls = []

    def scripted_response(bundle):
        calls.append(bundle)
        return json.dumps({"validators": [_item()]})

    candidates, errors = le.extract_from_content(
        file_path="app.py", content=content, extractor=scripted_response, cache=cache,
    )
    assert not errors and len(calls) == 1
    assert candidates[0].name == "validate"
    assert cache[key] == (legacy,)
