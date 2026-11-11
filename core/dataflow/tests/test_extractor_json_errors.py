"""Decoder refusal must remain a visible, uncached extraction error."""

import json

from core.dataflow.llm_extractor import extract_from_content


def _extract(raw, cache):
    return extract_from_content(
        file_path="app.py", content="pass\n", extractor=lambda _bundle: raw, cache=cache,
    )


def test_large_json_integer_is_an_extraction_error():
    item = {
        "name": "validate", "qualified_name": "validate", "semantics_tag": "other",
        "semantics_text": "Unverified candidate", "confidence": "INTEGER", "source_line": 1,
    }
    raw = json.dumps({"validators": [item]}).replace('"INTEGER"', "9" * 5000)
    cache = {}
    candidates, errors = _extract(raw, cache)
    assert candidates == () and errors
    assert not cache


def test_valid_empty_response_remains_distinct_from_decoder_error():
    cache = {}
    candidates, errors = _extract('{"validators": []}', cache)
    assert candidates == () and not errors
    assert cache
