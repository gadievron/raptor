"""Scripted extraction responses must name real integer source lines."""

import json

from core.dataflow.llm_extractor import extract_from_content


def test_extractor_declines_nonexistent_source_locations():
    item = {
        "name": "validate", "qualified_name": "app.validate",
        "semantics_tag": "other", "semantics_text": "Unverified candidate",
        "confidence": 0.5, "source_line": 1,
    }

    def scripted_response(_bundle):
        return json.dumps({"validators": [item]})

    for content in ("pass", "pass\n", "pass\r\n", "pass  # before\u2028after\n"):
        candidates, errors = extract_from_content(
            file_path="app.py", content=content, extractor=scripted_response,
        )
        assert not errors
        assert len(candidates) == 1 and candidates[0].source_line == 1

    for content, line in (("pass\n", 2), ("", 1), ("pass\n", True)):
        item["source_line"] = line
        cache = {}
        candidates, errors = extract_from_content(
            file_path="app.py", content=content, extractor=scripted_response, cache=cache,
        )
        assert candidates == (), (repr(content), repr(line))
        assert any("source_line" in error for error in errors)
        assert not cache


def test_extractor_cache_keeps_source_file_identity():
    calls = []

    def scripted_response(bundle):
        calls.append(bundle)
        return json.dumps({"validators": [{
            "name": "validate", "qualified_name": "validate", "semantics_tag": "other",
            "semantics_text": "Unverified candidate", "confidence": 0.5, "source_line": 1,
        }]})

    cache = {}
    for file_path in ("first.py", "second.py", "second.py"):
        candidates, errors = extract_from_content(
            file_path=file_path, content="pass\n", extractor=scripted_response, cache=cache,
        )
        assert not errors
        assert candidates[0].source_file == file_path
    assert len(calls) == 2
