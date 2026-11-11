"""Expose partial extraction without discarding prefix candidates."""

import json

from core.dataflow import llm_extractor as le


def test_prefix_extraction_reports_incomplete_coverage(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    header = "def validate(value):\n    return value\n"
    source.write_text(header)
    reader = le.read_text_capped
    prompts = []

    def bounded_read(file, **kwargs):
        return reader(file, 128, **kwargs)

    def scripted_response(bundle):
        prompts.append(bundle)
        return json.dumps({"validators": [{
            "name": "validate", "qualified_name": "app.validate", "semantics_tag": "other",
            "semantics_text": "Unverified prefix candidate", "confidence": 0.5,
            "source_line": 1,
        }]})

    monkeypatch.setattr(le, "read_text_capped", bounded_read)
    cache = {}
    candidates, errors = le.extract_from_files(
        file_paths=["app.py"], repo_root=tmp_path, extractor=scripted_response, cache=cache,
    )
    assert len(candidates) == 1 and not errors
    source.write_text(header + "# padding\n" * 30)
    assert bounded_read(source)[1] is True
    candidates, errors = le.extract_from_files(
        file_paths=["app.py"], repo_root=tmp_path, extractor=scripted_response, cache=cache,
    )
    assert len(candidates) == 1
    assert any("app.py" in error and "truncated" in error for error in errors)
    cached_candidates, cached_errors = le.extract_from_files(
        file_paths=["app.py"], repo_root=tmp_path, extractor=scripted_response, cache=cache,
    )
    assert cached_candidates == candidates
    assert cached_errors == errors
    assert len(prompts) == 2
