"""Cache identity accepts lossless filesystem filename strings."""

import json

from core.dataflow.llm_extractor import build_cache_key, extract_from_content


def test_surrogate_filename_cache_identity_is_lossless():
    paths = ("source-\udcff.py", "source-\udcfe.py")
    keys = [build_cache_key(
        file_content_sha="same-content", language="python", model_family="scripted",
        file_path=path,
    ) for path in paths]
    assert keys[0] != keys[1]
    calls = []

    def scripted_response(bundle):
        calls.append(bundle)
        return json.dumps({"validators": [{
            "name": "validate", "qualified_name": "validate", "semantics_tag": "other",
            "semantics_text": "Unverified candidate", "confidence": 0.5, "source_line": 1,
        }]})

    cache = {}
    for path in (*paths, paths[1]):
        candidates, errors = extract_from_content(
            file_path=path, content="pass\n", extractor=scripted_response, cache=cache,
        )
        assert not errors
        assert candidates[0].source_file == path
    assert len(calls) == 2
