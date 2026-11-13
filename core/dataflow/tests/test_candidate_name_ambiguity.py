"""Name deduplication must disclose distinct source observations."""

import json

from core.dataflow.llm_extractor import extract_from_files


def test_candidate_name_ambiguity_is_disclosed(tmp_path):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("def sanitize(value):\n    return value\n")
    candidate = {"name": "sanitize", "qualified_name": "", "semantics_tag": "other",
                 "semantics_text": "Unverified fixture", "confidence": 0.5, "source_line": 1}

    def extractor(_bundle):
        return json.dumps({"validators": [candidate]})

    cache = {}
    retained, errors = extract_from_files(file_paths=["a.py", "b.py"], repo_root=tmp_path, extractor=extractor, cache=cache)
    assert len(retained) == 1
    assert retained[0].source_file == "a.py"
    assert any("ambiguous candidate name" in error and "a.py:1" in error and "b.py:1" in error for error in errors)
    def unexpected_callback(_bundle):
        raise AssertionError("cache replay must not call extractor")

    replayed, replay_errors = extract_from_files(file_paths=["a.py", "b.py"], repo_root=tmp_path,
                                                extractor=unexpected_callback, cache=cache)
    assert replayed == retained
    assert replay_errors == errors
    repeated, errors = extract_from_files(file_paths=["a.py", "a.py"], repo_root=tmp_path, extractor=extractor)
    assert len(repeated) == 1
    assert errors == []
    replies = iter([json.dumps({"validators": [{**candidate, "qualified_name": name}]}) for name in ("a.sanitize", "b.sanitize")])
    distinct, errors = extract_from_files(file_paths=["a.py", "b.py"], repo_root=tmp_path,
                                         extractor=lambda _bundle: next(replies))
    assert len(distinct) == 2
    assert errors == []
