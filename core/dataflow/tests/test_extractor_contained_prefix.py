"""Prefix extraction must read beneath its root without altering source bytes."""

import json

from core.dataflow import llm_extractor as le


def _response(_bundle):
    return json.dumps({"validators": [{
        "name": "validate", "qualified_name": "validate", "semantics_tag": "other",
        "semantics_text": "Unverified fixture candidate", "confidence": 0.5, "source_line": 1,
    }]})


def test_loader_declines_directory_change_before_read(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    inside = root / "src"
    inside.mkdir(parents=True)
    outside = tmp_path / "outside-fixture"
    outside.mkdir()
    (inside / "app.py").write_text("pass\n")
    (outside / "app.py").write_text("# outside fixture\npass\n")
    candidates, errors = le.extract_from_files(
        file_paths=["src/app.py"], repo_root=root, extractor=_response,
    )
    assert len(candidates) == 1 and not errors
    confine = le.confine
    calls = []
    changed = False

    def change_directory(base, candidate):
        nonlocal changed
        resolved = confine(base, candidate)
        if resolved is not None and not changed:
            changed = True
            inside.rename(tmp_path / "parked-source")
            inside.symlink_to(outside, target_is_directory=True)
        return resolved

    def observe_response(bundle):
        calls.append(bundle)
        return _response(bundle)

    monkeypatch.setattr(le, "confine", change_directory)
    candidates, errors = le.extract_from_files(
        file_paths=["src/app.py"], repo_root=root, extractor=observe_response,
    )
    assert changed and not calls
    assert candidates == ()
    assert any("read failed" in error for error in errors)


def test_invalid_utf8_does_not_replace_valid_file_evidence(tmp_path):
    (tmp_path / "bad.py").write_bytes(b"# \xff\npass\n")
    (tmp_path / "good.py").write_text("pass\n")
    calls = []

    def observe_response(bundle):
        calls.append(bundle)
        return _response(bundle)

    candidates, errors = le.extract_from_files(
        file_paths=["bad.py", "good.py"], repo_root=tmp_path, extractor=observe_response,
    )
    assert len(calls) == 1
    assert len(candidates) == 1 and candidates[0].source_file == "good.py"
    assert any("bad.py" in error and "read failed" in error for error in errors)


def test_contained_prefix_preserves_multibyte_budget_and_newlines(tmp_path, monkeypatch):
    file = tmp_path / "app.py"
    monkeypatch.setattr(le, "DEFAULT_MAX_SOURCE_CHARS", 4)
    source = "x" + "\U0001f642" * 5
    file.write_bytes(source.encode())
    text, truncated = le._read_source_prefix(tmp_path, file)
    assert truncated and text == source[:4]
    assert "\ufffd" not in text
    source = "# \U0001f642\r\n"
    monkeypatch.setattr(le, "DEFAULT_MAX_SOURCE_CHARS", len(source))
    file.write_bytes(source.encode())
    assert le._read_source_prefix(tmp_path, file) == (source, False)
