"""Parsed analysis artefacts cannot reuse a prior physical file version."""
import json
import os

from core.audit.binary_context import load_redb


def _document(note):
    return json.dumps({"source_tool": "r2", "binary_path": "fixture.bin", "functions": [],
                       "metadata": {"analysis_note": note}})


def test_restored_mtime_json_rewrite_invalidates_parsed_analysis(tmp_path):
    artifact = tmp_path / "re-database.json"
    artifact.write_text(_document("before"))
    first = load_redb(artifact)
    assert first.metadata["analysis_note"] == "before"
    assert load_redb(artifact) is first
    before = artifact.stat()
    artifact.write_text(_document("after!"))
    os.utime(artifact, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = artifact.stat()
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
    assert after.st_ctime_ns != before.st_ctime_ns
    assert json.loads(artifact.read_text())["metadata"]["analysis_note"] == "after!"
    current = load_redb(artifact)
    assert current.metadata["analysis_note"] == "after!" and current is not first
    assert load_redb(artifact) is current


def test_replaced_json_inode_invalidates_parsed_analysis(tmp_path):
    artifact = tmp_path / "re-database.json"
    artifact.write_text(_document("before"))
    first = load_redb(artifact)
    before = artifact.stat()
    replacement = tmp_path / "replacement.json"
    replacement.write_text(_document("after!"))
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(replacement, artifact)
    after = artifact.stat()
    assert after.st_ino != before.st_ino
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
    current = load_redb(artifact)
    assert current.metadata["analysis_note"] == "after!" and current is not first


def test_cached_analysis_cannot_bypass_a_reduced_existing_read_budget(tmp_path, monkeypatch):
    import pytest
    import core.audit.binary_context as context
    from core.json.utils import JsonBudgetExceededError
    artifact = tmp_path / "re-database.json"
    artifact.write_text(_document("before"))
    first = load_redb(artifact)
    assert first.metadata["analysis_note"] == "before"
    monkeypatch.setattr(context, "_MAX_REDB_BYTES", 16)
    with pytest.raises(JsonBudgetExceededError):
        load_redb(artifact)
