"""Owned annotation roots remain stable across source-reader CWD changes."""
from copy import deepcopy
from pathlib import Path

import pytest

from packages.semgrep import nosemgrep


def document():
    return {"runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [
        {"ruleId": "owned", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": name}, "region": {"startLine": 1}}}]}
        for name in ("a.c", "b.c")]}]}


@pytest.mark.parametrize("relative", [True, False], ids=["relative-root", "absolute-control"])
def test_reader_cwd_change_does_not_rebind_repository_root(tmp_path, monkeypatch, relative):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "a.c").write_text("// nosemgrep\n")
    (first / "b.c").write_text("owned\n")
    (second / "b.c").write_text("// nosemgrep\n")
    original = nosemgrep._read_source_lines
    reads = []

    def read(path):
        reads.append(Path(path))
        lines = original(path)
        if Path(path) == first / "a.c":
            monkeypatch.chdir(second)
        return lines

    monkeypatch.setattr(nosemgrep, "_read_source_lines", read)
    monkeypatch.chdir(first)
    doc = document()
    assert nosemgrep.annotate_sarif(doc, "." if relative else first) == 1
    assert reads == [first / "a.c", first / "b.c"]
    results = doc["runs"][0]["results"]
    assert results[0]["properties"]["nosemgrep"]["suppressed"] is True
    assert "nosemgrep" not in results[1].get("properties", {})


def test_unknown_root_identity_does_not_read_or_annotate(monkeypatch):
    class RefusedRoot(type(Path())):
        def absolute(self):
            raise PermissionError("owned root-location refusal")

    def forbidden(path):
        pytest.fail("unknown root identity must not authorise a source read")

    monkeypatch.setattr(nosemgrep, "Path", RefusedRoot)
    monkeypatch.setattr(nosemgrep, "_read_source_lines", forbidden)
    doc = document()
    before = deepcopy(doc)
    assert nosemgrep.annotate_sarif(doc, ".") == 0
    assert doc == before


def test_unexpected_root_identity_error_propagates(monkeypatch):
    class FailedRoot(type(Path())):
        def absolute(self):
            raise RuntimeError("owned unexpected root-location failure")

    monkeypatch.setattr(nosemgrep, "Path", FailedRoot)
    with pytest.raises(RuntimeError, match="owned unexpected root-location failure"):
        nosemgrep.annotate_sarif(document(), ".")
