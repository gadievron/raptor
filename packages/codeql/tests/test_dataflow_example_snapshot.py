"""Example extraction preserves a caller's failed SARIF read snapshot."""

from pathlib import Path

import core.sarif.parser as parser
from packages.codeql.agent import CodeQLAgent


def document():
    def location(name):
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": name}, "region": {"startLine": 1}}}}
    return {"runs": [{"results": [{"ruleId": "owned/rule", "message": {"text": "owned"},
        "codeFlows": [{"threadFlows": [{"locations": [location("source.c"), location("sink.c")]}]}]}]}]}


def test_failed_preload_is_not_reopened(monkeypatch):
    calls = []

    def read(path):
        calls.append(path)
        return document()

    monkeypatch.setattr(parser, "load_sarif", read)
    assert CodeQLAgent._extract_dataflow_examples(None, Path("owned.sarif"), sarif_data=None) == []
    assert calls == []


def test_omitted_preload_keeps_standalone_reader(monkeypatch):
    calls = []

    def read(path):
        calls.append(path)
        return document()

    monkeypatch.setattr(parser, "load_sarif", read)
    path = Path("owned.sarif")
    result = CodeQLAgent._extract_dataflow_examples(None, path)
    assert calls == [path]
    assert len(result) == 1 and result[0]["source"] == "source.c:1"


def test_explicit_document_keeps_snapshot_and_limit(monkeypatch):
    calls = []

    def read(path):
        calls.append(path)
        return None

    monkeypatch.setattr(parser, "load_sarif", read)
    data = document()
    assert len(CodeQLAgent._extract_dataflow_examples(None, Path("owned.sarif"), sarif_data=data)) == 1
    assert CodeQLAgent._extract_dataflow_examples(None, Path("owned.sarif"), limit=0, sarif_data=data) == []
    assert calls == []
