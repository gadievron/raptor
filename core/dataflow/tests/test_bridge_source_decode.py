"""Bridge proposals retain source text identity across UTF-8 decoding."""

import json

import pytest

from core.dataflow import cvefix_bridge
from core.dataflow.cvefix_loader import CveFixPair


def test_bridge_refuses_lossy_source_decode(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "fixture.py"
    source.write_bytes(b"value = '\xff'\n")
    sarif = tmp_path / "fixture.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [{"locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "fixture.py"}, "region": {"startLine": 1},
    }}]}]}]}))
    pair = CveFixPair("CVE-FIXTURE", "CWE-22", "https://example.invalid/fixture", "Python", "fix", "parent")
    calls = []
    monkeypatch.setattr(cvefix_bridge, "_git_diff", lambda *a, **k: calls.append("sink") or "")
    monkeypatch.setattr(cvefix_bridge, "_git_diff_other_files", lambda *a, **k: calls.append("other") or "")
    with pytest.raises(UnicodeDecodeError):
        cvefix_bridge._extract_proposal(sarif, repo, pair)
    assert calls == []
    source.write_text("value = 'é�'\n", encoding="utf-8")
    valid = cvefix_bridge._extract_proposal(sarif, repo, pair)
    assert valid is not None
    assert valid[0].sink_snippet == "value = 'é�'"
    assert calls == ["sink", "other"]
