"""Source windows disclose their retained line range."""

import json

from core.dataflow import cvefix_bridge
from core.dataflow.cvefix_loader import CveFixPair


def test_bridge_discloses_source_window(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "fixture.py"
    source.write_text("".join(f"line_{n} = {n}\n" for n in range(1, 502)))
    sarif = tmp_path / "fixture.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [{"locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "fixture.py"}, "region": {"startLine": 250},
    }}]}]}]}))
    pair = CveFixPair("CVE-FIXTURE", "CWE-22", "https://example.invalid/fixture", "Python", "fix", "parent")
    monkeypatch.setattr(cvefix_bridge, "_git_diff", lambda *args, **kwargs: "")
    monkeypatch.setattr(cvefix_bridge, "_git_diff_other_files", lambda *args, **kwargs: "")
    result = cvefix_bridge._extract_proposal(sarif, repo, pair)
    assert result is not None
    context = result[0].source_context
    assert "Source window: lines 190-309; surrounding source omitted." in context
    assert "line_190 = 190" in context and "line_309 = 309" in context
    assert "line_189 = 189" not in context and "line_310 = 310" not in context
    assert "Source read truncated" not in context
    source.write_text("value = 1\n" * 250)
    complete = cvefix_bridge._extract_proposal(sarif, repo, pair)
    assert complete is not None
    assert "Source window:" not in complete[0].source_context
