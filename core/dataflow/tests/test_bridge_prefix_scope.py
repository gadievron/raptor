"""A useful in-prefix target must still disclose incomplete source reads."""

import json

from core.dataflow import cvefix_bridge
from core.dataflow.cvefix_loader import CveFixPair


def test_bridge_discloses_truncated_source_prefix(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fixture.py").write_text("value = 'fixture'\nconsume(value)\n" + "pad = 0\n" * 10 + "TAIL_SENTINEL = 1\n")
    sarif = tmp_path / "fixture.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [{"locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "fixture.py"}, "region": {"startLine": 1},
    }}]}]}]}))
    pair = CveFixPair("CVE-FIXTURE", "CWE-22", "https://example.invalid/fixture", "Python", "fixture-fix", "fixture-parent")
    monkeypatch.setattr(cvefix_bridge, "_git_diff", lambda *args, **kwargs: "")
    monkeypatch.setattr(cvefix_bridge, "_git_diff_other_files", lambda *args, **kwargs: "")
    original_reader = cvefix_bridge.read_contained_text_capped
    cap = 20
    flags = []

    def reader(root, path, **kwargs):
        result = original_reader(root, path, max_chars=cap, **kwargs)
        flags.append(result[1])
        return result

    monkeypatch.setattr(cvefix_bridge, "read_contained_text_capped", reader)
    prefix = cvefix_bridge._extract_proposal(sarif, repo, pair)
    assert prefix is not None and prefix[2] == 1
    assert flags == [True]
    assert "source read truncated" in prefix[0].source_context.lower()
    assert "TAIL_SENTINEL" not in prefix[0].source_context
    cap = 10000
    flags.clear()
    complete = cvefix_bridge._extract_proposal(sarif, repo, pair)
    assert complete is not None and complete[0].sink_snippet == prefix[0].sink_snippet
    assert flags == [False]
    assert "source read truncated" not in complete[0].source_context.lower()
    assert "TAIL_SENTINEL" in complete[0].source_context
