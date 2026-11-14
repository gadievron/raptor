"""Bridge proposals require a real line in the captured source snapshot."""

import json

from core.dataflow import cvefix_bridge
from core.dataflow.cvefix_loader import CveFixPair


def test_bridge_skips_unsupported_target_lines(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fixture.py").write_text("value = 'fixture'\nconsume(value)\n")
    pair = CveFixPair("CVE-FIXTURE", "CWE-22", "https://example.invalid/fixture", "Python", "fixture-fix", "fixture-parent")
    calls = []

    def diff(*args, **kwargs):
        calls.append("diff")
        return ""

    monkeypatch.setattr(cvefix_bridge, "_git_diff", diff)
    monkeypatch.setattr(cvefix_bridge, "_git_diff_other_files", diff)
    sarif = tmp_path / "fixture.sarif"

    def extract(lines):
        locations = [{"physicalLocation": {"artifactLocation": {"uri": "fixture.py"},
                                            "region": {"startLine": line}}} for line in lines]
        sarif.write_text(json.dumps({"runs": [{"results": [{"locations": locations}]}]}))
        return cvefix_bridge._extract_proposal(sarif, repo, pair)

    valid = extract([2])
    assert valid is not None and valid[2] == 2
    assert valid[0].sink_snippet == "consume(value)"
    original_reader = cvefix_bridge.read_contained_text_capped

    def unexpected_source_read(*args, **kwargs):
        raise AssertionError("malformed target line must refuse before source access")

    with monkeypatch.context() as guard:
        guard.setattr(cvefix_bridge, "read_contained_text_capped", unexpected_source_read)
        for invalid in (True, False, 0, -1, 1.5, "2"):
            calls.clear()
            assert extract([invalid]) is None
            assert calls == []
    calls.clear()
    assert extract([3]) is None
    assert calls == []
    later = extract([3, 2])
    assert later is not None and later[2] == 2
    monkeypatch.setattr(
        cvefix_bridge, "read_contained_text_capped",
        lambda root, path, **kwargs: original_reader(root, path, max_chars=20, **kwargs),
    )
    assert extract([1]) is not None
    assert extract([2]) is None
