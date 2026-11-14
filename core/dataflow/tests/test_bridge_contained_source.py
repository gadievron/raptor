"""Proposal context must not read source redirected outside its repository."""
import json

from core.dataflow import cvefix_bridge as bridge
from core.dataflow.cvefix_loader import CveFixPair


def test_directory_swap_cannot_supply_proposal_context(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    nested = root / "nested"
    nested.mkdir()
    (nested / "app.py").write_text("consume(value)\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text("OUTSIDE_CONTEXT_SENTINEL\n")
    sarif = tmp_path / "result.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [{"locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "nested/app.py"}, "region": {"startLine": 1},
    }}]}]}]}))
    real_resolve = bridge._resolve_in_repo

    def swap_after_resolution(base, uri):
        resolved = real_resolve(base, uri)
        nested.rename(root / "retired")
        nested.symlink_to(outside, target_is_directory=True)
        return resolved

    monkeypatch.setattr(bridge, "_resolve_in_repo", swap_after_resolution)
    calls = []
    monkeypatch.setattr(bridge, "_git_diff", lambda *a, **k: calls.append("sink") or "")
    monkeypatch.setattr(bridge, "_git_diff_other_files", lambda *a, **k: calls.append("other") or "")
    pair = CveFixPair("CVE-FIXTURE", "CWE-22", "https://example.invalid/fixture", "Python", "fix", "parent")
    result = bridge._extract_proposal(sarif, root, pair)
    assert result is None, "outside source became proposal context"
    assert calls == []
