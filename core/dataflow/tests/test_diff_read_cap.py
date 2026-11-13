"""SARIF byte budgets apply to consumed files, including growth."""

import json
from pathlib import Path

import pytest

from core.dataflow import finding_diff


def test_diff_refuses_growth_after_path_stat(tmp_path, monkeypatch):
    text = json.dumps({"runs": [], "note": "é"}, ensure_ascii=False)
    limit = len(text.encode("utf-8"))
    paths = [tmp_path / "baseline.sarif", tmp_path / "augmented.sarif"]
    monkeypatch.setattr(finding_diff, "SARIF_MAX_BYTES", limit)
    for path in paths:
        path.write_text(text, encoding="utf-8")
    assert finding_diff.diff_sarif_files(*paths).baseline_count == 0
    original_stat = Path.stat
    for changed in paths:
        for path in paths:
            path.write_text(text, encoding="utf-8")
        grew = False

        def stat_then_grow(path, *args, **kwargs):
            nonlocal grew
            result = original_stat(path, *args, **kwargs)
            if path == changed and not grew:
                grew = True
                path.write_text(text + " " * 64, encoding="utf-8")
            return result

        with monkeypatch.context() as patch:
            patch.setattr(Path, "stat", stat_then_grow)
            with pytest.raises(RuntimeError, match="max_bytes|cap"):
                finding_diff.diff_sarif_files(*paths)
        assert grew
