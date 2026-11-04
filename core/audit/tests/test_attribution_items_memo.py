"""Attribution reuses only a persist operation's private checklist items."""

from copy import deepcopy
import json

import pytest

from core.audit import findings as module
from core.audit.tests.test_findings_attribution import _c_checklist


@pytest.mark.parametrize("path", ["modules/util.c", "missing.c"])
def test_resolution_matches_uncached_and_normalizes_once(monkeypatch, path):
    checklist = _c_checklist()
    # The first matching file entry must win, including legacy layout.
    checklist["files"][0]["functions"] = checklist["files"][0].pop("items")
    checklist["files"].append({"path": "modules/util.c", "items": [{"name": "wrong"}]})
    expected = [module.resolve_function_attribution(checklist, path, claimed, line)
                for claimed, line in (("strcmp", 752), ("compare_certs", 740),
                                      ("unknown", "bad"), ("init_config", 140))]
    original = module._attribution_items
    calls = []

    def counted(*args):
        calls.append(args[1])
        return original(*args)

    monkeypatch.setattr(module, "_attribution_items", counted)
    memo = module._AttributionItemsMemo(checklist)
    actual = [module.resolve_function_attribution(checklist, path, claimed, line, _items_memo=memo)
              for claimed, line in (("strcmp", 752), ("compare_certs", 740),
                                    ("unknown", "bad"), ("init_config", 140))]
    assert actual == expected
    assert calls == [path]
    # A different checklist object never consults the saved entries.
    module.resolve_function_attribution(deepcopy(checklist), path, "strcmp", 752, _items_memo=memo)
    assert calls == [path, path]


def test_source_fallback_still_rereads_file(tmp_path):
    checklist = {"files": [{"path": "a.py", "items": []}]}
    memo = module._AttributionItemsMemo(checklist)
    for name in ("first", "second"):
        (tmp_path / "a.py").write_text(f"def {name}():\n    return 0\n")
        row = {"file": "a.py", "function": "unknown", "line": 2}
        module.stamp_function_attribution(row, checklist, target_path=tmp_path, _items_memo=memo)
        assert row["function"] == name
        assert row["claimed_function"] == "unknown"


def test_failed_normalization_is_not_cached():
    checklist = {"files": [{"path": "a.c", "items": 42}]}
    memo = module._AttributionItemsMemo(checklist)
    row = {"file": "a.c", "function": "claim", "line": 2}
    assert module.stamp_function_attribution(row, checklist, _items_memo=memo) == row
    assert memo.by_file == {}
    with pytest.raises(TypeError):
        module.resolve_function_attribution(checklist, "a.c", "claim", 2, _items_memo=memo)
    assert memo.by_file == {}


def test_retention_bounds_leave_items_available(monkeypatch):
    checklist = {}
    memo = module._AttributionItemsMemo(checklist)
    for index in range(129):
        assert memo.items_for(checklist, f"file{index}.c") is None
    assert len(memo.by_file) == 128
    big = [{}] * 8193
    monkeypatch.setattr(module, "_attribution_items", lambda *args: big)
    memo = module._AttributionItemsMemo(checklist)
    assert memo.items_for(checklist, "big.c") is big
    assert memo.by_file == {} and memo.item_count == 0


def test_persist_equivalence_and_fresh_checklist(monkeypatch, tmp_path):
    from core.audit import gaps
    from core.audit.orchestrator import (
        OrchestratorConfig, OrchestratorResult, ReviewOutcome, _persist_findings,
    )

    checklist = _c_checklist()
    monkeypatch.setattr(gaps, "load_checklist", lambda _: deepcopy(checklist))
    calls = []
    original = module._attribution_items

    def counted(*args):
        calls.append(args[1])
        return original(*args)

    monkeypatch.setattr(module, "_attribution_items", counted)
    result = OrchestratorResult(outcomes=[ReviewOutcome(
        file="modules/util.c", function="strcmp", line=752, status="finding", body="b",
    ) for _ in range(3)])
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
    _persist_findings(result, config)
    expected = (tmp_path / "findings.json").read_bytes()
    assert calls == ["modules/util.c"]
    with monkeypatch.context() as patch:
        patch.setattr(module._AttributionItemsMemo, "items_for",
                      lambda self, checklist, path: module._attribution_items(checklist, path))
        calls.clear()
        _persist_findings(result, config)
        assert (tmp_path / "findings.json").read_bytes() == expected
        assert calls == ["modules/util.c"] * 3
    checklist["files"][0]["items"][0]["name"] = "updated_name"
    calls.clear()
    _persist_findings(result, config)
    rows = json.loads((tmp_path / "findings.json").read_bytes())
    assert all(row["function"] == "updated_name" for row in rows)
    assert calls == ["modules/util.c"]
