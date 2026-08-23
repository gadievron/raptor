"""New/changed-code priority signal.

``ensure_inventory_diff`` materialises ``inventory-diff.json`` for a
fresh run directory by diffing against the most recent sibling run's
checklist; ``load_new_functions`` prefers the hash-based function-level
keys; compute_gaps applies a bounded tier boost; and score_functions
receives ``new_functions`` so SCORE_NEW_CODE orders new code first.
"""

from __future__ import annotations

import json

from core.audit.gaps import compute_gaps
from core.audit.priority import (
    SCORE_NEW_CODE,
    ensure_inventory_diff,
    load_new_functions,
    score_functions,
)


def _checklist(alpha_hash="aaaaaaaaaaaa", with_gamma=False):
    items = [
        {"name": "alpha", "kind": "function", "line_start": 1,
         "line_end": 12, "span_hash": alpha_hash},
        {"name": "beta", "kind": "function", "line_start": 14,
         "line_end": 25, "span_hash": "bbbbbbbbbbbb"},
    ]
    if with_gamma:
        items.append({"name": "gamma", "kind": "function",
                      "line_start": 27, "line_end": 38,
                      "span_hash": "cccccccccccc"})
    return {
        "target_path": "/tmp/proj",
        "files": [{"path": "a.py", "sha256": alpha_hash * 2,
                   "items": items}],
    }


class TestLoadNewFunctions:
    def test_prefers_function_level_keys(self, tmp_path):
        (tmp_path / "inventory-diff.json").write_text(json.dumps({
            "added": [], "removed": [], "modified": ["a.py"],
            "functions_added": ["a.py:gamma"],
            "functions_changed": ["a.py:alpha"],
        }))
        keys = load_new_functions(tmp_path, _checklist(with_gamma=True))
        assert keys == {"a.py:gamma", "a.py:alpha"}

    def test_legacy_file_level_fallback(self, tmp_path):
        (tmp_path / "inventory-diff.json").write_text(json.dumps({
            "added": [], "removed": [], "modified": ["a.py"],
        }))
        keys = load_new_functions(tmp_path, _checklist())
        assert keys == {"a.py:alpha", "a.py:beta"}


class TestEnsureInventoryDiff:
    def _project(self, tmp_path):
        prev = tmp_path / "run1"
        cur = tmp_path / "run2"
        prev.mkdir()
        cur.mkdir()
        # Sibling discovery requires run manifests when target-filtered.
        for d in (prev, cur):
            (d / ".raptor-run.json").write_text(json.dumps(
                {"target_path": "/tmp/proj"}))
        return prev, cur

    def test_diffs_against_latest_sibling_run(self, tmp_path):
        prev, cur = self._project(tmp_path)
        (prev / "checklist.json").write_text(json.dumps(_checklist()))
        current = _checklist(alpha_hash="dddddddddddd", with_gamma=True)
        current["files"][0]["sha256"] = "different-sha"

        keys = ensure_inventory_diff(cur, current, target_path="/tmp/proj")
        assert keys == {"a.py:alpha", "a.py:gamma"}
        diff = json.loads((cur / "inventory-diff.json").read_text())
        assert "a.py:alpha" in diff["functions_changed"]
        assert "a.py:gamma" in diff["functions_added"]
        assert "a.py:beta" not in diff["functions_changed"]

    def test_no_previous_inventory_is_empty(self, tmp_path):
        cur = tmp_path / "run1"
        cur.mkdir()
        (cur / ".raptor-run.json").write_text("{}")
        assert ensure_inventory_diff(cur, _checklist()) == set()
        assert not (cur / "inventory-diff.json").exists()

    def test_existing_diff_is_respected(self, tmp_path):
        _prev, cur = self._project(tmp_path)
        (cur / "inventory-diff.json").write_text(json.dumps({
            "functions_added": ["a.py:beta"], "functions_changed": [],
        }))
        keys = ensure_inventory_diff(cur, _checklist())
        assert keys == {"a.py:beta"}


class TestGapBoost:
    def test_new_code_gap_is_boosted_and_flagged(self, tmp_path):
        (tmp_path / "inventory-diff.json").write_text(json.dumps({
            "functions_added": [],
            "functions_changed": ["a.py:alpha"],
        }))
        gaps = compute_gaps(_checklist(), [], out_dir=tmp_path)
        by_name = {g["name"]: g for g in gaps}
        assert by_name["alpha"].get("new_code") is True
        assert "new_code" not in by_name["beta"]
        # Boosted gap sorts ahead of its unboosted twin.
        assert [g["name"] for g in gaps].index("alpha") < \
            [g["name"] for g in gaps].index("beta")

    def test_dead_code_is_not_boosted(self, tmp_path):
        (tmp_path / "inventory-diff.json").write_text(json.dumps({
            "functions_added": [], "functions_changed": ["a.py:alpha"],
        }))
        checklist = _checklist()
        checklist["files"][0]["items"][0]["lexical_dead"] = True
        gaps = compute_gaps(checklist, [], out_dir=tmp_path)
        alpha = next(g for g in gaps if g["name"] == "alpha")
        assert "new_code" not in alpha


class TestScoreOrdering:
    def test_new_functions_kwarg_orders_new_code_first(self):
        gaps = [
            {"file": "a.py", "name": "old_fn", "priority": 1, "sloc": 10,
             "strategies": [], "line_start": 1, "line_end": 10},
            {"file": "a.py", "name": "new_fn", "priority": 1, "sloc": 10,
             "strategies": [], "line_start": 12, "line_end": 21},
        ]
        scored = score_functions(gaps, new_functions={"a.py:new_fn"})
        assert [g["name"] for g in scored] == ["new_fn", "old_fn"]
        new = next(g for g in scored if g["name"] == "new_fn")
        old = next(g for g in scored if g["name"] == "old_fn")
        assert new["priority_score"] - old["priority_score"] == SCORE_NEW_CODE
