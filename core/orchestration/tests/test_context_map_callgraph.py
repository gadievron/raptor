"""Tests for ``core.orchestration.context_map_callgraph`` —
forward-reachable closure enrichment for /understand --map's
context-map.json output."""

from __future__ import annotations

from pathlib import Path

from core.orchestration.context_map_callgraph import (
    enrich_with_forward_reachable,
)


def _project(tmp_path: Path, files: dict) -> Path:
    for rel, contents in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)
    return tmp_path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_enrich_simple_entry_point(tmp_path):
    """Entry point reaches an internal function and an external
    dep — both surface in the forward_reachable field."""
    target = _project(tmp_path, {
        "src/routes/query.py": (
            "import sqlite3\n"
            "from src.db import run_query\n"
            "def handle_query():\n"             # line 3
            "    sqlite3.connect('x')\n"
            "    return run_query('SELECT 1')\n"
        ),
        "src/db.py": (
            "def run_query(sql):\n"
            "    pass\n"
        ),
    })
    cmap = {
        "entry_points": [{
            "id": "EP-001",
            "file": "src/routes/query.py",
            "line": 3,
        }],
    }
    enriched = enrich_with_forward_reachable(cmap, target)
    assert enriched == 1
    fr = cmap["entry_points"][0]["forward_reachable"]
    assert fr["host"] == "src/routes/query.py:handle_query@3"
    assert fr["internal_count"] >= 1
    assert any(
        "run_query" in n for n in fr["internal_names"]
    )
    assert fr["external_count"] >= 1
    assert any(
        "sqlite3" in n for n in fr["external_names"]
    )
    assert fr["truncated"] is False


def test_enrich_skips_entry_without_file_or_line(tmp_path):
    target = _project(tmp_path, {"src/v.py": "def f(): pass\n"})
    cmap = {
        "entry_points": [
            {"id": "EP-1", "file": "src/v.py"},          # no line
            {"id": "EP-2", "line": 1},                     # no file
            {"id": "EP-3", "file": "", "line": 5},         # empty file
            {"id": "EP-4", "file": "src/v.py", "line": 0}, # invalid line
        ],
    }
    enriched = enrich_with_forward_reachable(cmap, target)
    assert enriched == 0
    for ep in cmap["entry_points"]:
        assert "forward_reachable" not in ep


def test_enrich_skips_unresolvable_host(tmp_path):
    """File not in the inventory → no host → skip silently."""
    target = _project(tmp_path, {"src/real.py": "def f(): pass\n"})
    cmap = {
        "entry_points": [{
            "id": "EP-1", "file": "src/missing.py", "line": 1,
        }],
    }
    enriched = enrich_with_forward_reachable(cmap, target)
    assert enriched == 0
    assert "forward_reachable" not in cmap["entry_points"][0]


def test_enrich_handles_module_level_lines(tmp_path):
    """Line outside any function (module scope) → no host → skip."""
    target = _project(tmp_path, {
        "src/v.py": (
            "import os\n"               # line 1, module scope
            "def f():\n"
            "    pass\n"
        ),
    })
    cmap = {
        "entry_points": [{
            "id": "EP-1", "file": "src/v.py", "line": 1,
        }],
    }
    enriched = enrich_with_forward_reachable(cmap, target)
    assert enriched == 0


# ---------------------------------------------------------------------------
# Caps and bounds
# ---------------------------------------------------------------------------


def test_enrich_caps_internal_names(tmp_path):
    """When internal_count exceeds max_names_per_list, the names
    list is capped but the count reflects the full closure."""
    # entry → 12 internal helpers, each calling its own pass()
    src = ["def entry():"]
    for i in range(12):
        src.append(f"    h{i}()")
    for i in range(12):
        src.append(f"def h{i}():")
        src.append("    pass")
    target = _project(tmp_path, {
        "src/v.py": "\n".join(src) + "\n",
    })
    cmap = {
        "entry_points": [{
            "id": "EP-1", "file": "src/v.py", "line": 1,
        }],
    }
    enriched = enrich_with_forward_reachable(
        cmap, target, max_names_per_list=5,
    )
    assert enriched == 1
    fr = cmap["entry_points"][0]["forward_reachable"]
    assert fr["internal_count"] == 12
    assert len(fr["internal_names"]) == 5


def test_enrich_truncates_at_max_depth(tmp_path):
    """A deep chain hits max_depth → truncated flag set."""
    # f0 → f1 → f2 → f3 → ... → f9
    src = ["def f0():", "    f1()"]
    for i in range(1, 10):
        src.append(f"def f{i}():")
        if i == 9:
            src.append("    pass")
        else:
            src.append(f"    f{i + 1}()")
    target = _project(tmp_path, {
        "src/v.py": "\n".join(src) + "\n",
    })
    cmap = {
        "entry_points": [{
            "id": "EP-1", "file": "src/v.py", "line": 1,
        }],
    }
    enriched = enrich_with_forward_reachable(cmap, target, max_depth=3)
    assert enriched == 1
    fr = cmap["entry_points"][0]["forward_reachable"]
    assert fr["truncated"] is True


def test_enrich_idempotent(tmp_path):
    """Running twice produces the same enrichment — second run
    overwrites with fresh data."""
    target = _project(tmp_path, {
        "src/v.py": (
            "def helper():\n"
            "    pass\n"
            "def entry():\n"
            "    helper()\n"
        ),
    })
    cmap = {
        "entry_points": [{
            "id": "EP-1", "file": "src/v.py", "line": 3,
        }],
    }
    enrich_with_forward_reachable(cmap, target)
    fr1 = dict(cmap["entry_points"][0]["forward_reachable"])
    enrich_with_forward_reachable(cmap, target)
    fr2 = cmap["entry_points"][0]["forward_reachable"]
    assert fr1 == fr2


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_enrich_handles_empty_entry_points(tmp_path):
    target = _project(tmp_path, {"src/v.py": "def f(): pass\n"})
    assert enrich_with_forward_reachable({"entry_points": []}, target) == 0
    assert enrich_with_forward_reachable({}, target) == 0
    assert enrich_with_forward_reachable(
        {"entry_points": "not-a-list"}, target,
    ) == 0


def test_enrich_handles_non_dict_entries(tmp_path):
    target = _project(tmp_path, {"src/v.py": "def f(): pass\n"})
    cmap = {
        "entry_points": [
            "string-not-dict",
            42,
            None,
            {"id": "EP-1", "file": "src/v.py", "line": 1},
        ],
    }
    # Should process the dict and skip the non-dicts without raising.
    enrich_with_forward_reachable(cmap, target)
    # The valid entry should be processed (even if no enrichment lands).
    assert isinstance(cmap["entry_points"][3], dict)
