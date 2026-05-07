"""Tests for ``core.orchestration.reachability_enrichment``."""

from __future__ import annotations

from pathlib import Path

from core.orchestration.reachability_enrichment import (
    _path_to_module,
    mark_unreachable_low_priority,
)


def _project(tmp_path: Path, files: dict) -> Path:
    """Drop ``files`` (path → contents) under tmp_path."""
    for rel, contents in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)
    return tmp_path


def _checklist(files_funcs: dict) -> dict:
    """Build a minimal checklist with ``{rel_path: [{name, ...}, ...]}``."""
    return {
        "files": [
            {"path": rel, "items": funcs}
            for rel, funcs in files_funcs.items()
        ],
    }


# ---------------------------------------------------------------------------
# Marking behaviour
# ---------------------------------------------------------------------------


def test_marks_dead_function_low_priority(tmp_path):
    """Function not called from anywhere → priority=low."""
    target = _project(tmp_path, {
        "src/vuln.py": (
            "def dead(): pass\n"
            "def alive(): pass\n"
        ),
        "src/main.py": (
            "from src.vuln import alive\n"
            "alive()\n"
        ),
    })
    checklist = _checklist({
        "src/vuln.py": [
            {"name": "dead", "kind": "function"},
            {"name": "alive", "kind": "function"},
        ],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    assert marked == 1
    funcs = {f["name"]: f for f in checklist["files"][0]["items"]}
    assert funcs["dead"]["priority"] == "low"
    assert funcs["dead"]["priority_reason"] == "reachability:not_called"
    # alive function untouched.
    assert "priority" not in funcs["alive"]


def test_does_not_overwrite_high_priority(tmp_path):
    """Function already marked priority=high (from context-map
    enrichment) is left alone even if NOT_CALLED."""
    target = _project(tmp_path, {
        "src/vuln.py": "def entry_point(): pass\n",
        "src/main.py": "x = 1\n",
    })
    checklist = _checklist({
        "src/vuln.py": [{
            "name": "entry_point",
            "kind": "function",
            "priority": "high",
            "priority_reason": "entry_point",
        }],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    assert marked == 0
    func = checklist["files"][0]["items"][0]
    assert func["priority"] == "high"
    assert func["priority_reason"] == "entry_point"


def test_skips_uncertain_dispatch(tmp_path):
    """File using getattr → UNCERTAIN → no downgrade."""
    target = _project(tmp_path, {
        "src/vuln.py": "def affected(): pass\n",
        "src/main.py": (
            "from src import vuln\n"
            "fn = getattr(vuln, 'affected')\n"
            "fn()\n"
        ),
    })
    checklist = _checklist({
        "src/vuln.py": [{"name": "affected", "kind": "function"}],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    assert marked == 0
    func = checklist["files"][0]["items"][0]
    assert "priority" not in func


def test_skips_globals_and_classes(tmp_path):
    """Items with kind != "function" are skipped (only functions
    have call-graph reachability semantics)."""
    target = _project(tmp_path, {
        "src/vuln.py": (
            "x = 1\n"
            "def f(): pass\n"
        ),
    })
    checklist = _checklist({
        "src/vuln.py": [
            {"name": "x", "kind": "global"},
            {"name": "f", "kind": "function"},
        ],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    # f gets marked, x doesn't.
    assert marked == 1
    items = {it["name"]: it for it in checklist["files"][0]["items"]}
    assert "priority" not in items["x"]
    assert items["f"]["priority"] == "low"


def test_handles_empty_checklist(tmp_path):
    target = _project(tmp_path, {"src/x.py": "pass\n"})
    assert mark_unreachable_low_priority({}, target) == 0
    assert mark_unreachable_low_priority({"files": []}, target) == 0


def test_handles_malformed_inputs(tmp_path):
    """Non-dict / non-list shapes degrade gracefully."""
    assert mark_unreachable_low_priority(
        "not a dict",  # type: ignore[arg-type]
        tmp_path,
    ) == 0
    assert mark_unreachable_low_priority(
        {"files": "not a list"}, tmp_path,
    ) == 0
    # Files entry not a dict.
    assert mark_unreachable_low_priority(
        {"files": ["not a dict"]}, tmp_path,
    ) == 0


def test_function_without_name_skipped(tmp_path):
    target = _project(tmp_path, {"src/vuln.py": "def f(): pass\n"})
    checklist = _checklist({
        "src/vuln.py": [
            {"kind": "function"},                   # no name
            {"name": "", "kind": "function"},      # empty name
            {"name": "f", "kind": "function"},
        ],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    # Only ``f`` gets marked.
    assert marked == 1


def test_path_without_extension_skipped(tmp_path):
    """File entry with a path that has no extension can't be
    converted to a module — skipped."""
    target = _project(tmp_path, {"src/x.py": "pass\n"})
    checklist = {
        "files": [
            {"path": "Makefile", "items": [
                {"name": "build", "kind": "function"},
            ]},
        ],
    }
    marked = mark_unreachable_low_priority(checklist, target)
    assert marked == 0


def test_inventory_passed_through(tmp_path):
    """When the caller passes an inventory, no fresh build."""
    target = _project(tmp_path, {
        "src/vuln.py": "def dead(): pass\n",
    })
    checklist = _checklist({
        "src/vuln.py": [{"name": "dead", "kind": "function"}],
    })
    # Build inventory ourselves.
    from core.inventory.builder import build_inventory
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(target), td)
    marked = mark_unreachable_low_priority(
        checklist, target, inventory=inv,
    )
    assert marked == 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_path_to_module():
    assert _path_to_module("packages/foo/bar.py") == "packages.foo.bar"
    assert _path_to_module("Makefile") is None
    assert _path_to_module("") is None
