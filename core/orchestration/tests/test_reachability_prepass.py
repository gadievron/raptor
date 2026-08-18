"""Tests for ``run_reachability_prepass`` — the always-on
companion to ``run_understand_prepass``."""

from __future__ import annotations

import json
from pathlib import Path

from core.orchestration.agentic_passes import (
    ReachabilityPrepassResult,
    run_reachability_prepass,
)


def _project(tmp_path: Path, files: dict) -> Path:
    """Drop ``files`` (path → contents) under tmp_path."""
    for rel, contents in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)
    return tmp_path


def _write_checklist(out_dir: Path, files_funcs: dict) -> Path:
    """Build a minimal checklist with the given file → functions
    mapping. Returns the checklist path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "files": [
            {"path": rel, "items": funcs}
            for rel, funcs in files_funcs.items()
        ],
    }
    p = out_dir / "checklist.json"
    p.write_text(json.dumps(data))
    return p


# ---------------------------------------------------------------------------
# Always-on prepass behaviour
# ---------------------------------------------------------------------------


def test_runs_unconditionally_marks_dead_function(tmp_path):
    """Prepass fires regardless of whether --understand is set,
    marking dead-code functions priority=low."""
    target = _project(tmp_path, {
        "src/vuln.py": (
            "def dead(): pass\n"
            "def alive(): pass\n"
        ),
        "src/main.py": (
            "from src.vuln import alive\nalive()\n"
        ),
    })
    out_dir = tmp_path / "agentic-out"
    _write_checklist(out_dir, {
        "src/vuln.py": [
            {"name": "dead", "kind": "function"},
            {"name": "alive", "kind": "function"},
        ],
    })

    result = run_reachability_prepass(target, out_dir)
    assert isinstance(result, ReachabilityPrepassResult)
    assert result.ran is True
    assert result.marked_count == 1
    assert result.inventory is not None
    assert "files" in result.inventory

    # Verify the checklist.json on disk got the priority marker.
    saved = json.loads((out_dir / "checklist.json").read_text())
    funcs = {f["name"]: f for f in saved["files"][0]["items"]}
    assert funcs["dead"]["priority"] == "low"
    assert "priority" not in funcs["alive"]


def test_skipped_when_checklist_missing(tmp_path):
    """No agentic checklist on disk → prepass returns ran=False."""
    target = _project(tmp_path, {"src/x.py": "pass\n"})
    out_dir = tmp_path / "agentic-out"
    out_dir.mkdir()
    # No checklist.json — simulates "agentic agent hasn't run yet".

    result = run_reachability_prepass(target, out_dir)
    assert result.ran is False
    assert result.skipped_reason == "agentic checklist not yet built"


def test_inventory_returned_for_downstream_use(tmp_path):
    """The inventory built by the prepass is returned so the
    agentic launcher can thread it to /validate / codeql / etc.
    without rebuilding."""
    target = _project(tmp_path, {
        "src/x.py": "def f(): pass\n",
    })
    out_dir = tmp_path / "agentic-out"
    _write_checklist(out_dir, {
        "src/x.py": [{"name": "f", "kind": "function"}],
    })

    result = run_reachability_prepass(target, out_dir)
    assert result.inventory is not None
    # The inventory has the standard build_inventory shape.
    assert "files" in result.inventory
    paths = {f["path"] for f in result.inventory["files"]}
    assert "src/x.py" in paths


def test_no_marks_when_all_functions_alive(tmp_path):
    """All functions are reachable from project source →
    marked_count = 0, prepass ran successfully."""
    target = _project(tmp_path, {
        "src/x.py": "def a():\n    pass\n",
        "src/y.py": "def b():\n    pass\n",
        "src/main.py": (
            "from src.x import a\n"
            "from src.y import b\n"
            "a()\n"
            "b()\n"
        ),
    })
    out_dir = tmp_path / "agentic-out"
    _write_checklist(out_dir, {
        "src/x.py": [{"name": "a", "kind": "function"}],
        "src/y.py": [{"name": "b", "kind": "function"}],
    })

    result = run_reachability_prepass(target, out_dir)
    assert result.ran is True
    assert result.marked_count == 0


def test_handles_malformed_checklist(tmp_path):
    """Checklist.json present but corrupt → ran=False with a
    diagnostic skipped_reason."""
    target = _project(tmp_path, {"src/x.py": "pass\n"})
    out_dir = tmp_path / "agentic-out"
    out_dir.mkdir()
    (out_dir / "checklist.json").write_text("not valid json")

    result = run_reachability_prepass(target, out_dir)
    # Either ran=False with a skipped reason OR ran=True with
    # marked_count=0 — both are acceptable graceful degradations.
    assert isinstance(result, ReachabilityPrepassResult)
    if result.ran:
        assert result.marked_count == 0
    else:
        assert result.skipped_reason


def test_duration_recorded(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): pass\n"})
    out_dir = tmp_path / "agentic-out"
    _write_checklist(out_dir, {
        "src/x.py": [{"name": "f", "kind": "function"}],
    })
    result = run_reachability_prepass(target, out_dir)
    assert result.duration_s >= 0.0


# ---------------------------------------------------------------------------
# Checklist writes go through the accessor (symlink-resolving, flocked)
# ---------------------------------------------------------------------------


def test_mark_unreachable_concurrent_writer_markers_survive(
    tmp_path, monkeypatch,
):
    """Two writers through the accessor: the priority marker written
    inside ``_mark_unreachable_low_priority``'s transform AND a
    competing ``update_checklist`` write must both survive.

    Pre-fix the function did a plain load+save; a write landing
    between its read and its write was silently clobbered.
    """
    import threading
    import time

    import core.orchestration.reachability_enrichment as re_mod
    from core.inventory import update_checklist
    from core.orchestration.agentic_passes import (
        _mark_unreachable_low_priority,
    )

    out_dir = tmp_path / "agentic-out"
    _write_checklist(out_dir, {
        "src/a.py": [{"name": "dead", "kind": "function"}],
    })

    inside_transform = threading.Event()

    def fake_mark(checklist, target, *, inventory=None,
                  allow_unreachable=False):
        checklist["files"][0]["items"][0]["priority"] = "low"
        inside_transform.set()
        # Give the competing writer a window while the flock is held.
        time.sleep(0.3)
        return 1

    monkeypatch.setattr(
        re_mod, "mark_unreachable_low_priority", fake_mark,
    )

    results = {}

    def run_mark():
        results["marked"] = _mark_unreachable_low_priority(
            out_dir, tmp_path,
        )

    t = threading.Thread(target=run_mark)
    t.start()
    assert inside_transform.wait(timeout=10)

    # Competing writer — blocks on the flock until the transform's
    # write completes, then sees the marker and adds its own.
    def add_marker(current):
        current["competing_marker"] = True
        return current

    update_checklist(out_dir, add_marker)
    t.join(timeout=30)

    data = json.loads((out_dir / "checklist.json").read_text())
    assert results["marked"] == 1
    assert data["competing_marker"] is True
    assert data["files"][0]["items"][0]["priority"] == "low"


def test_mark_unreachable_preserves_project_symlink(tmp_path, monkeypatch):
    """Project mode: checklist.json in the run dir is a symlink to the
    project-level checklist. The write must go through the symlink,
    not replace it with a regular file."""
    import core.orchestration.reachability_enrichment as re_mod
    from core.orchestration.agentic_passes import (
        _mark_unreachable_low_priority,
    )

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    project_checklist = project_dir / "checklist.json"
    project_checklist.write_text(json.dumps({
        "files": [{"path": "src/a.py",
                   "items": [{"name": "dead", "kind": "function"}]}],
    }))

    out_dir = tmp_path / "agentic-out"
    out_dir.mkdir()
    link = out_dir / "checklist.json"
    link.symlink_to(project_checklist)

    def fake_mark(checklist, target, *, inventory=None,
                  allow_unreachable=False):
        checklist["files"][0]["items"][0]["priority"] = "low"
        return 1

    monkeypatch.setattr(
        re_mod, "mark_unreachable_low_priority", fake_mark,
    )

    marked = _mark_unreachable_low_priority(out_dir, tmp_path)
    assert marked == 1
    assert link.is_symlink()
    data = json.loads(project_checklist.read_text())
    assert data["files"][0]["items"][0]["priority"] == "low"


def test_mark_unreachable_no_write_when_nothing_marked(
    tmp_path, monkeypatch,
):
    """A no-op transform must not rewrite the checklist."""
    import core.orchestration.reachability_enrichment as re_mod
    from core.orchestration.agentic_passes import (
        _mark_unreachable_low_priority,
    )

    out_dir = tmp_path / "agentic-out"
    path = _write_checklist(out_dir, {
        "src/a.py": [{"name": "alive", "kind": "function"}],
    })
    before = path.read_text()
    mtime_before = path.stat().st_mtime_ns

    monkeypatch.setattr(
        re_mod, "mark_unreachable_low_priority",
        lambda checklist, target, *, inventory=None,
        allow_unreachable=False: 0,
    )

    assert _mark_unreachable_low_priority(out_dir, tmp_path) == 0
    assert path.read_text() == before
    assert path.stat().st_mtime_ns == mtime_before
