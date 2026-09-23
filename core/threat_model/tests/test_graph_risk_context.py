"""graph_risk_context_for_target never probes a CWD-relative graph.

The process CWD is the framework dir, never the analysis target, so a
CWD-relative graph_path_for_run probe can only ever read the wrong
graph. Non-project targets must yield no graph context at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.threat_model import graph_risk_context_for_target


@pytest.fixture()
def no_project(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "core.project.project.ProjectManager.find_project_for_target",
        lambda self, target, content_id=None: None,
    )
    monkeypatch.setattr(
        "core.project.project.ProjectManager.get_active",
        lambda self: None,
    )


def test_non_project_target_yields_empty_context(
        tmp_path: Path, no_project: None,
        monkeypatch: pytest.MonkeyPatch) -> None:
    import core.understand_graph as ug

    # Plant a graph at the CWD-relative location and chdir onto it, so
    # ANY CWD-relative spelling of the probe — routed through
    # graph_path_for_run or a direct Path("graph/...") — finds a file
    # that exists and would serve content. The spy-only oracle killed
    # just the import-routed spelling; a direct-Path regression stayed
    # green while serving the CWD graph.
    cwd = tmp_path / "framework-cwd"
    planted = cwd / "graph" / "raptor.graph.sqlite"
    planted.parent.mkdir(parents=True)
    planted.write_bytes(b"planted")
    monkeypatch.chdir(cwd)

    probes: list[tuple[Path, str | None]] = []

    def spy(run_dir: Path, target_path: str | None = None) -> Path:
        probes.append((run_dir, target_path))
        return tmp_path / "graph" / "raptor.graph.sqlite"

    monkeypatch.setattr(ug, "graph_path_for_run", spy)

    # Record — don't raise: the production code wraps the lookup in a
    # broad except that would swallow an AssertionError and return ""
    # anyway. Returning sentinel text makes any graph read visible in
    # the return value; the call log catches an exception-eaten path.
    graph_reads: list[Path] = []

    def read_spy(gp: Path, target: str, limit: int = 8) -> str:
        graph_reads.append(Path(gp))
        return f"CWD GRAPH CONTENT from {gp}"

    monkeypatch.setattr(ug, "threat_model_graph_context", read_spy)

    target = tmp_path / "some-target"
    target.mkdir()
    assert graph_risk_context_for_target(target) == ""
    # No graph was read, and no run-dir probe happened — in particular
    # never a Path(".")-relative one.
    assert graph_reads == []
    assert probes == []


def test_project_target_still_serves_graph_context(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import core.understand_graph as ug

    project_dir = tmp_path / "project"
    graph_path = project_dir / "graph" / "raptor.graph.sqlite"
    graph_path.parent.mkdir(parents=True)
    graph_path.touch()

    class _Project:
        output_dir = str(project_dir)

    monkeypatch.setattr(
        "core.project.project.ProjectManager.find_project_for_target",
        lambda self, target, content_id=None: _Project(),
    )
    monkeypatch.setattr(
        ug, "threat_model_graph_context",
        lambda gp, target, limit=8: f"GRAPH RISKS from {gp}",
    )

    target = tmp_path / "some-target"
    target.mkdir()
    out = graph_risk_context_for_target(target)
    assert out == f"GRAPH RISKS from {graph_path}"


def test_process_pin_governs_graph_context(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """OWNER RULE parity with load_for_target: with a run pinned to
    project A, the graph context must come from A — never from a twin
    project that happens to share the target."""
    import core.understand_graph as ug

    pinned_dir = tmp_path / "proj-a-out"
    pinned_graph = pinned_dir / "graph" / "raptor.graph.sqlite"
    pinned_graph.parent.mkdir(parents=True)
    pinned_graph.touch()

    twin_dir = tmp_path / "proj-b-out"
    twin_graph = twin_dir / "graph" / "raptor.graph.sqlite"
    twin_graph.parent.mkdir(parents=True)
    twin_graph.touch()

    target = tmp_path / "shared-target"
    target.mkdir()

    class _Pinned:
        output_dir = str(pinned_dir)
        target_path = str(target)

        def __init__(self) -> None:
            self.target = str(target)

    class _Twin:
        output_dir = str(twin_dir)

        def __init__(self) -> None:
            self.target = str(target)

    monkeypatch.setattr(
        "core.run.pin.get_process_project", lambda: "proj-a")
    monkeypatch.setattr(
        "core.project.trust._context_project_name",
        lambda run_dir=None: "proj-a")
    monkeypatch.setattr(
        "core.project.project.ProjectManager.load",
        lambda self, name: _Pinned() if name == "proj-a" else None)
    # The twin is what the raw first-match scan would return.
    monkeypatch.setattr(
        "core.project.project.ProjectManager.find_project_for_target",
        lambda self, target, content_id=None: _Twin())
    monkeypatch.setattr(
        "core.project.project.ProjectManager.get_active",
        lambda self: None)
    monkeypatch.setattr(
        ug, "threat_model_graph_context",
        lambda gp, target, limit=8: f"GRAPH RISKS from {gp}",
    )

    out = graph_risk_context_for_target(target)
    assert out == f"GRAPH RISKS from {pinned_graph}"


def test_process_pin_target_mismatch_yields_no_graph_context(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A governed context whose pinned project targets something else
    must yield nothing — never fall back to the twin scan."""
    import core.understand_graph as ug

    other_dir = tmp_path / "other-out"
    other_graph = other_dir / "graph" / "raptor.graph.sqlite"
    other_graph.parent.mkdir(parents=True)
    other_graph.touch()

    target = tmp_path / "the-target"
    target.mkdir()

    class _Elsewhere:
        output_dir = str(other_dir)

        def __init__(self) -> None:
            self.target = str(tmp_path / "different-target")

    monkeypatch.setattr(
        "core.run.pin.get_process_project", lambda: "proj-x")
    monkeypatch.setattr(
        "core.project.trust._context_project_name",
        lambda run_dir=None: "proj-x")
    monkeypatch.setattr(
        "core.project.project.ProjectManager.load",
        lambda self, name: _Elsewhere())
    monkeypatch.setattr(
        "core.project.project.ProjectManager.find_project_for_target",
        lambda self, target, content_id=None: _Elsewhere())
    monkeypatch.setattr(
        "core.project.project.ProjectManager.get_active",
        lambda self: None)
    monkeypatch.setattr(
        ug, "threat_model_graph_context",
        lambda gp, target, limit=8: f"GRAPH RISKS from {gp}",
    )

    assert graph_risk_context_for_target(target) == ""
