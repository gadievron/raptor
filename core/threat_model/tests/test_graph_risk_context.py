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

    probes: list[tuple[Path, str | None]] = []

    def spy(run_dir: Path, target_path: str | None = None) -> Path:
        probes.append((run_dir, target_path))
        return tmp_path / "graph" / "raptor.graph.sqlite"

    monkeypatch.setattr(ug, "graph_path_for_run", spy)

    target = tmp_path / "some-target"
    target.mkdir()
    assert graph_risk_context_for_target(target) == ""
    # No probe at all — in particular never a Path(".")-relative one.
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
