"""URL targets are opaque strings for projects, never filesystem paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.project.project import ProjectManager


@pytest.fixture()
def manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ProjectManager:
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
    return ProjectManager(projects_dir=tmp_path / "projects")


def test_create_project_stores_url_target_verbatim(manager: ProjectManager, tmp_path: Path):
    project = manager.create(
        "webapp",
        target="https://example.test:8443/app",
        output_dir=str(tmp_path / "out"),
    )

    # Path-resolving a URL would anchor it to the cwd — nonsense.
    assert project.target == "https://example.test:8443/app"


def test_find_project_for_target_matches_url_without_resolution(
    manager: ProjectManager, tmp_path: Path
):
    manager.create(
        "webapp",
        target="https://example.test",
        output_dir=str(tmp_path / "out"),
    )

    found = manager.find_project_for_target("https://example.test")

    assert found is not None
    assert found.name == "webapp"


def test_filesystem_targets_still_resolve(manager: ProjectManager, tmp_path: Path):
    target = tmp_path / "repo"
    target.mkdir()
    project = manager.create(
        "code", target=str(target), output_dir=str(tmp_path / "out2")
    )

    assert project.target == str(target.resolve())
    assert manager.find_project_for_target(str(target)) is not None


def test_adopt_target_for_keeps_url_targets_verbatim(
    manager: ProjectManager, tmp_path: Path
):
    """A /web run's recorded URL target must survive adopt/retro-create
    without being anchored to the cwd."""
    import json

    run_dir = tmp_path / "web_scan_123"
    run_dir.mkdir()
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"target_path": "https://example.test/"}), encoding="utf-8"
    )

    adopted = manager.adopt_target_for(str(run_dir))

    assert adopted == "https://example.test"


def test_same_target_compares_urls_normalized_and_never_mixes():
    from core.project.project import _same_target

    assert _same_target("https://example.test", "https://example.test/")
    assert not _same_target("https://example.test", "https://other.test")
    # URL vs filesystem is never the same target.
    assert not _same_target("https://example.test", "/srv/app")


def test_trailing_slash_create_and_find_agree(
    manager: ProjectManager, tmp_path: Path
):
    project = manager.create(
        "webslash",
        target="https://example.test/",
        output_dir=str(tmp_path / "out"),
    )

    assert project.target == "https://example.test"
    assert manager.find_project_for_target("https://example.test") is not None
    assert manager.find_project_for_target("https://example.test/") is not None
