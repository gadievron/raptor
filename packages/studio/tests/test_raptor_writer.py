"""Tests for raptor_writer.create_project."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.studio.services.raptor_reader import list_projects
from packages.studio.services.raptor_writer import ProjectCreateError, create_project


def test_create_project_writes_json(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    output_base = tmp_path / "out"
    proj = create_project(
        name="example",
        target=str(tmp_path / "target"),
        description="test project",
        projects_dir=projects_dir,
        output_base=output_base,
    )
    assert proj.name == "example"
    project_file = projects_dir / "example.json"
    assert project_file.exists()
    data = json.loads(project_file.read_text())
    assert data["version"] == 1
    assert data["name"] == "example"
    assert data["description"] == "test project"
    assert Path(data["output_dir"]).is_dir()
    assert data["target"].endswith("target")
    assert data["created"]  # ISO timestamp present
    assert data["notes"] == ""


def test_create_project_uses_explicit_output_dir(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    custom_output = tmp_path / "custom"
    create_project(
        name="custom",
        target=str(tmp_path / "target"),
        output_dir=str(custom_output),
        projects_dir=projects_dir,
        output_base=tmp_path / "out",
    )
    data = json.loads((projects_dir / "custom.json").read_text())
    assert Path(data["output_dir"]).resolve() == custom_output.resolve()
    assert custom_output.is_dir()


def test_create_project_defaults_output_to_output_base(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    output_base = tmp_path / "base"
    create_project(
        "defaulted",
        str(tmp_path / "target"),
        projects_dir=projects_dir,
        output_base=output_base,
    )
    data = json.loads((projects_dir / "defaulted.json").read_text())
    assert Path(data["output_dir"]).resolve() == (output_base / "defaulted").resolve()


def test_create_project_rejects_duplicate(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    output_base = tmp_path / "out"
    create_project(
        "dup", str(tmp_path / "a"),
        projects_dir=projects_dir, output_base=output_base,
    )
    with pytest.raises(ProjectCreateError, match="already exists"):
        create_project(
            "dup", str(tmp_path / "b"),
            projects_dir=projects_dir, output_base=output_base,
        )


@pytest.mark.parametrize(
    "bad_name",
    ["", " ", ".hidden", "_under", "bad/slash", "bad space", "bad?", "-leading"],
)
def test_create_project_rejects_invalid_names(tmp_path: Path, bad_name: str):
    with pytest.raises(ProjectCreateError):
        create_project(
            bad_name,
            str(tmp_path / "a"),
            projects_dir=tmp_path / "projects",
            output_base=tmp_path / "out",
        )


def test_create_project_accepts_valid_names(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    output_base = tmp_path / "out"
    for good in ("simple", "with-hyphen", "with.dot", "with_under", "a1", "1name"):
        create_project(
            good, str(tmp_path / "t"),
            projects_dir=projects_dir, output_base=output_base,
        )
        assert (projects_dir / f"{good}.json").exists()


def test_create_project_rejects_missing_target(tmp_path: Path):
    with pytest.raises(ProjectCreateError, match="Target is required"):
        create_project(
            "ok", "",
            projects_dir=tmp_path / "projects",
            output_base=tmp_path / "out",
        )


def test_create_forensics_project_accepts_github_url(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    proj = create_project(
        "forensics-test",
        "https://github.com/aws/aws-toolkit-vscode",
        project_type="forensics",
        focus="Investigate the July 13 incident",
        projects_dir=projects_dir,
        output_base=tmp_path / "out",
    )
    data = json.loads((projects_dir / "forensics-test.json").read_text())
    # Target stored as-is (no path resolution)
    assert data["target"] == "https://github.com/aws/aws-toolkit-vscode"


def test_create_forensics_rejects_non_url_target(tmp_path: Path):
    with pytest.raises(ProjectCreateError, match="URL"):
        create_project(
            "bad-forensics",
            "/tmp/not-a-url",
            project_type="forensics",
            projects_dir=tmp_path / "projects",
            output_base=tmp_path / "out",
        )


def test_create_project_rejects_unknown_type(tmp_path: Path):
    with pytest.raises(ProjectCreateError, match="Invalid project type"):
        create_project(
            "bad-type", "/tmp/x",
            project_type="nonsense",
            projects_dir=tmp_path / "projects",
            output_base=tmp_path / "out",
        )


def test_create_project_writes_notes_field(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    create_project(
        "with-notes", "/tmp/x",
        notes="This project tracks auth flows.\nWatch the middleware.",
        projects_dir=projects_dir,
        output_base=tmp_path / "out",
    )
    data = json.loads((projects_dir / "with-notes.json").read_text())
    assert "auth flows" in data["notes"]
    assert "middleware" in data["notes"]


def test_created_project_appears_in_list(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    create_project(
        "listable",
        str(tmp_path / "target"),
        projects_dir=projects_dir,
        output_base=tmp_path / "out",
    )
    projects = list_projects(projects_dir)
    assert [p.name for p in projects] == ["listable"]
    assert projects[0].target.endswith("target")


def test_schema_matches_raptor_validate_project(tmp_path: Path):
    """Written JSON must pass raptor's own schema validator.

    Imports raptor directly to confirm the two schemas stay aligned.
    If raptor is not available on sys.path, the test is skipped.
    """
    import sys

    from packages.studio.config import RAPTOR_HOME

    if not (RAPTOR_HOME / "core" / "project" / "schema.py").is_file():
        pytest.skip(f"raptor not available at {RAPTOR_HOME}")

    sys.path.insert(0, str(RAPTOR_HOME))
    try:
        from core.project.schema import validate_project  # type: ignore
    finally:
        sys.path.pop(0)

    projects_dir = tmp_path / "projects"
    create_project(
        "schemacheck",
        str(tmp_path / "target"),
        description="verifying against raptor's validator",
        projects_dir=projects_dir,
        output_base=tmp_path / "out",
    )
    data = json.loads((projects_dir / "schemacheck.json").read_text())
    valid, errors = validate_project(data)
    assert valid, f"raptor rejected our schema: {errors}"
