"""Regression tests for standard-image Docker Hub publication."""

from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "dockerhub-publish.yml"


def _workflow() -> dict[str, Any]:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(workflow, dict)
    return workflow


def _push_paths() -> set[str]:
    return set(_workflow()["on"]["push"]["paths"])


def _step_script(name: str) -> str:
    steps = _workflow()["jobs"]["build-push"]["steps"]
    step = next(step for step in steps if step.get("name") == name)
    return step["run"]


def test_standard_image_rebuild_paths_cover_all_inputs() -> None:
    required_paths = {
        ".devcontainer/**",
        "containers/**",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-grammars.txt",
        "packages/web/requirements.txt",
        ".dockerignore",
        ".containerignore",
        "bin/raptor-container",
        ".github/workflows/dockerhub-publish.yml",
    }

    paths = _push_paths()
    assert required_paths <= paths, (
        "Docker Hub workflow is missing rebuild paths: "
        f"{sorted(required_paths - paths)}"
    )


def test_publication_is_limited_to_main_and_release_tags() -> None:
    triggers = _workflow()["on"]
    assert set(triggers) == {"push"}
    assert triggers["push"]["branches"] == ["main"]
    assert triggers["push"]["tags"] == ["v*.*.*"]


def test_build_explicitly_targets_standard_image() -> None:
    script = _step_script("Build and push")
    assert "docker build" in script
    assert "--target raptor-devcontainer" in script
    assert "docker push" in script


def test_workflow_never_builds_or_publishes_all_tools() -> None:
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    assert "raptor-all-tools" not in workflow_text
    assert "ACCEPT_CODEQL_TERMS" not in workflow_text
