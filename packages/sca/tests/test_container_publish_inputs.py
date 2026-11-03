"""Dependency upgrades and container notice changes must rebuild the image."""

import importlib.util
from pathlib import Path
import shlex

import yaml

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "container_publish_filters", ROOT / ".github/scripts/compute_filters.py",
)
FILTERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FILTERS)


def test_publication_tracks_all_local_docker_copy_inputs():
    workflow = yaml.load(
        (ROOT / ".github/workflows/dockerhub-publish.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    paths = workflow["on"]["push"]["paths"]
    sources = []
    for line in (ROOT / ".devcontainer/Dockerfile").read_text().splitlines():
        if not line.lstrip().upper().startswith("COPY "):
            continue
        words = shlex.split(line, comments=True)
        # External build stages are governed by the Dockerfile itself.
        if any(word.startswith("--from=") for word in words[1:]):
            continue
        sources.extend(word for word in words[1:-1] if not word.startswith("--"))
    assert sources, "the Dockerfile copy-input audit must inspect real inputs"
    uncovered = []
    for source in sources:
        # A directory COPY includes future files as well as today's seed files.
        changed = source + "new-notice-evidence.txt" if source.endswith("/") else source
        if not any(FILTERS.match_glob(changed, pattern) for pattern in paths):
            uncovered.append(changed)
    assert not uncovered, f"image inputs missing publication triggers: {uncovered}"


def test_new_notice_helpers_and_seed_directories_trigger_publication():
    workflow = yaml.load(
        (ROOT / ".github/workflows/dockerhub-publish.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    paths = workflow["on"]["push"]["paths"]
    for changed in (
        ".devcontainer/refresh-future-notices.py",
        ".devcontainer/future-notices/new-release/LICENSE",
    ):
        assert any(FILTERS.match_glob(changed, pattern) for pattern in paths), changed
