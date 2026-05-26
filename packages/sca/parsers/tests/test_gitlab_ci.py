"""Tests for the GitLab CI parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.parsers.gitlab_ci import parse


pytest.importorskip("yaml")


def _write(tmp_path: Path, content: str, name: str = ".gitlab-ci.yml") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def test_top_level_image(tmp_path):
    p = _write(tmp_path, """\
image: python:3.11

test:
  script: pytest
""")
    [d] = parse(p)
    assert d.name == "python"
    assert d.version == "3.11"
    assert d.ecosystem == "OCI"
    assert d.source_kind == "gitlab_ci"
    assert "top-level image" in d.source_extra["context"]


def test_per_job_image_overrides(tmp_path):
    p = _write(tmp_path, """\
image: python:3.11

build:
  image: ghcr.io/myorg/builder:v2
  script: make
""")
    deps = parse(p)
    images = {d.name for d in deps}
    assert "python" in images
    assert "ghcr.io/myorg/builder" in images


def test_top_level_services(tmp_path):
    p = _write(tmp_path, """\
services:
  - postgres:16-alpine
  - redis:7

test:
  script: pytest
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "postgres" in by_name
    assert "redis" in by_name
    assert "services" in by_name["postgres"].source_extra["context"]


def test_dict_form_service(tmp_path):
    """``services: [{name: ..., alias: ...}]`` — newer GitLab
    syntax."""
    p = _write(tmp_path, """\
services:
  - name: postgres:16-alpine
    alias: db
  - name: redis:7
""")
    deps = parse(p)
    assert {d.name for d in deps} == {"postgres", "redis"}


def test_dict_form_image(tmp_path):
    """``image: { name: ..., entrypoint: [...] }`` — image with
    custom entrypoint."""
    p = _write(tmp_path, """\
image:
  name: custom/runner:v3
  entrypoint: ['']

test:
  script: ls
""")
    [d] = parse(p)
    assert d.name == "custom/runner"
    assert d.version == "v3"


def test_per_job_services(tmp_path):
    p = _write(tmp_path, """\
test:
  image: python:3.11
  services:
    - mysql:8
""")
    deps = parse(p)
    images = {d.name for d in deps}
    assert images == {"python", "mysql"}


def test_reserved_keys_not_treated_as_jobs(tmp_path):
    """Top-level ``variables:`` / ``stages:`` / ``cache:`` aren't
    jobs and don't have meaningful image fields."""
    p = _write(tmp_path, """\
variables:
  FOO: bar

stages:
  - test
  - build

cache:
  paths: [.cache]

test:
  image: python:3.11
  script: pytest
""")
    deps = parse(p)
    assert {d.name for d in deps} == {"python"}


def test_template_anchor_jobs_extracted(tmp_path):
    """``.template:`` (leading dot) is a hidden job; its image
    flows into actual jobs via ``extends:``. We extract it
    anyway so the SBOM has the dep."""
    p = _write(tmp_path, """\
.python-base:
  image: python:3.11

test:
  extends: .python-base
  script: pytest
""")
    deps = parse(p)
    assert any(d.name == "python" for d in deps)


def test_dedup_same_image_in_multiple_contexts(tmp_path):
    """Same image used in two distinct contexts → two rows
    (preserves provenance), but identical (image, ctx) pair
    deduped."""
    p = _write(tmp_path, """\
image: python:3.11

test1:
  image: python:3.11
  script: pytest

test2:
  image: python:3.11
  script: pytest
""")
    deps = parse(p)
    # Three different contexts → three rows.
    contexts = {d.source_extra["context"] for d in deps}
    assert "top-level image" in contexts
    assert any("test1" in c for c in contexts)
    assert any("test2" in c for c in contexts)


def test_no_image_blocks_returns_empty(tmp_path):
    """A pipeline that uses only ``trigger:`` / external runners
    has no image: refs. Don't crash, return empty."""
    p = _write(tmp_path, """\
stages: [build]

deploy:
  stage: build
  trigger:
    project: parent/proj
""")
    assert parse(p) == []


def test_malformed_yaml(tmp_path):
    p = _write(tmp_path, ":")
    assert parse(p) == []


def test_yaml_extension(tmp_path):
    """Both ``.yml`` and ``.yaml`` extensions are valid."""
    p = _write(
        tmp_path, "image: alpine:3.18\ntest:\n  script: ls\n",
        name=".gitlab-ci.yaml",
    )
    [d] = parse(p)
    assert d.name == "alpine"


# ---------------------------------------------------------------------------
# Discovery integration
# ---------------------------------------------------------------------------


def test_discovery_finds_gitlab_ci(tmp_path):
    from packages.sca.discovery import find_manifests
    _write(tmp_path, "image: python:3.11\ntest:\n  script: pytest\n")
    manifests = find_manifests(tmp_path)
    found = [m for m in manifests if m.path.name == ".gitlab-ci.yml"]
    assert len(found) == 1
    assert found[0].ecosystem == "GitLabCI"
