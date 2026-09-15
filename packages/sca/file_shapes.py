"""Shared file-shape predicates for SCA walkers, parsers, and rewriters.

One name grammar per file shape. These predicates decide which files
each lane sees — parsers and their paired rewriters MUST agree, and
per-module copies had already drifted (the platform-matrix Dockerfile
copy accepted a hidden ``.dockerfile`` name the others missed; one
GHA predicate covered composite actions, its rewriter twin did not).
``test_file_shapes`` pins the grammar and keeps new local copies out
of the package.
"""

from __future__ import annotations

from pathlib import Path

#: Exact Dockerfile basenames (case-sensitive, matching the OCI
#: ecosystem convention).
DOCKERFILE_NAMES = frozenset({"Dockerfile", "Containerfile"})


def is_dockerfile(path: Path) -> bool:
    """Match ``Dockerfile`` / ``Containerfile`` /
    ``Dockerfile.<variant>`` / ``<variant>.Dockerfile`` /
    ``*.dockerfile`` (including a bare hidden ``.dockerfile`` —
    the widest of the copies this replaces; ``path.suffix`` misses
    that spelling).
    """
    name = path.name
    if name in DOCKERFILE_NAMES:
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    return name.endswith(".dockerfile")


def is_compose_file(path: Path) -> bool:
    """Match ``compose.yml`` / ``compose.yaml`` /
    ``docker-compose*.yml`` / ``compose.<overlay>.yml`` (and the
    ``.yaml`` spellings), case-insensitively.

    Conservative: the name must START with ``compose`` or
    ``docker-compose`` — plenty of unrelated tools ship files merely
    containing "compose".
    """
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    name = path.name.lower()
    if name.startswith("docker-compose"):
        return True
    if name in ("compose.yml", "compose.yaml"):
        return True
    return name.startswith("compose.")


def is_gha_workflow(path: Path) -> bool:
    """Match GitHub Actions WORKFLOW files only:
    ``.github/workflows/*.yml`` / ``*.yaml``.

    Composite action manifests (``action.yml``) are a different
    shape — use :func:`is_gha_workflow_or_action` for lanes that
    process ``uses:``/``run:`` steps in both.
    """
    if path.suffix not in (".yml", ".yaml"):
        return False
    parts = path.parts
    for i in range(len(parts) - 2):
        if parts[i] == ".github" and parts[i + 1] == "workflows":
            return True
    return False


def is_gha_workflow_or_action(path: Path) -> bool:
    """Match GHA workflow files PLUS composite-action manifests
    (``action.yml`` / ``action.yaml`` anywhere) — both carry
    ``uses:`` and ``run:`` steps."""
    if is_gha_workflow(path):
        return True
    return path.name in ("action.yml", "action.yaml")


def is_gitlab_ci_file(path: Path) -> bool:
    """Match ``.gitlab-ci.yml`` / ``.gitlab-ci.yaml``."""
    return path.name in (".gitlab-ci.yml", ".gitlab-ci.yaml")
