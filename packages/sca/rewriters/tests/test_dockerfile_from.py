"""Tests for ``packages.sca.rewriters.dockerfile_from``.

The FROM-image-tag rewriter and the combined ARG+FROM dispatch
through the registry."""

from __future__ import annotations

from pathlib import Path


from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.dockerfile_from import (
    rewrite_dockerfile_from,
)


# ---------------------------------------------------------------------------
# Canonical FROM rewrite
# ---------------------------------------------------------------------------

def test_from_rewrite_simple_image(tmp_path: Path) -> None:
    """``FROM python:3.11`` → ``FROM python:3.12`` when locator
    is the canonical ``docker.io/library/python`` and tag bump
    matches."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.11\nRUN echo hi\n")
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    results = rewrite_dockerfile_from(dockerfile, edits)
    assert results[0].applied
    text = dockerfile.read_text()
    assert "FROM python:3.12" in text
    assert "FROM python:3.11" not in text


def test_from_rewrite_with_registry(tmp_path: Path) -> None:
    """Non-docker.io image (ghcr.io / mcr.microsoft.com)."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM ghcr.io/anthropic/claude-code:2.0.0\n"
    )
    edits = [RewriteEdit(
        locator="ghcr.io/anthropic/claude-code",
        old_value="2.0.0", new_value="2.1.0",
    )]
    results = rewrite_dockerfile_from(dockerfile, edits)
    assert results[0].applied
    assert "ghcr.io/anthropic/claude-code:2.1.0" in dockerfile.read_text()


def test_from_rewrite_preserves_as_stage_suffix(tmp_path: Path) -> None:
    """Multi-stage builds: ``FROM image:tag AS stagename`` — the
    AS stage clause must survive the rewrite."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.11 AS builder\n")
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    rewrite_dockerfile_from(dockerfile, edits)
    assert "FROM python:3.12 AS builder" in dockerfile.read_text()


def test_from_rewrite_preserves_platform_flag(tmp_path: Path) -> None:
    """``FROM --platform=linux/amd64 image:tag`` (BuildKit) —
    the platform flag must survive."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM --platform=linux/amd64 python:3.11\n"
    )
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    rewrite_dockerfile_from(dockerfile, edits)
    text = dockerfile.read_text()
    assert "--platform=linux/amd64" in text
    assert "python:3.12" in text


def test_from_rewrite_value_mismatch_refuses(tmp_path: Path) -> None:
    """File has a different tag than the plan expected — refuse
    to overwrite. Same suspend-on-stale-plan semantics as the
    ARG rewriter."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.13\n")
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    results = rewrite_dockerfile_from(dockerfile, edits)
    assert not results[0].applied
    assert "value_mismatch" in results[0].reason
    assert "FROM python:3.13" in dockerfile.read_text()


def test_from_rewrite_already_at_target_no_change(tmp_path: Path) -> None:
    """Idempotent: file already at target → no_change, no write."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12\n")
    orig_mtime = dockerfile.stat().st_mtime
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    results = rewrite_dockerfile_from(dockerfile, edits)
    assert not results[0].applied
    assert results[0].reason == "no_change"
    assert dockerfile.stat().st_mtime == orig_mtime


def test_from_rewrite_not_found_when_image_absent(tmp_path: Path) -> None:
    """No FROM line for the locator → not_found."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine:3.18\n")
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    results = rewrite_dockerfile_from(dockerfile, edits)
    assert not results[0].applied
    assert results[0].reason == "not_found"


# ---------------------------------------------------------------------------
# Mixed ARG + FROM batch
# ---------------------------------------------------------------------------

def test_mixed_arg_and_from_edits_both_applied(tmp_path: Path) -> None:
    """A single call with both an ARG edit and a FROM edit — the
    combined dispatcher splits them and applies each to the right
    location."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.11\n"
        "ARG SEMGREP_VERSION=1.50.0\n"
        "RUN echo hi\n"
    )
    edits = [
        RewriteEdit("docker.io/library/python", "3.11", "3.12"),
        RewriteEdit("SEMGREP_VERSION", "1.50.0", "1.119.0"),
    ]
    results = rewrite_dockerfile_from(dockerfile, edits)
    assert all(r.applied for r in results)
    text = dockerfile.read_text()
    assert "FROM python:3.12" in text
    assert "ARG SEMGREP_VERSION=1.119.0" in text


# ---------------------------------------------------------------------------
# Registry dispatch
# ---------------------------------------------------------------------------

def test_registry_dispatch_routes_from_edits(tmp_path: Path) -> None:
    """``rewriters.rewrite(path, edits)`` with FROM-shaped
    locators (``/`` present) dispatches to the FROM rewriter."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.11\n")
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    results = rewrite(dockerfile, edits)
    assert len(results) == 1
    assert results[0].applied


def test_registry_dispatch_routes_arg_edits_through_combined(
    tmp_path: Path,
) -> None:
    """ARG-shaped edits (no ``/`` in locator) still route via
    the combined Dockerfile dispatcher, which forwards them to
    the ARG rewriter internally."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG SEMGREP_VERSION=1.50.0\n")
    edits = [RewriteEdit(
        locator="SEMGREP_VERSION",
        old_value="1.50.0", new_value="1.119.0",
    )]
    results = rewrite(dockerfile, edits)
    assert len(results) == 1
    assert results[0].applied
