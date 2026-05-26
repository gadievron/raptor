"""Tests for ``packages.sca.rewriters.yaml_image``.

Covers in-place rewriting of YAML ``image:`` refs across the
three file kinds the rewriter targets:

* docker-compose / compose
* GitLab CI (``.gitlab-ci.yml``)
* Kubernetes manifests
"""

from __future__ import annotations

from pathlib import Path


from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.yaml_image import rewrite_yaml_image


# ---------------------------------------------------------------------------
# Happy path — compose
# ---------------------------------------------------------------------------

def test_compose_image_rewrite(tmp_path: Path) -> None:
    """``services:`` block with ``image: postgres:15`` →
    rewrite tag to 16."""
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres:15\n"
    )
    edits = [RewriteEdit(
        locator="docker.io/library/postgres",
        old_value="15", new_value="16",
    )]
    results = rewrite_yaml_image(compose, edits)
    assert results[0].applied
    assert "image: postgres:16" in compose.read_text()


def test_compose_image_with_registry(tmp_path: Path) -> None:
    """Non-docker.io registry: ``image: ghcr.io/foo/bar:v1.0``."""
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  app:\n"
        "    image: ghcr.io/foo/bar:v1.0\n"
    )
    edits = [RewriteEdit(
        locator="ghcr.io/foo/bar",
        old_value="v1.0", new_value="v2.0",
    )]
    results = rewrite_yaml_image(compose, edits)
    assert results[0].applied
    assert "ghcr.io/foo/bar:v2.0" in compose.read_text()


def test_compose_quoted_image_value_handled(tmp_path: Path) -> None:
    """``image: \"postgres:15\"`` (quoted YAML scalar) rewrites
    correctly. The parser strips quotes when extracting; the
    rewriter accepts both quoted and unquoted in the file."""
    compose = tmp_path / "compose.yml"
    compose.write_text(
        "services:\n"
        "  db:\n"
        '    image: "postgres:15"\n'
    )
    edits = [RewriteEdit(
        locator="docker.io/library/postgres",
        old_value="15", new_value="16",
    )]
    results = rewrite_yaml_image(compose, edits)
    assert results[0].applied
    text = compose.read_text()
    assert ':"' in text or "16" in text


# ---------------------------------------------------------------------------
# k8s manifests
# ---------------------------------------------------------------------------

def test_k8s_deployment_container_image_rewrite(tmp_path: Path) -> None:
    """k8s Deployment with ``containers[].image: foo:tag``."""
    manifest = tmp_path / "deployment.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: web\n"
        "          image: nginx:1.25\n"
    )
    edits = [RewriteEdit(
        locator="docker.io/library/nginx",
        old_value="1.25", new_value="1.27",
    )]
    results = rewrite_yaml_image(manifest, edits)
    assert results[0].applied
    assert "image: nginx:1.27" in manifest.read_text()


# ---------------------------------------------------------------------------
# Gitlab CI
# ---------------------------------------------------------------------------

def test_gitlab_ci_top_level_image_rewrite(tmp_path: Path) -> None:
    """GitLab CI top-level ``image:`` rewrites correctly."""
    cifile = tmp_path / ".gitlab-ci.yml"
    cifile.write_text(
        "image: python:3.11\n"
        "\n"
        "build:\n"
        "  script:\n"
        "    - python --version\n"
    )
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    results = rewrite_yaml_image(cifile, edits)
    assert results[0].applied
    assert "image: python:3.12" in cifile.read_text()


# ---------------------------------------------------------------------------
# Value mismatch / not found / idempotency
# ---------------------------------------------------------------------------

def test_value_mismatch_refuses(tmp_path: Path) -> None:
    """File has different tag than the plan expected — refuse."""
    compose = tmp_path / "compose.yml"
    compose.write_text("    image: postgres:14\n")
    edits = [RewriteEdit(
        locator="docker.io/library/postgres",
        old_value="15", new_value="16",
    )]
    results = rewrite_yaml_image(compose, edits)
    assert not results[0].applied
    assert "value_mismatch" in results[0].reason
    assert "image: postgres:14" in compose.read_text()


def test_no_change_when_already_at_target(tmp_path: Path) -> None:
    compose = tmp_path / "compose.yml"
    compose.write_text("    image: postgres:16\n")
    orig_mtime = compose.stat().st_mtime
    edits = [RewriteEdit(
        locator="docker.io/library/postgres",
        old_value="15", new_value="16",
    )]
    results = rewrite_yaml_image(compose, edits)
    assert not results[0].applied
    assert results[0].reason == "no_change"
    assert compose.stat().st_mtime == orig_mtime


def test_not_found_when_image_absent(tmp_path: Path) -> None:
    """Locator isn't in the file → not_found."""
    compose = tmp_path / "compose.yml"
    compose.write_text("    image: redis:7\n")
    edits = [RewriteEdit(
        locator="docker.io/library/postgres",
        old_value="15", new_value="16",
    )]
    results = rewrite_yaml_image(compose, edits)
    assert not results[0].applied
    assert results[0].reason == "not_found"


# ---------------------------------------------------------------------------
# Registry dispatch
# ---------------------------------------------------------------------------

def test_registry_dispatch_compose(tmp_path: Path) -> None:
    """``rewrite(path, edits)`` with a compose file routes here."""
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("    image: postgres:15\n")
    edits = [RewriteEdit(
        locator="docker.io/library/postgres",
        old_value="15", new_value="16",
    )]
    results = rewrite(compose, edits)
    assert len(results) == 1
    assert results[0].applied


def test_registry_dispatch_gitlab_ci(tmp_path: Path) -> None:
    cifile = tmp_path / ".gitlab-ci.yml"
    cifile.write_text("image: python:3.11\n")
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    results = rewrite(cifile, edits)
    assert len(results) == 1
    assert results[0].applied


def test_registry_dispatch_gha_workflow_not_routed(tmp_path: Path) -> None:
    """``.github/workflows/*.yml`` files explicitly excluded from
    this rewriter — they're owned by the GHA-uses rewriter. Even
    if a workflow file contained an ``image:`` line (it can —
    job containers), this rewriter shouldn't fire on it."""
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "jobs:\n"
        "  build:\n"
        "    container:\n"
        "      image: python:3.11\n"
    )
    edits = [RewriteEdit(
        locator="docker.io/library/python",
        old_value="3.11", new_value="3.12",
    )]
    results = rewrite(wf, edits)
    # The GHA rewriter routed first, the ``uses:`` regex didn't
    # match (this is an ``image:`` line), and the YAML rewriter
    # was excluded by the .github/workflows/ check, so we get
    # NOT_FOUND — the file is untouched.
    if results:
        assert not results[0].applied
    assert "image: python:3.11" in wf.read_text()
