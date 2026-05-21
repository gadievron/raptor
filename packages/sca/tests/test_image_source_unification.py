"""Tests for the OCI image-source unification — shared SBOM
fetcher across Dockerfile FROM, docker-compose, and GitLab CI.

The original B9 commit's tests cover the Dockerfile-only path.
These tests pin the unified ``find_all_image_refs`` /
``scan_image_sources`` / ``image_source_registry_hosts`` triple
across the three image-source file shapes.
"""

from __future__ import annotations

import gzip
import io
import tarfile
from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional
from unittest.mock import MagicMock

import pytest

from packages.sca.dockerfile_from import (
    find_all_image_refs,
    find_compose_image_refs,
    find_gitlab_ci_image_refs,
    image_source_registry_hosts,
    scan_image_sources,
)


pytest.importorskip("yaml")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _FakeManifestResp:
    parsed: Dict[str, Any]
    content_type: str
    digest: Optional[str]


def _make_layer_blob(file_payloads: Dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for path, content in file_payloads.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return gzip.compress(raw.getvalue())


def _chunk(data: bytes, size: int = 1024) -> Iterator[bytes]:
    for i in range(0, len(data), size):
        yield data[i:i + size]


def _make_client(
    manifests: Dict[str, _FakeManifestResp],
    blobs: Dict[str, bytes],
) -> MagicMock:
    client = MagicMock()

    def _fetch(ref, *, reference=None):
        key = reference or ref.tag or ref.digest or "latest"
        if key not in manifests:
            raise RuntimeError(f"no fake manifest for {key}")
        return manifests[key]

    def _stream(ref, digest, **_):
        if digest not in blobs:
            raise RuntimeError(f"no fake blob for {digest}")
        return _chunk(blobs[digest])

    client.fetch_manifest.side_effect = _fetch
    client.stream_blob.side_effect = _stream
    return client


def _debian_manifest(layer_digest: str, layer_blob: bytes) -> _FakeManifestResp:
    return _FakeManifestResp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer_blob),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:" + "m" * 64,
    )


# ---------------------------------------------------------------------------
# find_compose_image_refs
# ---------------------------------------------------------------------------


def test_find_compose_image_refs_extracts(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres:16-alpine\n"
        "  cache:\n"
        "    image: redis:7\n"
    )
    refs = find_compose_image_refs(tmp_path)
    assert len(refs) == 2
    images = {r.image for r in refs}
    assert images == {"postgres:16-alpine", "redis:7"}
    assert all(r.source_kind == "compose" for r in refs)


def test_find_compose_skips_build_only_services(tmp_path):
    (tmp_path / "compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    build: ./app\n"
        "  db:\n"
        "    image: postgres:16\n"
    )
    refs = find_compose_image_refs(tmp_path)
    images = [r.image for r in refs]
    assert images == ["postgres:16"]


def test_find_compose_overlay_variants(tmp_path):
    """``docker-compose.dev.yml``, ``compose.prod.yaml``, etc."""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  a:\n    image: foo:1\n"
    )
    (tmp_path / "docker-compose.dev.yml").write_text(
        "services:\n  b:\n    image: bar:1\n"
    )
    (tmp_path / "compose.prod.yaml").write_text(
        "services:\n  c:\n    image: baz:1\n"
    )
    refs = find_compose_image_refs(tmp_path)
    assert {r.image for r in refs} == {"foo:1", "bar:1", "baz:1"}


# ---------------------------------------------------------------------------
# find_gitlab_ci_image_refs
# ---------------------------------------------------------------------------


def test_find_gitlab_ci_top_level_and_jobs(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text(
        "image: python:3.11\n"
        "services:\n"
        "  - postgres:16\n"
        "test:\n"
        "  image: ghcr.io/myorg/runner:v2\n"
        "  script: pytest\n"
    )
    refs = find_gitlab_ci_image_refs(tmp_path)
    images = {r.image for r in refs}
    assert images == {"python:3.11", "postgres:16", "ghcr.io/myorg/runner:v2"}
    assert all(r.source_kind == "gitlab_ci" for r in refs)


def test_find_gitlab_ci_dict_form_image_and_service(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text(
        "image:\n  name: custom/runner:v3\n  entrypoint: ['']\n"
        "test:\n"
        "  services:\n"
        "    - name: redis:7\n"
        "      alias: cache\n"
    )
    refs = find_gitlab_ci_image_refs(tmp_path)
    assert {r.image for r in refs} == {"custom/runner:v3", "redis:7"}


def test_find_gitlab_ci_reserved_keys_skipped(tmp_path):
    (tmp_path / ".gitlab-ci.yaml").write_text(
        "variables:\n  FOO: bar\n"
        "stages:\n  - test\n"
        "test:\n"
        "  image: alpine:3.18\n"
    )
    refs = find_gitlab_ci_image_refs(tmp_path)
    assert {r.image for r in refs} == {"alpine:3.18"}


# ---------------------------------------------------------------------------
# find_all_image_refs — unified discovery across all sources
# ---------------------------------------------------------------------------


def test_find_all_unifies_three_sources(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM debian:11\n")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: postgres:16\n"
    )
    (tmp_path / ".gitlab-ci.yml").write_text(
        "image: python:3.11\ntest:\n  script: pytest\n"
    )
    refs = find_all_image_refs(tmp_path)
    by_kind = {(r.source_kind, r.image) for r in refs}
    assert ("dockerfile_from", "debian:11") in by_kind
    assert ("compose", "postgres:16") in by_kind
    assert ("gitlab_ci", "python:3.11") in by_kind


def test_find_all_empty_target_returns_empty(tmp_path):
    assert find_all_image_refs(tmp_path) == []


# ---------------------------------------------------------------------------
# scan_image_sources — shared SBOM fetcher
# ---------------------------------------------------------------------------


def test_scan_dedupes_same_image_across_sources(tmp_path):
    """A Dockerfile FROM postgres:16 + compose service postgres:16
    should fetch the SBOM only ONCE."""
    (tmp_path / "Dockerfile").write_text("FROM postgres:16\n")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: postgres:16\n"
    )
    layer_blob = _make_layer_blob({
        "var/lib/dpkg/status": (
            "Package: openssl\n"
            "Status: install ok installed\n"
            "Version: 3.0.11\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "a" * 64
    manifest = _debian_manifest(layer_digest, layer_blob)
    client = _make_client(
        manifests={"16": manifest},
        blobs={layer_digest: layer_blob},
    )

    deps = scan_image_sources(tmp_path, client=client)
    # Two refs to postgres:16 → two Dependency rows (one per
    # declared_in path), but the layer blob fetched ONCE.
    assert len(deps) == 2
    declared = sorted({d.declared_in.name for d in deps})
    assert declared == ["Dockerfile", "docker-compose.yml"]
    # Single fetch_manifest call per image (deduped via seen_images).
    assert client.fetch_manifest.call_count == 1
    assert client.stream_blob.call_count == 1


def test_scan_compose_only(tmp_path):
    """No Dockerfile, just compose. Fetcher should still emit
    OS-package rows from the compose-declared images."""
    (tmp_path / "compose.yml").write_text(
        "services:\n  db:\n    image: debian:11\n"
    )
    layer_blob = _make_layer_blob({
        "var/lib/dpkg/status": (
            "Package: zlib1g\n"
            "Status: install ok installed\n"
            "Version: 1.2.13\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "z" * 64
    manifest = _debian_manifest(layer_digest, layer_blob)
    client = _make_client(
        manifests={"11": manifest},
        blobs={layer_digest: layer_blob},
    )

    deps = scan_image_sources(tmp_path, client=client)
    assert len(deps) == 1
    assert deps[0].name == "zlib1g"
    assert deps[0].declared_in.name == "compose.yml"


def test_scan_gitlab_ci_only(tmp_path):
    """No Dockerfile, no compose, just GitLab CI. Image-from-image:
    field is fetched."""
    (tmp_path / ".gitlab-ci.yml").write_text(
        "test:\n  image: debian:11\n  script: ls\n"
    )
    layer_blob = _make_layer_blob({
        "var/lib/dpkg/status": (
            "Package: x\nStatus: install ok installed\n"
            "Version: 1.0\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "g" * 64
    manifest = _debian_manifest(layer_digest, layer_blob)
    client = _make_client(
        manifests={"11": manifest},
        blobs={layer_digest: layer_blob},
    )

    deps = scan_image_sources(tmp_path, client=client)
    assert any(d.name == "x" for d in deps)
    assert all(d.declared_in.name == ".gitlab-ci.yml" for d in deps)


def test_scan_failed_image_doesnt_break_others(tmp_path):
    """One image's manifest fetch fails (registry unreachable);
    other images still produce deps."""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  bad:\n    image: doesnotexist:1\n"
        "  good:\n    image: debian:11\n"
    )
    layer_blob = _make_layer_blob({
        "var/lib/dpkg/status": (
            "Package: ok\nStatus: install ok installed\n"
            "Version: 1.0\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "g" * 64
    good = _debian_manifest(layer_digest, layer_blob)
    client = MagicMock()

    def _fetch(ref, *, reference=None):
        if ref.repository.endswith("doesnotexist"):
            raise RuntimeError("404")
        return good

    def _stream(ref, digest, **_):
        return _chunk(layer_blob)

    client.fetch_manifest.side_effect = _fetch
    client.stream_blob.side_effect = _stream

    deps = scan_image_sources(tmp_path, client=client)
    assert any(d.name == "ok" for d in deps)


def test_scan_no_image_sources_returns_empty(tmp_path):
    client = MagicMock()
    deps = scan_image_sources(tmp_path, client=client)
    assert deps == []
    client.fetch_manifest.assert_not_called()


# ---------------------------------------------------------------------------
# image_source_registry_hosts — unified host discovery
# ---------------------------------------------------------------------------


def test_image_source_hosts_unifies_three_sources(tmp_path):
    """All three source files contribute to the registry host
    set. Compose's ghcr.io image should appear alongside the
    Dockerfile's docker.io and GitLab CI's docker.io."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
    (tmp_path / "compose.yml").write_text(
        "services:\n  app:\n    image: ghcr.io/x/y:v1\n"
    )
    (tmp_path / ".gitlab-ci.yml").write_text(
        "image: alpine:3.18\ntest:\n  script: ls\n"
    )
    hosts = set(image_source_registry_hosts(tmp_path))
    # docker.io split (registry-1 + auth) for Dockerfile/python +
    # gitlab/alpine
    assert "registry-1.docker.io" in hosts
    assert "auth.docker.io" in hosts
    # ghcr from compose
    assert "ghcr.io" in hosts


def test_image_source_hosts_empty_for_empty_target(tmp_path):
    assert image_source_registry_hosts(tmp_path) == []
