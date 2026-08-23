"""S23.1 (2026-05-03): test _is_external_image classifier.

The classifier is the gate for `--pull always` in docker_run / docker_build /
docker_compose_up. External (registry-pulled) images get the flag — locally
built images (source_build output) don't, since they have no upstream.

Cascade-test Phase 2 confirmed the cache-bypass leak this addresses:
agent successfully built CVEs via vulhub-image despite Docker Hub at 0/100,
because docker_run consulted the local layer cache before any registry probe.
With `--pull always` for external images, the cache is bypassed and a real
fetch is forced. See cascade-test/out/cascade-bug-report.md.
"""

from __future__ import annotations

import pytest

from cve_env.tools._image_origin import _is_external_image

# External: image came from a registry (Docker Hub, quay, ghcr, mcr).
# These MUST get --pull always so we never silently use a stale cached layer.


@pytest.mark.parametrize(
    "image",
    [
        "vulhub/openssl",
        "vulhub/openssl:1.0.1g",
        "docker.io/library/alpine",
        "library/alpine:3.19",
        "library/redis:6.2",
        "quay.io/centos/centos:stream9",
        "ghcr.io/foo/bar:tag",
        "mcr.microsoft.com/dotnet/runtime:8.0",
        # S23.3 refinement: bare names ARE Docker Hub canonical (library/X).
        # Earlier "no '/' = local" was wrong; FROM debian:11 in a Dockerfile
        # IS external and needs --pull. Cache-leak fix.
        "debian:11",
        "redis",
        "python:3.12-slim",
        "ubuntu:22.04",
    ],
)
def test_external_images_classified_external(image: str) -> None:
    assert _is_external_image(image) is True, f"{image!r} should be external"


# Local: built by source_build (cve-NNNN-...:tag), explicit localhost/ prefix,
# or 'scratch' (special builder reference). These must NOT get --pull (no upstream).


@pytest.mark.parametrize(
    "image",
    [
        "cve-2015-10010-openresolve:build",
        "cve-2019-11043:local",
        "cve-2014-0160-heartbleed:build",
        "localhost/foo:bar",
        "localhost/cve-2015-10010:build",
        "scratch",  # special builder reference; never pulls
    ],
)
def test_local_images_classified_local(image: str) -> None:
    assert _is_external_image(image) is False, f"{image!r} should be local"


def test_empty_string_is_local() -> None:
    """Defensive: empty/None-like input should not crash; treat as local
    (no pull). Caller should validate input separately."""
    assert _is_external_image("") is False
