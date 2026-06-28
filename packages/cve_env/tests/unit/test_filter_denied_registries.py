"""Phase 42.5 corrigendum (2026-05-16): regression-lock test for
`_filter_denied_registries`.

Phase 42.5's coverage assessment originally classified this function as
✓ has-test based on a grep that found its name in `test_cascade_order_phase29.py`.
Re-audit on 2026-05-16 revealed the reference was a docstring mention only
(line 48 of that test file): `"Per `_filter_denied_registries`: bare `{p}:{v}`..."`
NOT an actual exercise of the function.

This is a real coverage gap surfaced by /work-audit C-class +
A-class findings. Fixed here per user "use TDD" directive.

The function is at `src/cve_env/tools/image_resolve.py:191-227`. It's the
Phase 29 cascade-deny-registry filter — used to test what the engine
does when a registry is unavailable (e.g., Docker Hub rate-limited).
"""

from __future__ import annotations

import pytest

from cve_env.tools.image_resolve import _filter_denied_registries


def test_no_op_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase 29: when CVE_ENV_DENY_REGISTRY is unset, no filtering."""
    monkeypatch.delenv("CVE_ENV_DENY_REGISTRY", raising=False)
    candidates = ["mirror.gcr.io/library/redis:7", "redis:7", "vulhub/redis:7"]
    result = _filter_denied_registries(candidates)
    assert result == candidates


def test_no_op_when_env_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty string treated as unset."""
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "")
    candidates = ["mirror.gcr.io/library/redis:7", "redis:7"]
    result = _filter_denied_registries(candidates)
    assert result == candidates


def test_no_op_when_env_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whitespace-only treated as unset."""
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "  ,  ")
    candidates = ["mirror.gcr.io/library/redis:7", "redis:7"]
    result = _filter_denied_registries(candidates)
    assert result == candidates


def test_drops_named_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """When CVE_ENV_DENY_REGISTRY=quay.io, drops quay.io refs only."""
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "quay.io")
    candidates = [
        "mirror.gcr.io/library/redis:7",
        "quay.io/redis/redis:7",
        "redis:7",
    ]
    result = _filter_denied_registries(candidates)
    assert "quay.io/redis/redis:7" not in result
    assert "mirror.gcr.io/library/redis:7" in result
    assert "redis:7" in result


def test_docker_io_drops_bare_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """CVE_ENV_DENY_REGISTRY=docker.io drops bare-name refs (`redis:7`)
    which default to Docker Hub. Special-handling per docstring.
    """
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "docker.io")
    candidates = ["redis:7", "mirror.gcr.io/library/redis:7"]
    result = _filter_denied_registries(candidates)
    assert "redis:7" not in result, (
        "bare-name redis:7 should be dropped (defaults to docker.io)"
    )
    assert "mirror.gcr.io/library/redis:7" in result


def test_docker_io_drops_library(monkeypatch: pytest.MonkeyPatch) -> None:
    """CVE_ENV_DENY_REGISTRY=docker.io drops library/* refs."""
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "docker.io")
    candidates = ["library/redis:7", "mirror.gcr.io/library/redis:7"]
    result = _filter_denied_registries(candidates)
    assert "library/redis:7" not in result
    assert "mirror.gcr.io/library/redis:7" in result


def test_docker_io_drops_vulhub(monkeypatch: pytest.MonkeyPatch) -> None:
    """vulhub/* refs default to Docker Hub; dropped when docker.io denied."""
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "docker.io")
    candidates = ["vulhub/redis:7", "quay.io/x/redis:7"]
    result = _filter_denied_registries(candidates)
    assert "vulhub/redis:7" not in result
    assert "quay.io/x/redis:7" in result


def test_docker_io_keeps_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    """localhost refs are NOT Docker Hub; kept even when docker.io denied."""
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "docker.io")
    candidates = ["localhost:5000/redis:7", "redis:7"]
    result = _filter_denied_registries(candidates)
    assert "localhost:5000/redis:7" in result
    assert "redis:7" not in result


def test_dockerhub_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    """'dockerhub' is treated as alias for 'docker.io'."""
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "dockerhub")
    candidates = ["redis:7", "library/redis:7", "mirror.gcr.io/redis:7"]
    result = _filter_denied_registries(candidates)
    assert "redis:7" not in result
    assert "library/redis:7" not in result
    assert "mirror.gcr.io/redis:7" in result


def test_multiple_registries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Comma-separated list filters all matching registries."""
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "quay.io,ghcr.io")
    candidates = [
        "mirror.gcr.io/library/redis:7",
        "quay.io/redis/redis:7",
        "ghcr.io/foo/redis:7",
        "mcr.microsoft.com/redis:7",
    ]
    result = _filter_denied_registries(candidates)
    assert "quay.io/redis/redis:7" not in result
    assert "ghcr.io/foo/redis:7" not in result
    assert "mirror.gcr.io/library/redis:7" in result
    assert "mcr.microsoft.com/redis:7" in result


def test_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Registry matching is case-insensitive."""
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "QUAY.IO")
    candidates = ["quay.io/redis/redis:7", "mirror.gcr.io/redis:7"]
    result = _filter_denied_registries(candidates)
    assert "quay.io/redis/redis:7" not in result
    assert "mirror.gcr.io/redis:7" in result


def test_phase_29_full_cascade_with_docker_io_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 29 attempt 5 workaround: CVE_ENV_DENY_REGISTRY=docker.io
    forces mirrors + vendor registries only. Full 10-item Phase 29
    cascade reduces to the 5 non-Docker-Hub entries.
    """
    monkeypatch.setenv("CVE_ENV_DENY_REGISTRY", "docker.io")
    cascade = [
        "mirror.gcr.io/library/redis:7",
        "public.ecr.aws/docker/library/redis:7",
        "quay.io/redis/redis:7",
        "ghcr.io/redis/redis:7",
        "mcr.microsoft.com/redis:7",
        "redis:7",  # DH bare-name
        "library/redis:7",  # DH library
        "vulhub/redis:7",  # DH vulhub
        "docker.io/redis:7",  # DH explicit
        "docker.io/library/redis:7",  # DH explicit library
    ]
    result = _filter_denied_registries(cascade)
    # 5 mirrors/vendors kept; 5 DH variants dropped
    assert len(result) == 5
    assert "mirror.gcr.io/library/redis:7" in result
    assert "public.ecr.aws/docker/library/redis:7" in result
    assert "quay.io/redis/redis:7" in result
    assert "ghcr.io/redis/redis:7" in result
    assert "mcr.microsoft.com/redis:7" in result
    for dropped in (
        "redis:7",
        "library/redis:7",
        "vulhub/redis:7",
        "docker.io/redis:7",
        "docker.io/library/redis:7",
    ):
        assert dropped not in result
