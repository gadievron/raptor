"""Tests for B9 sandbox host plumbing.

Confirms that ``dockerfile_registry_hosts(target)`` extracts the
right registry hostnames from every Dockerfile in a target tree,
and that the agent's ``_compose_proxy_hosts`` unions those into
the sandbox allowlist alongside the static set.
"""

from __future__ import annotations


from packages.sca import SCA_ALLOWED_HOSTS
from packages.sca.agent import _compose_proxy_hosts
from packages.sca.dockerfile_from import dockerfile_registry_hosts


# ---------------------------------------------------------------------------
# dockerfile_registry_hosts — extraction
# ---------------------------------------------------------------------------


def test_no_dockerfiles_returns_empty(tmp_path):
    assert dockerfile_registry_hosts(tmp_path) == []


def test_dockerhub_short_form_yields_two_hosts(tmp_path):
    """``FROM python:3.11`` resolves to docker.io, which the host
    resolver expands to registry-1.docker.io + auth.docker.io."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
    hosts = dockerfile_registry_hosts(tmp_path)
    assert "registry-1.docker.io" in hosts
    assert "auth.docker.io" in hosts


def test_ghcr_single_host(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM ghcr.io/anthropics/claude-code:0.1\n"
    )
    assert dockerfile_registry_hosts(tmp_path) == ["ghcr.io"]


def test_multiple_dockerfiles_unioned(tmp_path):
    """Two Dockerfiles with different registries → both registries'
    hosts appear in the result."""
    (tmp_path / "Dockerfile.api").write_text("FROM python:3.11\n")
    (tmp_path / "Dockerfile.tools").write_text("FROM ghcr.io/x/y:1\n")
    hosts = set(dockerfile_registry_hosts(tmp_path))
    assert "registry-1.docker.io" in hosts
    assert "ghcr.io" in hosts


def test_multi_stage_unions_hosts(tmp_path):
    """A multi-stage Dockerfile pulling from two different
    registries surfaces both."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11 AS builder\n"
        "RUN pip install build\n"
        "FROM ghcr.io/x/runtime:1\n"
    )
    hosts = set(dockerfile_registry_hosts(tmp_path))
    assert "registry-1.docker.io" in hosts
    assert "ghcr.io" in hosts


def test_scratch_skipped(tmp_path):
    """``FROM scratch`` is no registry pull — contributes no
    hosts."""
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    assert dockerfile_registry_hosts(tmp_path) == []


def test_intra_stage_reuse_skipped(tmp_path):
    """``FROM <stage>`` referring to an earlier ``AS <stage>`` is
    intra-Dockerfile reuse; no extra registry host needed."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11 AS base\n"
        "FROM base\n"
    )
    hosts = set(dockerfile_registry_hosts(tmp_path))
    # Only python:3.11's hosts; no host added for the bare ``base``.
    assert hosts == {"registry-1.docker.io", "auth.docker.io"}


def test_excluded_dirs_skipped(tmp_path):
    """Dockerfiles inside node_modules / vendor / .git aren't
    project-authoritative and aren't scanned."""
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "Dockerfile").write_text(
        "FROM python:3.11\n"
    )
    assert dockerfile_registry_hosts(tmp_path) == []


def test_unparseable_image_ref_skipped_silently(tmp_path):
    """A FROM with a malformed ref is logged + skipped, not
    fatal."""
    (tmp_path / "Dockerfile.bad").write_text(
        "FROM \nRUN echo hi\n"          # blank ref
    )
    (tmp_path / "Dockerfile.good").write_text("FROM ghcr.io/x/y:1\n")
    hosts = set(dockerfile_registry_hosts(tmp_path))
    # Bad Dockerfile contributes nothing; good one still does.
    assert hosts == {"ghcr.io"}


def test_dedup_across_multiple_dockerfiles_with_same_registry(tmp_path):
    """Three Dockerfiles all pulling from docker.io — each
    contributes the same two hosts; result is deduplicated."""
    (tmp_path / "Dockerfile.a").write_text("FROM python:3.11\n")
    (tmp_path / "Dockerfile.b").write_text("FROM debian:11\n")
    (tmp_path / "Dockerfile.c").write_text("FROM alpine:3.18\n")
    hosts = dockerfile_registry_hosts(tmp_path)
    assert hosts == sorted(set(hosts))           # deduplicated
    assert set(hosts) == {"registry-1.docker.io", "auth.docker.io"}


def test_output_is_sorted(tmp_path):
    """Operators care that the allowlist is composed
    deterministically."""
    (tmp_path / "Dockerfile").write_text(
        "FROM ghcr.io/x/y:1\nFROM python:3.11\n"
    )
    hosts = dockerfile_registry_hosts(tmp_path)
    assert hosts == sorted(hosts)


# ---------------------------------------------------------------------------
# agent._compose_proxy_hosts — sandbox allowlist composition
# ---------------------------------------------------------------------------


def test_compose_proxy_hosts_no_dockerfiles_matches_static_set(tmp_path):
    """Empty target → result equals SCA_ALLOWED_HOSTS; preserves
    the existing test_passes_proxy_hosts contract."""
    hosts = _compose_proxy_hosts(tmp_path)
    assert set(hosts) == set(SCA_ALLOWED_HOSTS)


def test_compose_proxy_hosts_with_dockerfile_unions(tmp_path):
    """A Dockerfile with a docker.io FROM extends the static set
    with the registry hosts the OCI client needs."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
    hosts = _compose_proxy_hosts(tmp_path)
    # Static set still present in full.
    assert set(SCA_ALLOWED_HOSTS) <= set(hosts)
    # Plus the docker.io plumbing.
    assert "registry-1.docker.io" in hosts
    assert "auth.docker.io" in hosts


def test_compose_proxy_hosts_static_first(tmp_path):
    """SCA_ALLOWED_HOSTS comes first (deterministic ordering for
    operators reading the allowlist), Dockerfile hosts appended."""
    (tmp_path / "Dockerfile").write_text("FROM ghcr.io/x/y:1\n")
    hosts = _compose_proxy_hosts(tmp_path)
    # Confirm static prefix matches SCA_ALLOWED_HOSTS exactly.
    assert hosts[: len(SCA_ALLOWED_HOSTS)] == list(SCA_ALLOWED_HOSTS)
    # And ghcr.io comes after.
    assert "ghcr.io" in hosts[len(SCA_ALLOWED_HOSTS):]


def test_compose_proxy_hosts_dedups_against_static_set(tmp_path):
    """If a Dockerfile happened to pull from a host that's already
    in SCA_ALLOWED_HOSTS, the result wouldn't carry duplicates."""
    # Use a Dockerfile FROM that resolves to a host already in the
    # static set. None of the static hosts are real OCI registries,
    # so this is a synthetic check via direct inspection of
    # _compose_proxy_hosts's dedup property.
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
    hosts = _compose_proxy_hosts(tmp_path)
    assert len(hosts) == len(set(hosts))
