"""Tests for ``core.oci.registry_hosts``.

The host-allowlist resolver is consulted at sandbox-construction
time — a wrong answer breaks operator scans (over-narrow → fetch
fails; over-broad → unnecessary network reachability). Each
registry family has its own quirks; tests pin them down so future
additions don't shift behaviour silently.
"""

from __future__ import annotations

from core.oci.image_ref import parse_image_ref
from core.oci.registry_hosts import registry_hosts_for


# ---------------------------------------------------------------------------
# Docker Hub
# ---------------------------------------------------------------------------


def test_docker_hub_returns_two_hosts():
    """Docker Hub splits manifests + auth across two hosts. Both
    must be on the allowlist or the bearer-token dance fails."""
    # Set-equality (rather than ``"x" in hosts``) because the
    # latter pattern trips CodeQL's incomplete-URL-substring
    # heuristic on string-shaped hostnames.
    hosts = registry_hosts_for("python:3.11")
    assert set(hosts) == {"registry-1.docker.io", "auth.docker.io"}


def test_docker_hub_works_with_explicit_registry_prefix():
    hosts = registry_hosts_for("docker.io/library/alpine:3")
    assert set(hosts) == {"registry-1.docker.io", "auth.docker.io"}


# ---------------------------------------------------------------------------
# GitHub Container Registry
# ---------------------------------------------------------------------------


def test_ghcr_single_host():
    """ghcr.io serves manifests + auth from one host. A single-host
    family stays single-host."""
    assert registry_hosts_for(
        "ghcr.io/anthropics/claude-code:0.1",
    ) == ["ghcr.io"]


# ---------------------------------------------------------------------------
# AWS ECR
# ---------------------------------------------------------------------------


def test_ecr_private_adds_regional_sts_and_ecr_api():
    """ECR private auth requires both the registry's own host AND
    the regional STS / ECR API hosts — the auth dance issues a
    short-lived token via the AWS SDK against those endpoints.
    Without them on the allowlist, anonymous pulls fail and
    authenticated pulls fail with cryptic 'connection refused'."""
    # Set-equality form sidesteps CodeQL's incomplete-URL-substring
    # heuristic on the ``"x" in hosts`` pattern with hostname-shaped
    # strings.
    hosts = registry_hosts_for(
        "1234.dkr.ecr.us-east-1.amazonaws.com/myapp:v2",
    )
    assert set(hosts) == {
        "1234.dkr.ecr.us-east-1.amazonaws.com",
        "ecr.us-east-1.amazonaws.com",
        "sts.us-east-1.amazonaws.com",
    }


def test_ecr_other_region():
    hosts = registry_hosts_for(
        "555.dkr.ecr.eu-west-2.amazonaws.com/img:1",
    )
    assert set(hosts) == {
        "555.dkr.ecr.eu-west-2.amazonaws.com",
        "ecr.eu-west-2.amazonaws.com",
        "sts.eu-west-2.amazonaws.com",
    }


def test_ecr_public_single_host():
    """Public ECR is a fixed host, no per-region split."""
    assert registry_hosts_for("public.ecr.aws/foo/bar:v1") == [
        "public.ecr.aws",
    ]


# ---------------------------------------------------------------------------
# GCR / Artifact Registry
# ---------------------------------------------------------------------------


def test_gcr_returns_self():
    hosts = registry_hosts_for("gcr.io/myproj/img:v1")
    assert hosts == ["gcr.io"]


def test_artifact_registry_regional():
    """Google Artifact Registry uses ``<region>-docker.pkg.dev``."""
    hosts = registry_hosts_for(
        "us-central1-docker.pkg.dev/myproj/repo/img:v1",
    )
    assert hosts == ["us-central1-docker.pkg.dev"]


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------


def test_azure_acr_returns_self():
    hosts = registry_hosts_for("myorg.azurecr.io/img:v1")
    assert hosts == ["myorg.azurecr.io"]


# ---------------------------------------------------------------------------
# GitLab
# ---------------------------------------------------------------------------


def test_gitlab_saas():
    hosts = registry_hosts_for("registry.gitlab.com/group/proj/img:v1")
    assert hosts == ["registry.gitlab.com"]


# ---------------------------------------------------------------------------
# Unknown / self-hosted
# ---------------------------------------------------------------------------


def test_unknown_registry_returns_self():
    """Unrecognised registries pass through as their own host. This
    is the right behaviour for self-hosted / corporate registries —
    the operator's registry IS its own host. If the host doesn't
    actually accept the OCI v2 API, the failure surfaces clearly
    later (404 / 405) rather than silently doing nothing."""
    hosts = registry_hosts_for("my-registry.corp.example/team/img:1")
    assert hosts == ["my-registry.corp.example"]


def test_localhost_registry():
    hosts = registry_hosts_for("localhost:5000/img:tag")
    assert hosts == ["localhost:5000"]


# ---------------------------------------------------------------------------
# Input shapes
# ---------------------------------------------------------------------------


def test_accepts_imageref_object_too():
    """The function accepts both raw strings and pre-parsed
    :class:`ImageRef` so consumers that already hold the parsed form
    don't pay double-parsing cost."""
    parsed = parse_image_ref("ghcr.io/x/y:1")
    assert registry_hosts_for(parsed) == ["ghcr.io"]


def test_dedup_preserves_order():
    """No duplicates in the output, original order preserved."""
    hosts = registry_hosts_for("python:3.11")
    assert len(hosts) == len(set(hosts))


# ---------------------------------------------------------------------------
# api_endpoint_for — canonical-name → API-host resolution for HTTP requests
# ---------------------------------------------------------------------------

def test_api_endpoint_for_docker_hub_routes_to_registry_1():
    """Docker Hub canonical ``docker.io`` is a brand identifier;
    the v2 API actually lives at ``registry-1.docker.io``."""
    from core.oci.registry_hosts import api_endpoint_for
    assert api_endpoint_for("docker.io") == "registry-1.docker.io"


def test_api_endpoint_for_ghcr_passthrough():
    from core.oci.registry_hosts import api_endpoint_for
    assert api_endpoint_for("ghcr.io") == "ghcr.io"


def test_api_endpoint_for_self_hosted_passthrough():
    from core.oci.registry_hosts import api_endpoint_for
    assert api_endpoint_for("registry.corp.example") \
        == "registry.corp.example"


def test_api_endpoint_for_quay_passthrough():
    from core.oci.registry_hosts import api_endpoint_for
    assert api_endpoint_for("quay.io") == "quay.io"
