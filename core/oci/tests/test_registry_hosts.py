"""Tests for ``core.oci.registry_hosts``.

The host-allowlist resolver is consulted at sandbox-construction
time — a wrong answer breaks operator scans (over-narrow → fetch
fails; over-broad → unnecessary network reachability). Each
registry family has its own quirks; tests pin them down so future
additions don't shift behaviour silently.
"""

from __future__ import annotations

import pytest

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
# Elastic registry — auth-host split
# ---------------------------------------------------------------------------


def test_elastic_registry_returns_two_hosts():
    """``docker.elastic.co`` uses a separate ``docker-auth.elastic.co``
    for token issuance — same auth-host split as Docker Hub. Both
    hosts must be in the sandbox allowlist; an absent auth host
    surfaces as repeated proxy DENYs during manifest fetch. Surfaced
    by the May 2026 200-project sweep against Elasticsearch
    Maven artefacts that pull this base image."""
    hosts = registry_hosts_for(
        "docker.elastic.co/elasticsearch/elasticsearch:8.13.0",
    )
    assert hosts == ["docker.elastic.co", "docker-auth.elastic.co"]


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


def test_localhost_registry_refused():
    """Target-derived references naming loopback registries are an
    SSRF vector (they would join the egress allowlist); refused."""
    with pytest.raises(ValueError, match="localhost"):
        registry_hosts_for("localhost:5000/img:tag")


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


# ---------------------------------------------------------------------------
# Address / hostname policy for target-derived registries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("image", [
    "169.254.169.254/latest/meta-data:x",       # cloud metadata
    "127.0.0.1:8443/img:tag",                   # loopback IP
    "10.0.0.8:5000/img:tag",                    # RFC1918
    "172.16.3.4/img:tag",                       # RFC1918
    "192.168.1.1:5000/img:tag",                 # RFC1918
    "100.64.0.1:5000/img:tag",                  # shared address space
    "0.0.0.0:5000/img:tag",                     # unspecified
    "[::1]:5000/img:tag",                       # IPv6 loopback
    "[fe80::1]:5000/img:tag",                   # IPv6 link-local
])
def test_non_global_ip_literal_registry_refused(image):
    """Target-derived references must not point egress at internal
    or metadata endpoints via IP-literal registries."""
    with pytest.raises(ValueError, match="SSRF|not\\b.*routable"):
        registry_hosts_for(image)


@pytest.mark.parametrize("image", [
    "evil_host.com/img:tag",                    # underscore label
    "bad..name.com/img:tag",                    # empty label
    "-leadingdash.com/img:tag",                 # bad label shape
    "host.example:99999/img:tag",               # bogus port
    "host.example:0/img:tag",                   # bogus port
])
def test_malformed_registry_hostnames_refused(image):
    with pytest.raises(ValueError, match="malformed"):
        registry_hosts_for(image)


def test_global_ip_literal_registry_allowed():
    """A globally-routable IP literal is unusual but legitimate."""
    assert registry_hosts_for("8.8.8.8:5000/img:tag") == ["8.8.8.8:5000"]


def test_corporate_hostname_registry_still_allowed():
    assert registry_hosts_for("registry.corp.example/img:tag") \
        == ["registry.corp.example"]


def test_api_endpoint_refuses_non_global_registry():
    """The client resolves every request URL through
    api_endpoint_for — the same policy applies there so callers that
    skip registry_hosts_for get no weaker gate."""
    from core.oci.registry_hosts import api_endpoint_for
    with pytest.raises(ValueError, match="SSRF|not\\b.*routable"):
        api_endpoint_for("169.254.169.254")
    with pytest.raises(ValueError, match="localhost"):
        api_endpoint_for("localhost:5000")


# ---------------------------------------------------------------------------
# inet_aton-shape hostnames — the resolver's address grammar is wider
# than ipaddress's. Every shape below passed the hostname branch while
# glibc resolved it as an IPv4 literal (no DNS involved), driving the
# OCI client into loopback / metadata TCP connects.
# ---------------------------------------------------------------------------

_INET_ATON_BYPASS_SHAPES = [
    "127.1",                    # shorthand dotted -> 127.0.0.1
    "127.0.0.1.",               # trailing dot -> 127.0.0.1
    "2130706433",               # bare decimal -> 127.0.0.1
    "0x7f000001",               # hex -> 127.0.0.1
    "0177.0.0.1",               # octal first label -> 127.0.0.1
    "2852039166",               # bare decimal -> 169.254.169.254
    "0xa9fea9fe",               # hex -> 169.254.169.254
    "169.254.43518",            # 3-label dotted -> 169.254.169.254
    "[64:ff9b::a9fe:a9fe]",     # NAT64-embedded 169.254.169.254
]


@pytest.mark.parametrize("registry", _INET_ATON_BYPASS_SHAPES)
def test_inet_aton_shape_registry_refused(registry):
    """Numeric/hex/octal/trailing-dot address shapes must be
    normalised to the parsed address FIRST and then refused by the
    same non-global policy as proper IP literals."""
    from core.oci.registry_hosts import _validate_registry_host
    with pytest.raises(ValueError, match="SSRF|not\\b.*routable"):
        _validate_registry_host(registry)


@pytest.mark.parametrize("registry", _INET_ATON_BYPASS_SHAPES)
def test_inet_aton_shape_registry_refused_with_port(registry):
    """Same shapes with an explicit :port (the live PoC used
    ``FROM 127.1:<port>/app``)."""
    from core.oci.registry_hosts import _validate_registry_host
    with pytest.raises(ValueError, match="SSRF|not\\b.*routable"):
        _validate_registry_host(f"{registry}:5000")


def test_inet_aton_shape_refused_at_image_level():
    """End to end through the image-ref path dockerfile_from uses."""
    with pytest.raises(ValueError, match="SSRF|not\\b.*routable"):
        registry_hosts_for("127.1:5000/app:latest")


def test_api_endpoint_refuses_inet_aton_shapes():
    from core.oci.registry_hosts import api_endpoint_for
    with pytest.raises(ValueError, match="SSRF|not\\b.*routable"):
        api_endpoint_for("0x7f000001")
    with pytest.raises(ValueError, match="SSRF|not\\b.*routable"):
        api_endpoint_for("169.254.43518:8443")


@pytest.mark.parametrize("registry", [
    "1.2.3.4.5",                # five numeric labels — not inet_aton
    "300.300.300.300",          # out-of-range octets — not inet_aton
    "0x.1",                     # bare hex prefix label
])
def test_all_numeric_label_hostnames_refused(registry):
    """Names built only from numeric/hex labels that even inet_aton
    refuses are address syntax to laxer resolvers, never legitimate
    registries — refused outright rather than sent to DNS."""
    from core.oci.registry_hosts import _validate_registry_host
    with pytest.raises(ValueError, match="SSRF|numeric"):
        _validate_registry_host(registry)


def test_ipv4_mapped_ipv6_literal_refused():
    """Embedded-IPv4 extraction keeps mapped loopback refused even
    if a future Python changes is_global on mapped addresses."""
    from core.oci.registry_hosts import _validate_registry_host
    with pytest.raises(ValueError, match="SSRF|not\\b.*routable"):
        _validate_registry_host("[::ffff:127.0.0.1]")


def test_global_ip_shorthand_still_follows_ip_policy():
    """The normalise-first rule applies the ADDRESS policy, not a
    shape ban: a shorthand form of a globally-routable address is
    treated exactly like its canonical literal."""
    from core.oci.registry_hosts import _validate_registry_host
    _validate_registry_host("8.8.8.8")          # canonical, global
    _validate_registry_host("8.8.8.8.")         # trailing dot, global


# ---------------------------------------------------------------------------
# Resolved-address gate — validate_resolved_registry_addresses
# ---------------------------------------------------------------------------


def _a_record(addr: str, port: int = 443):
    import socket
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
            "", (addr, port))


def _aaaa_record(addr: str, port: int = 443):
    import socket
    return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
            "", (addr, port, 0, 0))


def test_resolved_loopback_refused(monkeypatch):
    """A hostname whose A record answers 127.0.0.1 (rebinding /
    private DNS) is refused at resolution time."""
    import socket
    from core.oci.registry_hosts import validate_resolved_registry_addresses
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [_a_record("127.0.0.1")],
    )
    with pytest.raises(ValueError, match="rebinding|not globally routable"):
        validate_resolved_registry_addresses("innocent.example")


def test_resolved_nat64_metadata_refused(monkeypatch):
    """An AAAA answer of 64:ff9b::a9fe:a9fe is is_global=True but
    embeds 169.254.169.254 — the embedded v4 policy must fire."""
    import socket
    from core.oci.registry_hosts import validate_resolved_registry_addresses
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [_aaaa_record("64:ff9b::a9fe:a9fe")],
    )
    with pytest.raises(ValueError, match="rebinding|not globally routable"):
        validate_resolved_registry_addresses("innocent.example")


def test_resolved_any_bad_address_refuses(monkeypatch):
    """ANY non-global answer refuses, even alongside global ones —
    the attacker controls answer ordering."""
    import socket
    from core.oci.registry_hosts import validate_resolved_registry_addresses
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [_a_record("8.8.8.8"),
                         _a_record("192.168.1.1")],
    )
    with pytest.raises(ValueError, match="rebinding|not globally routable"):
        validate_resolved_registry_addresses("innocent.example")


def test_resolved_all_global_passes(monkeypatch):
    import socket
    from core.oci.registry_hosts import validate_resolved_registry_addresses
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [_a_record("8.8.8.8"),
                         _aaaa_record("2606:4700::6810:85e5")],
    )
    validate_resolved_registry_addresses("registry.corp.example")


def test_unresolvable_host_refused(monkeypatch):
    """Fail closed: a selectively-failing resolver must not downgrade
    the gate, and an unresolvable fetch could not succeed anyway."""
    import socket
    from core.oci.registry_hosts import validate_resolved_registry_addresses

    def _boom(*a, **k):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    with pytest.raises(ValueError, match="cannot resolve"):
        validate_resolved_registry_addresses("innocent.example")


def test_resolution_gate_ip_literal_skips_dns(monkeypatch):
    """IP-literal registries never touch the resolver — the literal
    policy applies directly (and refuses non-global)."""
    import socket
    from core.oci.registry_hosts import validate_resolved_registry_addresses

    def _no_dns(*a, **k):
        raise AssertionError("getaddrinfo must not be called for literals")

    monkeypatch.setattr(socket, "getaddrinfo", _no_dns)
    validate_resolved_registry_addresses("8.8.8.8:5000")
    with pytest.raises(ValueError, match="SSRF|not\\b.*routable"):
        validate_resolved_registry_addresses("127.1:5000")


def test_client_refuses_registry_resolving_to_loopback(monkeypatch):
    """The OCI client re-validates resolved addresses before ANY
    request bytes leave — a rebinding registry never sees a TCP
    connect, not even the first manifest HEAD."""
    import socket
    from core.oci.client import OciRegistryClient, RegistryError

    class _NoHttp:
        def request(self, *a, **k):
            raise AssertionError("HTTP request must not be issued")

    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [_a_record("127.0.0.1")],
    )
    client = OciRegistryClient(http=_NoHttp())
    ref = parse_image_ref("registry.corp.example/team/img:1")
    with pytest.raises(RegistryError,
                       match="rebinding|not globally routable"):
        client.resolve_digest(ref)


def test_client_refuses_registry_resolving_to_nat64_metadata(monkeypatch):
    import socket
    from core.oci.client import OciRegistryClient, RegistryError

    class _NoHttp:
        def request(self, *a, **k):
            raise AssertionError("HTTP request must not be issued")

    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [_aaaa_record("64:ff9b::a9fe:a9fe")],
    )
    client = OciRegistryClient(http=_NoHttp())
    ref = parse_image_ref("registry.corp.example/team/img:1")
    with pytest.raises(RegistryError,
                       match="rebinding|not globally routable"):
        client.resolve_digest(ref)
