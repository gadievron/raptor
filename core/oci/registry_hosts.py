"""Resolve a list of HTTPS hosts the sandbox must allow for a given
image reference's registry to work.

The sandbox's egress proxy takes a static allowlist
(``proxy_hosts=[...]``) at run time. For OCI work, the host(s) we
need depend on the image's registry, and some registries (notably
Docker Hub) split into multiple hosts: ``registry-1.docker.io``
serves manifests + blobs but ``auth.docker.io`` issues bearer tokens.

This resolver knows the well-known mappings. Project-internal /
self-hosted registries pass through as-is (``my-registry.corp.example``
just allows itself).

Adding a new registry family: extend ``_REGISTRY_FAMILIES`` with a
predicate + list of hosts. Tests should add coverage for the
predicate edge cases.
"""

from __future__ import annotations

import re
from typing import Callable, List, Tuple

from .image_ref import ImageRef, parse_image_ref


# Each entry is (predicate, hosts). The predicate takes the image's
# registry (e.g. "docker.io" or "1234.dkr.ecr.us-east-1.amazonaws.com")
# and returns True if this family applies. First match wins.
_REGISTRY_FAMILIES: List[Tuple[Callable[[str], bool], List[str]]] = [
    # Docker Hub: manifests on registry-1, tokens on auth.
    (lambda r: r == "docker.io",
     ["registry-1.docker.io", "auth.docker.io"]),

    # GitHub Container Registry: single host, anonymous OK for public.
    (lambda r: r == "ghcr.io", ["ghcr.io"]),

    # GitHub Packages (legacy npm/maven, not OCI but operators
    # sometimes write ``docker.pkg.github.com/...``).
    (lambda r: r == "docker.pkg.github.com",
     ["docker.pkg.github.com"]),

    # AWS ECR private — host shape ``<acct>.dkr.ecr.<region>.amazonaws.com``.
    # ECR auth uses STS-issued tokens; the host itself plus the STS
    # endpoint for the region.
    (lambda r: bool(re.match(
        r"^\d+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com$", r,
    )),
     # The STS regional host gets injected at runtime since the
     # region is in the registry name. The list-form helper below
     # handles that. For static use, allow the registry alone and
     # let the ECR auth code add STS dynamically.
     []),       # filled by ``_aws_ecr_hosts(registry)`` below

    # AWS ECR public — ``public.ecr.aws``.
    (lambda r: r == "public.ecr.aws", ["public.ecr.aws"]),

    # Quay.io.
    (lambda r: r == "quay.io", ["quay.io"]),

    # Google Container Registry / Artifact Registry.
    (lambda r: r in {"gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"},
     [None]),     # fill the registry-name as the host (see below)
    (lambda r: r.endswith("-docker.pkg.dev"),
     [None]),     # Artifact Registry: <region>-docker.pkg.dev

    # Azure Container Registry — ``<name>.azurecr.io``.
    (lambda r: r.endswith(".azurecr.io"), [None]),

    # GitLab Container Registry — usually ``registry.gitlab.com`` for
    # the SaaS, or ``registry.<host>`` for self-hosted.
    (lambda r: r == "registry.gitlab.com", ["registry.gitlab.com"]),
]


def registry_hosts_for(image: "str | ImageRef") -> List[str]:
    """Return the list of HTTPS hostnames the sandbox must allow for
    operations against ``image``'s registry.

    Accepts either a raw image reference string (parsed via
    :func:`core.oci.image_ref.parse_image_ref`) or a pre-parsed
    :class:`ImageRef`. Always returns at least one host — the image's
    own registry — even when the registry isn't in the well-known
    families list.

    For ECR private registries the regional STS host is added so the
    auth dance succeeds. The list is deduplicated and order-stable.
    """
    if isinstance(image, str):
        ref = parse_image_ref(image)
    else:
        ref = image

    registry = ref.registry
    out: List[str] = []
    matched_family = False
    for predicate, hosts in _REGISTRY_FAMILIES:
        if not predicate(registry):
            continue
        matched_family = True
        if hosts == []:                            # ECR private special-case
            out.extend(_aws_ecr_hosts(registry))
        elif hosts == [None]:                      # registry name IS the host
            out.append(registry)
        else:
            out.extend(hosts)
        break

    if not matched_family:
        # Unknown registry — assume the host is the registry name
        # itself. Operators with self-hosted / corporate registries
        # always satisfy this (their registry IS its own host); the
        # failure mode for genuinely-bogus references is later, when
        # the auth or manifest call fails clearly.
        out.append(registry)

    # Dedup, preserve order.
    seen = set()
    deduped: List[str] = []
    for h in out:
        if h not in seen:
            seen.add(h)
            deduped.append(h)
    return deduped


def _aws_ecr_hosts(registry: str) -> List[str]:
    """ECR private: the registry host plus the regional STS endpoint
    for the auth dance.

    Registry shape: ``<account>.dkr.ecr.<region>.amazonaws.com``.
    Extract ``<region>``, return ``[registry, "sts.<region>.amazonaws.com",
    "ecr.<region>.amazonaws.com"]``. ``ecr.<region>.amazonaws.com`` is the
    AWS API endpoint that issues authorization tokens; ``sts`` is for
    role assumption when credentials are role-based."""
    match = re.match(
        r"^\d+\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$", registry,
    )
    if not match:
        return [registry]
    region = match.group(1)
    return [
        registry,
        f"ecr.{region}.amazonaws.com",
        f"sts.{region}.amazonaws.com",
    ]


def api_endpoint_for(registry: str) -> str:
    """Return the actual HTTPS hostname to send registry-API requests to.

    For most registries this is the canonical name itself
    (``ghcr.io`` -> ``ghcr.io``). Docker Hub is the notable
    exception: the canonical name ``docker.io`` is a brand /
    namespace identifier, but the v2 API lives at
    ``registry-1.docker.io``. Connecting to ``docker.io`` directly
    returns 301-to-marketing-page or fails, depending on the path.

    Used by :class:`core.oci.client.RegistryClient` when building
    request URLs. Pairs with :func:`registry_hosts_for` which
    returns the same hostnames for sandbox-allowlist purposes —
    the proxy must permit whatever the client actually CONNECTs to,
    not the canonical name.
    """
    if registry == "docker.io":
        return "registry-1.docker.io"
    return registry


__all__ = ["api_endpoint_for", "registry_hosts_for"]
