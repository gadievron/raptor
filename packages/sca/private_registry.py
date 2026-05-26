"""Per-ecosystem registry-URL overrides for operators using
private mirrors (Artifactory / Nexus / GitHub Enterprise / etc.)
instead of the canonical public registries.

## Configuration

Operators set per-ecosystem environment variables; the SCA
pipeline picks them up at run-time and:

  1. Routes registry-metadata fetches to the override URL.
  2. Adds the override host to ``SCA_ALLOWED_HOSTS`` so the
     EgressClient permits the traffic.
  3. Threads an Authorization header (when configured) into
     each registry-client request.

Recognised env vars:

  * ``PIP_INDEX_URL`` — PyPI mirror URL (matches pip's existing
    convention; operators with this set for ``pip install``
    don't need to set anything new).
  * ``RAPTOR_SCA_PYPI_AUTH`` — Authorization header value
    (e.g. ``Bearer xyz`` or ``Basic <b64>``).
  * ``NPM_CONFIG_REGISTRY`` — npm mirror URL (matches the npm
    CLI's convention).
  * ``RAPTOR_SCA_NPM_AUTH`` — Authorization header value.
  * ``RAPTOR_SCA_MAVEN_REGISTRY`` — Maven mirror URL.
  * ``RAPTOR_SCA_MAVEN_AUTH`` — Authorization header value.

We *don't* read ``.netrc`` / ``.npmrc`` / ``settings.xml`` —
they're operator-side files in non-portable formats. The
env-var pattern keeps the SCA invocation explicit and matches
how container / CI environments configure private registries
already.

## Why no URL-embedded credentials

``core.http`` refuses URLs with embedded ``user:pass@`` for
security (those leak into logs and bypass header-based auth
guards). Hence the separate ``_AUTH`` env var per ecosystem.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RegistryOverride:
    """Operator's override for one ecosystem's registry."""

    base_url: str          # full URL to the mirror
    auth_header: Optional[str] = None


# Env-var names per ecosystem. Mirrors the upstream tool convention
# where one exists (PIP_INDEX_URL / NPM_CONFIG_REGISTRY); RAPTOR_SCA_*
# for ecosystems where no canonical env var exists.
_ENV_URL = {
    "PyPI": "PIP_INDEX_URL",
    "npm": "NPM_CONFIG_REGISTRY",
    "Maven": "RAPTOR_SCA_MAVEN_REGISTRY",
}

_ENV_AUTH = {
    "PyPI": "RAPTOR_SCA_PYPI_AUTH",
    "npm": "RAPTOR_SCA_NPM_AUTH",
    "Maven": "RAPTOR_SCA_MAVEN_AUTH",
}


def load_overrides(
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, RegistryOverride]:
    """Read env vars; return ``{ecosystem: RegistryOverride}``.

    Only ecosystems with a non-empty URL env var land in the
    output. Auth header is optional — included when its env var
    is also set.

    ``env`` parameter is for tests; production callers omit it
    and ``os.environ`` is consulted.
    """
    if env is None:
        env = os.environ
    out: Dict[str, RegistryOverride] = {}
    for ecosystem, url_var in _ENV_URL.items():
        url = (env.get(url_var) or "").strip()
        if not url:
            continue
        # Sanity-check: must be http(s) — refuses ``file://``,
        # ``ftp://``, etc. Same posture as ``core.http``.
        if not url.startswith(("http://", "https://")):
            logger.warning(
                "sca.private_registry: %s=%s — only http(s) URLs are "
                "accepted; ignoring", url_var, url,
            )
            continue
        auth = env.get(_ENV_AUTH[ecosystem])
        out[ecosystem] = RegistryOverride(
            base_url=url,
            auth_header=(auth.strip() if auth else None),
        )
    return out


def hosts_for_overrides(
    overrides: Dict[str, RegistryOverride],
) -> List[str]:
    """Extract the set of hostnames operators want the EgressClient
    to permit. Used by ``packages.sca.compose_proxy_hosts`` to expand
    the static allowlist with operator-supplied private hosts.
    """
    hosts: List[str] = []
    seen: set = set()
    for over in overrides.values():
        host = urlparse(over.base_url).hostname
        if host and host not in seen:
            hosts.append(host)
            seen.add(host)
    return hosts


def get(
    ecosystem: str,
    overrides: Optional[Dict[str, RegistryOverride]] = None,
) -> Optional[RegistryOverride]:
    """Convenience: fetch one ecosystem's override (or None).

    Loads from env when ``overrides`` is not passed."""
    if overrides is None:
        overrides = load_overrides()
    return overrides.get(ecosystem)


__all__ = [
    "RegistryOverride",
    "get",
    "hosts_for_overrides",
    "load_overrides",
]
