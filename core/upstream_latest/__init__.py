"""Look up the latest stable version of an upstream package /
release artefact.

Centralised module so multiple call sites (current SCA bumper +
future ``/agentic`` upstream-checks, ``cve-diff`` upstream
resolution, etc.) don't each reinvent "fetch from GitHub
releases, filter to stable semver, strip v prefix, cache for
24h, respect rate limits".

This package ships three registry kinds:
  * :mod:`github_releases` — GitHub releases / tags endpoints
    plus the ``resolve_tag_to_sha`` primitive
  * :mod:`oci_tags` — OCI Distribution Spec tag listings
    (Docker Hub / ghcr.io / etc.)
  * :mod:`helm_index` — Helm repository index.yaml lookups

Why centralise: the patterns drift otherwise. Multiple
copies of "is this tag stable-semver" leads to "is this *quite*
stable-semver" variants that handle edge cases differently —
one source of truth (see :mod:`_version_filter`) keeps the
substrate honest.
"""

from core.upstream_latest.github_releases import (
    GITHUB_API_BASE,
    NoStableVersionsFound,
    UpstreamLookupError,
    latest_release,
    latest_tag,
    resolve_tag_to_sha,
)
from core.upstream_latest.helm_index import latest_chart_version
from core.upstream_latest.oci_tags import (
    latest_tag as latest_oci_tag,
    list_all_tags as list_all_oci_tags,
)

__all__ = [
    "GITHUB_API_BASE",
    "NoStableVersionsFound",
    "UpstreamLookupError",
    "latest_release",
    "latest_tag",
    "resolve_tag_to_sha",
    "latest_oci_tag",
    "list_all_oci_tags",
    "latest_chart_version",
]
