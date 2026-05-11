"""Look up the latest stable version of an upstream package /
release artefact.

Centralised module so multiple call sites (current SCA bumper +
future ``/agentic`` upstream-checks, ``cve-diff`` upstream
resolution, etc.) don't each reinvent "fetch from GitHub
releases, filter to stable semver, strip v prefix, cache for
24h, respect rate limits".

This commit ships :mod:`github_releases` (GitHub releases / tags
endpoints + tag→SHA resolution). Subsequent commits add
``oci_tags`` (OCI registry tag listings) and ``helm_index``
(Helm repo index.yaml lookups).

Why centralise: the patterns drift otherwise. Multiple
copies of "is this tag stable-semver" leads to "is this *quite*
stable-semver" variants that handle edge cases differently —
one source of truth keeps the substrate honest.
"""

from core.upstream_latest.github_releases import (
    GITHUB_API_BASE,
    NoStableVersionsFound,
    UpstreamLookupError,
    latest_release,
    latest_tag,
    resolve_tag_to_sha,
)

__all__ = [
    "GITHUB_API_BASE",
    "NoStableVersionsFound",
    "UpstreamLookupError",
    "latest_release",
    "latest_tag",
    "resolve_tag_to_sha",
]
