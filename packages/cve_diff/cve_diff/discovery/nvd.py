"""NVD Patch-tag discoverer.

Wraps ``packages.nvd.NvdClient`` with cve-diff-specific domain types
(:class:`DiscoveryResult`, :class:`PatchTuple`) and the rate-limit
telemetry callback (``cve_diff.infra.api_status``).

The shared client handles API fetch, retry, and caching.  This module
adds:

  - ``NvdDiscoverer.fetch()`` → ``DiscoveryResult | None``
  - ``NvdDiscoverer.parse()`` → converts raw NVD payload to tuples
  - Rate-limit callback wired to ``api_status.record_rate_limit``
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packages.nvd import extract_patch_refs
from packages.nvd.client import (
    DEFAULT_TIMEOUT_S,
    NvdClient,
    _SENTINEL_USE_DEFAULT,
)

from cve_diff.core.models import CommitSha, DiscoveryResult, PatchTuple

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _rate_limit_callback() -> None:
    from cve_diff.infra import api_status
    api_status.record_rate_limit("nvd", 429)


@dataclass
class NvdDiscoverer:
    """cve-diff facade over :class:`packages.nvd.NvdClient`."""

    timeout_s: int = DEFAULT_TIMEOUT_S
    cache_enabled: bool = True
    disk_cache_dir: Path | None = field(default=_SENTINEL_USE_DEFAULT)  # type: ignore[assignment]
    _client: NvdClient | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self._client is None:
            self._client = NvdClient(
                timeout_s=self.timeout_s,
                cache_enabled=self.cache_enabled,
                disk_cache_dir=self.disk_cache_dir,
                on_rate_limit=_rate_limit_callback,
            )

    def fetch(self, cve_id: str) -> DiscoveryResult | None:
        payload = self.get_payload(cve_id)
        if payload is None:
            return None
        return self.parse(payload)

    def get_payload(self, cve_id: str) -> dict[str, Any] | None:
        """Public payload accessor — delegates to the shared NvdClient."""
        assert self._client is not None
        return self._client.get_payload(cve_id)

    @classmethod
    def parse(cls, payload: dict[str, Any]) -> DiscoveryResult | None:
        """Convert NVD payload to a cve-diff :class:`DiscoveryResult`."""
        pairs = extract_patch_refs(payload)
        if not pairs:
            return None

        vulns = payload.get("vulnerabilities") or []
        raw = ((vulns[0] or {}).get("cve") or {}) if vulns else {}

        tuples: list[PatchTuple] = []
        for slug, sha in pairs:
            tuples.append(PatchTuple(
                repository_url=f"https://github.com/{slug}",
                fix_commit=CommitSha(sha),
                introduced=None,
            ))

        return DiscoveryResult(
            source="nvd",
            tuples=tuple(tuples),
            confidence=70,
            raw=raw,
        )
