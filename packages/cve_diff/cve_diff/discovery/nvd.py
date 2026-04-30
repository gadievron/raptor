"""
NVD Patch-tag discoverer.

NVD's `references[].tags` carries a `"Patch"` marker on references the
analyst considered load-bearing — which for nearly every open-source CVE
includes a `github.com/<owner>/<repo>/commit/<sha>` URL. That's structured
(slug, sha) data we weren't consulting; the cascade previously fell
through to a date-floored commit search when OSV lacked a fix SHA, which
is weaker evidence than NVD's curated Patch link.

Placement in the cascade (osv → nvd → github_api) reflects coverage:
- OSV covers most OSS CVEs with both slug and fix_commit.
- NVD Patch-tagged refs cover a different set (vendor-first CVEs, Linux
  backports, some cases OSV never picked up).
- github_api is the last resort when neither OSV nor NVD resolves.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from cve_diff.core.models import CommitSha, DiscoveryResult, PatchTuple

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Disk cache location. Shared across ProcessPoolExecutor workers (each has its
# own memory-local cache, but this disk layer lets one worker's successful
# fetch serve every other worker's same-CVE call — preventing the 429 storm
# observed 2026-04-23 on random_2022_40 `-w 4`.
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "cve-diff" / "nvd"
_NVD_CACHE_MARKER_MISSING = "__MISSING__"
# NVD's endpoint is unusually slow (median 2–4 s, p95 > 15 s under load).
# The 2026-04-20 re-bench had the default 10 s timeout fire on roughly all
# 80 CVEs — Phase D contributed zero rescues as a result. 30 s lets the
# endpoint finish while still capping the cascade's per-CVE budget.
DEFAULT_TIMEOUT_S = 30
# NVD public quota is 5 req / 30 s; Cloudflare returns 429 with
# `Retry-After: 0` when exceeded. Measured 2026-04-23 on random_2022_40
# with `-w 4`: half the workers hit 429 on the cascade's up-front
# `fetch_context` call, losing CPE enrichment and producing scorer
# false-passes (`CpanelInc/tech-CSI`, `Al1ex/LinuxEelvation`,
# `Metarget/metarget`). Retrying respects Retry-After and caps total
# retries so a persistently-rate-limited run fails fast rather than
# blocking the bench for minutes.
_RETRY_MAX = 4
_RETRY_BASE_S = 1.0

_GITHUB_COMMIT_URL_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/#?]+)/commit/([a-f0-9]{7,40})",
    re.IGNORECASE,
)


_SENTINEL_USE_DEFAULT = object()


@dataclass
class NvdDiscoverer:
    timeout_s: int = DEFAULT_TIMEOUT_S
    cache_enabled: bool = True
    # Sentinel so tests can monkeypatch the module-level DEFAULT_CACHE_DIR
    # and have it take effect — a bound class-level default would freeze at
    # class-creation time.
    disk_cache_dir: Path | None = field(default=_SENTINEL_USE_DEFAULT)  # type: ignore[assignment]
    _cache: dict[str, dict[str, Any] | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.disk_cache_dir is _SENTINEL_USE_DEFAULT:
            self.disk_cache_dir = DEFAULT_CACHE_DIR

    def fetch(self, cve_id: str) -> DiscoveryResult | None:
        payload = self.get_payload(cve_id)
        if payload is None:
            return None
        return self.parse(payload)

    def get_payload(self, cve_id: str) -> dict[str, Any] | None:
        """Public payload accessor. Cached at the per-process level and on
        disk at ``~/.cache/cve-diff/nvd/`` so a single worker's successful
        fetch serves every other ``ProcessPoolExecutor`` worker's
        identical-CVE call. The agent's ``nvd_raw`` /
        ``deterministic_hints`` tools use this directly."""
        if self.cache_enabled and cve_id in self._cache:
            return self._cache[cve_id]
        if self.cache_enabled and self.disk_cache_dir is not None:
            disk = self._read_disk_cache(cve_id)
            if disk is not None:
                payload = None if disk == _NVD_CACHE_MARKER_MISSING else disk
                self._cache[cve_id] = payload
                return payload
        payload = self._fetch_with_retry(cve_id)
        if self.cache_enabled:
            self._cache[cve_id] = payload
            if self.disk_cache_dir is not None:
                self._write_disk_cache(cve_id, payload)
        return payload

    def _cache_path(self, cve_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", cve_id)
        return (self.disk_cache_dir or DEFAULT_CACHE_DIR) / f"{safe}.json"

    def _read_disk_cache(self, cve_id: str) -> dict[str, Any] | str | None:
        path = self._cache_path(cve_id)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        if data == _NVD_CACHE_MARKER_MISSING:
            return _NVD_CACHE_MARKER_MISSING
        return data if isinstance(data, dict) else None

    def _write_disk_cache(self, cve_id: str, payload: dict[str, Any] | None) -> None:
        path = self._cache_path(cve_id)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic-ish write via temp file in the same directory.
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(payload if payload is not None else _NVD_CACHE_MARKER_MISSING),
                encoding="utf-8",
            )
            tmp.replace(path)
        except OSError:
            pass

    def _fetch_with_retry(self, cve_id: str) -> dict[str, Any] | None:
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        headers = {"apiKey": api_key} if api_key else {}
        delay_s = _RETRY_BASE_S
        for attempt in range(_RETRY_MAX + 1):
            try:
                response = requests.get(
                    BASE_URL,
                    params={"cveId": cve_id},
                    headers=headers,
                    timeout=self.timeout_s,
                )
            except requests.RequestException:
                return None
            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError:
                    return None
            if response.status_code == 429:
                from cve_diff.infra import api_status
                api_status.record_rate_limit("nvd", 429)
            if response.status_code == 429 and attempt < _RETRY_MAX:
                retry_after = response.headers.get("Retry-After", "")
                try:
                    wait_s = max(float(retry_after), delay_s) if retry_after else delay_s
                except ValueError:
                    wait_s = delay_s
                # Cloudflare sometimes returns Retry-After: 0 even when the
                # quota window hasn't cleared; floor at delay_s so we don't
                # spin. Exponential backoff on subsequent retries.
                if wait_s > 0:
                    time.sleep(wait_s)
                delay_s *= 2
                continue
            return None
        return None

    @classmethod
    def parse(cls, payload: dict[str, Any]) -> DiscoveryResult | None:
        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            return None
        cve = (vulns[0] or {}).get("cve") or {}
        refs = cve.get("references") or []

        tuples: list[PatchTuple] = []
        seen: set[tuple[str, str]] = set()
        for ref in refs:
            tags = ref.get("tags") or []
            if "Patch" not in tags:
                continue
            url = ref.get("url") or ""
            m = _GITHUB_COMMIT_URL_RE.match(url)
            if not m:
                continue
            slug = m.group(1).removesuffix(".git")
            sha = m.group(2).lower()
            key = (slug, sha)
            if key in seen:
                continue
            seen.add(key)
            tuples.append(
                PatchTuple(
                    repository_url=f"https://github.com/{slug}",
                    fix_commit=CommitSha(sha),
                    introduced=None,
                )
            )

        if not tuples:
            return None
        return DiscoveryResult(
            source="nvd",
            tuples=tuple(tuples),
            confidence=70,
            raw=cve,
        )
