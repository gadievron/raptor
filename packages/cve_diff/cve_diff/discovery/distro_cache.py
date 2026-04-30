"""Distro security-tracker fetcher with disk cache.

Three trackers fetched in parallel: Debian, Ubuntu, Red Hat. Per-CVE,
per-distro cache lives under ``~/.cache/cve-diff/distro/`` so a Debian
404 doesn't block re-trying Ubuntu, and a successful run isn't re-hit
on bench reruns.

Each per-distro fetch returns a dict with the same shape::

    {
        "status": "fixed|open|not-affected|unknown" | None,
        "fix_version": "<package version string>" | None,
        "references": ["<url>", ...],
    }

…or an error dict::

    {"error": "<short message>"}

Candidate ``(slug, sha)`` extraction is the caller's responsibility —
this module returns reference URLs untouched.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "cve-diff" / "distro"
_TIMEOUT_S = 10.0
_MAX_BYTES = 256 * 1024
_USER_AGENT = "cve-diff-agent/0.1"

_DEBIAN_URL = "https://security-tracker.debian.org/tracker/{cve_id}"
_UBUNTU_URL = "https://ubuntu.com/security/cves.json?q={cve_id}"
_REDHAT_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"

_HREF_RE = re.compile(r'href="([^"]+)"', re.IGNORECASE)


@dataclass
class DistroFetcher:
    cache_enabled: bool = True
    cache_dir: Path = field(default_factory=lambda: DEFAULT_CACHE_DIR)
    _mem: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)

    def fetch_all(self, cve_id: str) -> dict[str, dict[str, Any]]:
        """Fan out to 3 distros in parallel, return per-distro results."""
        if not _is_cve_id(cve_id):
            return {d: {"error": "invalid cve_id"} for d in ("debian", "ubuntu", "redhat")}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                "debian": pool.submit(self._cached, "debian", cve_id, _fetch_debian),
                "ubuntu": pool.submit(self._cached, "ubuntu", cve_id, _fetch_ubuntu),
                "redhat": pool.submit(self._cached, "redhat", cve_id, _fetch_redhat),
            }
            return {name: fut.result() for name, fut in futures.items()}

    def _cached(self, distro: str, cve_id: str, fetcher) -> dict[str, Any]:
        key = (distro, cve_id)
        if key in self._mem:
            return self._mem[key]
        if self.cache_enabled:
            disk = self._read_disk(distro, cve_id)
            if disk is not None:
                self._mem[key] = disk
                return disk
        result = fetcher(cve_id)
        # Cache 200s and structural 404s (CVE not tracked there is a
        # stable answer). Skip transient network errors so a retry can
        # succeed.
        if "error" not in result or result["error"].startswith("http "):
            if self.cache_enabled:
                self._write_disk(distro, cve_id, result)
        self._mem[key] = result
        return result

    def _cache_path(self, distro: str, cve_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", cve_id)
        return self.cache_dir / f"{distro}_{safe}.json"

    def _read_disk(self, distro: str, cve_id: str) -> dict[str, Any] | None:
        try:
            raw = self._cache_path(distro, cve_id).read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def _write_disk(self, distro: str, cve_id: str, payload: dict[str, Any]) -> None:
        path = self._cache_path(distro, cve_id)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass


def _is_cve_id(cve_id: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id or ""))


def _get(url: str) -> requests.Response | dict[str, Any]:
    try:
        resp = requests.get(url, timeout=_TIMEOUT_S, headers={"User-Agent": _USER_AGENT})
    except requests.RequestException as exc:
        return {"error": f"network: {str(exc)[:200]}"}
    return resp


def _fetch_debian(cve_id: str) -> dict[str, Any]:
    """Scrape Debian security-tracker HTML — extract anchor URLs +
    'Fixed by:' notes line."""
    resp = _get(_DEBIAN_URL.format(cve_id=cve_id))
    if isinstance(resp, dict):
        return resp
    if resp.status_code != 200:
        return {"error": f"http {resp.status_code}"}
    body = resp.text[:_MAX_BYTES]
    refs: list[str] = []
    for href in _HREF_RE.findall(body):
        if (href.startswith("http://") or href.startswith("https://")) and href not in refs:
            refs.append(href)
    status = "fixed" if "fixed" in body.lower() else None
    return {"status": status, "fix_version": None, "references": refs[:50]}


def _fetch_ubuntu(cve_id: str) -> dict[str, Any]:
    """Ubuntu CVE search API — returns JSON with cves[].references + notes."""
    resp = _get(_UBUNTU_URL.format(cve_id=cve_id))
    if isinstance(resp, dict):
        return resp
    if resp.status_code != 200:
        return {"error": f"http {resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        return {"error": "non-json response"}
    cves = data.get("cves") or []
    match = next((c for c in cves if (c.get("id") or "").upper() == cve_id.upper()), None)
    if match is None:
        return {"error": "http 404"}
    refs = list(match.get("references") or [])
    for note in match.get("notes") or []:
        text = note.get("note") if isinstance(note, dict) else str(note)
        if isinstance(text, str):
            refs.append(text)
    status = match.get("status") or None
    fix_version = None
    pkgs = match.get("packages") or []
    if pkgs and isinstance(pkgs[0], dict):
        fix_version = pkgs[0].get("statuses", [{}])[0].get("description") if pkgs[0].get("statuses") else None
    return {"status": status, "fix_version": fix_version, "references": refs[:50]}


def _fetch_redhat(cve_id: str) -> dict[str, Any]:
    """Red Hat hydra security-data API — returns JSON with references[]."""
    resp = _get(_REDHAT_URL.format(cve_id=cve_id))
    if isinstance(resp, dict):
        return resp
    if resp.status_code != 200:
        return {"error": f"http {resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        return {"error": "non-json response"}
    refs = list(data.get("references") or [])
    affected = data.get("affected_release") or []
    fix_version = affected[0].get("package") if affected and isinstance(affected[0], dict) else None
    status = "fixed" if affected else None
    return {"status": status, "fix_version": fix_version, "references": refs[:50]}
