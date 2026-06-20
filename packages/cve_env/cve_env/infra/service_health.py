"""Service-health probes.

For each external service the bench depends on, a fast (≤10s) probe that:

* Confirms the service is reachable
* Measures round-trip latency
* Reads any rate-limit headers if the service exposes them
* Returns a structured ``HealthResult`` for tabular display

Used by:

* ``cve-env doctor`` CLI command — manual health check at any time
* ``scripts/bench50.sh`` preflight — fail-fast on critical service outage,
  warn on non-critical.

Probes are deliberately small/cheap so they can run as a pre-flight without
delaying the main work. Each probe returns within ``_TIMEOUT_S`` (10s)
regardless of network state — a hung service surfaces as ``ok=False,
detail="timeout"`` rather than blocking.

Notes:

* No ``probe_anthropic`` (cve-env uses Claude Code session auth, not API key).
* ``probe_docker_hub`` + ``probe_quay`` + ``probe_ghcr`` + ``probe_mcr``
  cover the alt registries cve-env's ``image_resolve`` probes.
* Reads existing ``docker login`` state from ``~/.docker/config.json``.
"""

from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path

import requests

_TIMEOUT_S = 10.0
_DOCKER_TIMEOUT_S = 30.0  # docker manifest inspect is slow even cache-warm


@dataclass(frozen=True)
class HealthResult:
    name: str
    ok: bool
    latency_ms: float
    detail: str = ""
    rate_limit: str = ""  # human-readable hint if available

    def as_row(self) -> str:
        status = "✓" if self.ok else "✗"
        latency = f"{self.latency_ms:>6.0f} ms" if self.latency_ms < 99999 else "  --"
        rl = f" [{self.rate_limit}]" if self.rate_limit else ""
        return f"  {status}  {self.name:<22} {latency}  {self.detail[:60]}{rl}"


def _timed_get(
    url: str, headers: dict[str, str] | None = None
) -> tuple[float, requests.Response | None, str]:
    """Return (latency_ms, response, error). One of response/error is filled."""
    start = time.monotonic()
    try:
        resp = requests.get(
            url,
            headers=headers or {},
            timeout=_TIMEOUT_S,
            proxies={"http": "", "https": ""},  # disable env-based proxies
        )
        return ((time.monotonic() - start) * 1000.0, resp, "")
    except requests.RequestException as exc:
        return ((time.monotonic() - start) * 1000.0, None, str(exc)[:120])


def probe_dns() -> HealthResult:
    """Canary: 'is the network up at all?'"""
    start = time.monotonic()
    try:
        socket.gethostbyname("api.osv.dev")
    except socket.gaierror as exc:
        return HealthResult(
            "DNS resolution",
            ok=False,
            latency_ms=(time.monotonic() - start) * 1000.0,
            detail=f"resolve failure: {exc}",
        )
    return HealthResult(
        "DNS resolution",
        ok=True,
        latency_ms=(time.monotonic() - start) * 1000.0,
        detail="ok",
    )


def probe_nvd() -> HealthResult:
    """NVD: empirically returns 429 with Cloudflare 1015 after ~8 anon bursts.

    With ``NVD_API_KEY`` env var → ``apiKey`` header → 50 req/30s tier.
    """
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}
    latency, resp, err = _timed_get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-0160",
        headers=headers,
    )
    if err:
        return HealthResult(
            "NVD API", ok=False, latency_ms=latency, detail=f"network: {err}"
        )
    if resp is None or resp.status_code != 200:
        code = resp.status_code if resp else "?"
        rl_note = ""
        if resp is not None and resp.status_code == 429:
            rl_note = (
                "no API key — rate-limited (5 req/30s)"
                if not api_key
                else "rate-limited even with API key"
            )
        return HealthResult(
            "NVD API",
            ok=False,
            latency_ms=latency,
            detail=f"http {code}",
            rate_limit=rl_note,
        )
    rl = "with API key (50 req/30s)" if api_key else "no API key (5 req/30s — slow)"
    return HealthResult(
        "NVD API", ok=True, latency_ms=latency, detail="ok", rate_limit=rl
    )


def probe_osv() -> HealthResult:
    """OSV.dev: free, no auth, used as fallback when NVD throttles."""
    latency, resp, err = _timed_get("https://api.osv.dev/v1/vulns/CVE-2014-0160")
    if err:
        return HealthResult(
            "OSV API", ok=False, latency_ms=latency, detail=f"network: {err}"
        )
    if resp is None or resp.status_code != 200:
        code = resp.status_code if resp else "?"
        return HealthResult(
            "OSV API", ok=False, latency_ms=latency, detail=f"http {code}"
        )
    return HealthResult("OSV API", ok=True, latency_ms=latency, detail="ok")


def _resolve_github_token_for_probe() -> str:
    """Inline copy of resolve_github_token's logic — but we don't import it
    here to avoid pulling tools/* into the infra layer."""
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        return token
    # Uses run_with_timeout, which folds (FileNotFoundError,
    # TimeoutExpired, OSError) into outcome.returncode=None on transport
    # failure → "". The rc==0 path returns the token.
    from cve_env.utils.run import run_with_timeout

    outcome = run_with_timeout(["gh", "auth", "token"], timeout=2.0)
    if outcome.returncode == 0:
        return outcome.stdout.strip()
    return ""


def probe_github() -> HealthResult:
    """GitHub: reads x-ratelimit-* headers from the /rate_limit endpoint
    so we know the actual remaining/limit, not just whether we have a token."""
    token = _resolve_github_token_for_probe()
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    latency, resp, err = _timed_get(
        "https://api.github.com/rate_limit", headers=headers
    )
    if err:
        return HealthResult(
            "GitHub API", ok=False, latency_ms=latency, detail=f"network: {err}"
        )
    if resp is None or resp.status_code != 200:
        code = resp.status_code if resp else "?"
        return HealthResult(
            "GitHub API", ok=False, latency_ms=latency, detail=f"http {code}"
        )
    try:
        data = resp.json()
    except ValueError:
        return HealthResult(
            "GitHub API", ok=True, latency_ms=latency, detail="ok (non-JSON)"
        )
    core = (data.get("resources") or {}).get("core") or {}
    remaining = core.get("remaining", "?")
    limit = core.get("limit", "?")
    auth_label = "authed" if token else "unauth"
    rl = f"{remaining}/{limit} core ({auth_label})"
    return HealthResult(
        "GitHub API", ok=True, latency_ms=latency, detail="ok", rate_limit=rl
    )


def _docker_authed() -> bool:
    """True iff ``~/.docker/config.json`` has any saved auth entries."""
    cfg = Path.home() / ".docker" / "config.json"
    if not cfg.is_file():
        return False
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    auths = data.get("auths") if isinstance(data, dict) else None
    if not isinstance(auths, dict):
        return False
    # An entry counts only if it actually has an auth/identitytoken value.
    return any(
        isinstance(v, dict) and (v.get("auth") or v.get("identitytoken"))
        for v in auths.values()
    )


def _probe_docker_registry(name: str, ref: str, anon_note: str) -> HealthResult:
    """Generic ``docker manifest inspect`` probe for a registry."""
    # Uses run_with_timeout, which unifies FileNotFoundError ("docker CLI
    # not on PATH") and TimeoutExpired ("timeout after Ns") into
    # RunOutcome; the canonical "command_not_found:" stderr prefix
    # distinguishes the missing-binary case from a timeout.
    from cve_env.utils.run import run_with_timeout

    start = time.monotonic()
    outcome = run_with_timeout(
        ["docker", "manifest", "inspect", ref],
        timeout=_DOCKER_TIMEOUT_S,
    )
    latency = (time.monotonic() - start) * 1000.0
    if outcome.returncode is None and outcome.stderr.startswith("command_not_found:"):
        return HealthResult(
            name,
            ok=False,
            latency_ms=latency,
            detail="docker CLI not on PATH",
        )
    if outcome.timed_out:
        return HealthResult(
            name,
            ok=False,
            latency_ms=latency,
            detail=f"timeout after {_DOCKER_TIMEOUT_S}s",
        )
    if outcome.returncode != 0:
        stderr = (outcome.stderr or "").strip()[:80]
        rl_note = ""
        sl = stderr.lower()
        if "toomanyrequests" in sl or "rate limit" in sl:
            rl_note = "rate-limited"
        return HealthResult(
            name, ok=False, latency_ms=latency, detail=stderr, rate_limit=rl_note
        )
    return HealthResult(
        name, ok=True, latency_ms=latency, detail="ok", rate_limit=anon_note
    )


def probe_docker_hub() -> HealthResult:
    if _docker_authed():
        return _probe_docker_registry(
            "Docker Hub", "alpine:3.19", "authed (200 pulls/6h or unlimited paid)"
        )
    return _probe_docker_registry("Docker Hub", "alpine:3.19", "anon (100 pulls/6h)")


def probe_quay() -> HealthResult:
    return _probe_docker_registry(
        "quay.io", "quay.io/centos/centos:stream9", "anon (unmetered for public)"
    )


def probe_ghcr() -> HealthResult:
    return _probe_docker_registry(
        "ghcr.io", "ghcr.io/linuxserver/nginx:latest", "anon (PAT raises limit)"
    )


def probe_mcr() -> HealthResult:
    return _probe_docker_registry(
        "mcr.microsoft.com",
        "mcr.microsoft.com/dotnet/runtime:8.0",
        "anon (no auth needed)",
    )


# Order matters: DNS first (everything else fails if DNS fails), then
# critical-path services, then nice-to-haves.
PROBES = (
    probe_dns,
    probe_nvd,
    probe_osv,
    probe_github,
    probe_docker_hub,
    probe_quay,
    probe_ghcr,
    probe_mcr,
)

# Services that are CRITICAL — bench can't run productively without them.
# OSV matters because it's the NVD fallback. Either of NVD/OSV being up is
# enough for grounding a CVE; but if BOTH fail, the bench will give_up
# immediately. We track them individually so the doctor can show which is healthy.
CRITICAL_NAMES = frozenset({"DNS resolution", "GitHub API", "Docker Hub"})


def run_all() -> list[HealthResult]:
    """Run every probe sequentially. Returns results in display order."""
    return [probe() for probe in PROBES]


def render_table(results: list[HealthResult]) -> str:
    """Format results as a fixed-width table for terminal display."""
    lines = ["", "Service health probes:", ""]
    for r in results:
        lines.append(r.as_row())
    lines.append("")
    failing_critical = [
        r.name for r in results if not r.ok and r.name in CRITICAL_NAMES
    ]
    nvd_ok = any(r.ok and r.name == "NVD API" for r in results)
    osv_ok = any(r.ok and r.name == "OSV API" for r in results)
    if failing_critical:
        lines.append(
            f"⚠ {len(failing_critical)} CRITICAL service(s) unhealthy: "
            f"{', '.join(failing_critical)}. Bench will likely fail."
        )
    if not nvd_ok and not osv_ok:
        lines.append(
            "⚠ Both NVD and OSV are unhealthy. Agent has no working CVE-grounding source."
        )
    elif not nvd_ok and osv_ok:
        lines.append(
            "ⓘ NVD throttled/unavailable — OSV fallback will pick up the slack."
        )
    if not failing_critical and nvd_ok and all(r.ok for r in results):
        lines.append("All probes passed.")
    elif not failing_critical:
        lines.append(
            "Non-critical services degraded; bench can still run with "
            "reduced data sources."
        )
    return "\n".join(lines)


def has_critical_failure(results: list[HealthResult]) -> bool:
    return any(not r.ok and r.name in CRITICAL_NAMES for r in results)
