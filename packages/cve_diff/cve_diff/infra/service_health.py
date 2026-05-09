"""Service health probes.

For each external service the pipeline depends on, a fast (≤ 10s)
probe that:
  - Confirms the service is reachable
  - Measures round-trip latency
  - Reads any rate-limit headers if the service exposes them
  - Returns a structured ``HealthResult`` for tabular display

Used by:
  - ``cve-diff health`` CLI command (manual run)
  - ``cve-diff bench --health-check`` pre-flight (optional)

Probes are deliberately small/cheap so they can run as a pre-flight
without delaying the main work. Each probe returns within ``timeout_s``
(default 10s) regardless of network state — a hung service surfaces as
``ok=False, detail="timeout"`` rather than blocking.
"""

from __future__ import annotations

import functools
import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass

from core.http import HttpError
from core.http.urllib_backend import UrllibClient


@dataclass(frozen=True, slots=True)
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


_TIMEOUT_S = 10


@functools.lru_cache(maxsize=1)
def _client() -> UrllibClient:
    return UrllibClient(user_agent="cve-diff-health/0.1")


def _timed_get(url: str, headers: dict | None = None) -> tuple[float, dict | bytes | None, int, str]:
    """Return (latency_ms, body_or_none, status, error). ``body`` is parsed JSON
    when the Content-Type looks like JSON, raw bytes otherwise."""
    start = time.monotonic()
    try:
        resp = _client().request(
            "GET", url, headers=headers, timeout=_TIMEOUT_S, retries=0,
        )
        elapsed = (time.monotonic() - start) * 1000.0
        try:
            body = resp.json()
        except Exception:
            body = resp.body
        return (elapsed, body, resp.status, "")
    except HttpError as exc:
        return ((time.monotonic() - start) * 1000.0, None, exc.status or 0, str(exc)[:120])


def _health_model() -> str:
    """Current default Anthropic model from the shared model registry."""
    try:
        from core.llm.model_data import PROVIDER_DEFAULT_MODELS
        return PROVIDER_DEFAULT_MODELS.get("anthropic", "claude-sonnet-4-6")
    except Exception:
        return "claude-sonnet-4-6"


def probe_anthropic() -> HealthResult:
    """Anthropic: 1-token message to prove reachability.

    Skips when no auth is available — accepts either ``ANTHROPIC_API_KEY``
    or the dispatcher route (``RAPTOR_LLM_SOCKET`` set) as a valid
    auth path, matching the resolution in :mod:`cve_diff.llm.auth`.
    Other providers (Gemini, OpenAI, ...) are not probed here yet —
    when an operator runs cve-diff with ``--model gemini-2.5-pro``
    and no Anthropic auth, the agent loop's resolver picks Gemini
    cleanly; this health probe is informational, not gating.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    via_dispatcher = bool(os.environ.get("RAPTOR_LLM_SOCKET"))
    if not api_key and not via_dispatcher:
        # Phrasing keeps the historical "ANTHROPIC_API_KEY not set"
        # substring so existing test fixtures + scripts grepping for
        # it still match; the credential-isolation hint is appended
        # so operators with a dispatcher know the alternative.
        return HealthResult(
            "Anthropic API", False, 0,
            detail=(
                "ANTHROPIC_API_KEY not set (or run with "
                "RAPTOR_LLM_SOCKET for credential-isolation dispatcher)"
            ),
        )
    if not api_key:
        # Dispatcher route — the API call would succeed via
        # dispatcher-injected headers, but we can't probe upstream
        # from this layer without setting up an httpx UDS client.
        # Surface as healthy + dispatcher-noted so operators see
        # auth is wired up.
        return HealthResult(
            "Anthropic API", True, 0,
            detail="auth via credential-isolation dispatcher",
        )
    start = time.monotonic()
    body = json.dumps({"model": _health_model(), "max_tokens": 1,
                       "messages": [{"role": "user", "content": "x"}]}).encode()
    try:
        resp = _client().request(
            "POST", "https://api.anthropic.com/v1/messages",
            body=body,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            timeout=_TIMEOUT_S, retries=0,
        )
    except HttpError as exc:
        latency = (time.monotonic() - start) * 1000.0
        status = exc.status or 0
        if status == 401:
            return HealthResult("Anthropic API", False, latency, detail="auth (401)")
        if status == 529:
            return HealthResult("Anthropic API", False, latency, detail="overloaded (529)")
        if status == 429:
            return HealthResult("Anthropic API", False, latency,
                                detail="rate-limited (429)",
                                rate_limit=str(exc.retry_after or ""))
        return HealthResult("Anthropic API", False, latency,
                            detail=f"network: {str(exc)[:80]}")
    latency = (time.monotonic() - start) * 1000.0
    return HealthResult("Anthropic API", True, latency, detail="ok (1-token ping)")


def probe_nvd() -> HealthResult:
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}
    latency, body, status, err = _timed_get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-5195",
        headers=headers,
    )
    if err:
        return HealthResult("NVD API", False, latency, detail=f"network: {err}")
    if status != 200:
        return HealthResult("NVD API", False, latency, detail=f"http {status}")
    rl = "with API key (50 req/30s)" if api_key else "no API key (5 req/30s — slow)"
    return HealthResult("NVD API", True, latency, detail="ok", rate_limit=rl)


def probe_osv() -> HealthResult:
    latency, body, status, err = _timed_get(
        "https://api.osv.dev/v1/vulns/CVE-2016-5195"
    )
    if err:
        return HealthResult("OSV API", False, latency, detail=f"network: {err}")
    if status != 200:
        return HealthResult("OSV API", False, latency, detail=f"http {status}")
    return HealthResult("OSV API", True, latency, detail="ok")


def probe_github() -> HealthResult:
    # `gh auth token` returns non-zero with an empty stdout when the user
    # isn't logged in (no exception raised). The previous code only fell
    # back to $GITHUB_TOKEN on exec failure (TimeoutExpired/FileNotFoundError),
    # so a logged-out gh would shadow a perfectly good env-var token and
    # the probe would report "(unauth)" despite credentials being present.
    # Fall back whenever gh's stdout is empty for any reason.
    token = ""
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True,
                             timeout=2.0)
        token = (out.stdout or "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    if not token:
        token = os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    latency, body, status, err = _timed_get(
        "https://api.github.com/rate_limit",
        headers=headers,
    )
    if err:
        return HealthResult("GitHub API", False, latency, detail=f"network: {err}")
    if status != 200:
        return HealthResult("GitHub API", False, latency, detail=f"http {status}")
    data = body if isinstance(body, dict) else {}
    core = (data.get("resources") or {}).get("core") or {}
    remaining = core.get("remaining", "?")
    limit = core.get("limit", "?")
    rl = f"{remaining}/{limit} core remaining" + (" (authed)" if token else " (unauth)")
    return HealthResult("GitHub API", True, latency, detail="ok", rate_limit=rl)


def probe_debian() -> HealthResult:
    latency, body, status, err = _timed_get(
        "https://security-tracker.debian.org/tracker/CVE-2016-5195",
    )
    if err:
        return HealthResult("Debian tracker", False, latency, detail=f"network: {err}")
    if status != 200:
        return HealthResult("Debian tracker", False, latency, detail=f"http {status}")
    return HealthResult("Debian tracker", True, latency, detail="ok")


def probe_ubuntu() -> HealthResult:
    latency, body, status, err = _timed_get(
        "https://ubuntu.com/security/cves.json?q=CVE-2016-5195",
    )
    if err:
        return HealthResult("Ubuntu tracker", False, latency, detail=f"network: {err}")
    if status != 200:
        return HealthResult("Ubuntu tracker", False, latency, detail=f"http {status}")
    return HealthResult("Ubuntu tracker", True, latency, detail="ok")


def probe_redhat() -> HealthResult:
    latency, body, status, err = _timed_get(
        "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2016-5195.json",
    )
    if err:
        return HealthResult("Red Hat tracker", False, latency, detail=f"network: {err}")
    if status != 200:
        return HealthResult("Red Hat tracker", False, latency, detail=f"http {status}")
    return HealthResult("Red Hat tracker", True, latency, detail="ok")


def probe_dns() -> HealthResult:
    """A canary for 'is the network up at all?'"""
    start = time.monotonic()
    try:
        socket.gethostbyname("api.osv.dev")
    except socket.gaierror as exc:
        return HealthResult("DNS resolution", False,
                            (time.monotonic() - start) * 1000.0,
                            detail=f"resolve failure: {exc}")
    return HealthResult("DNS resolution", True,
                        (time.monotonic() - start) * 1000.0,
                        detail="ok")


# Order matters: DNS first (everything else fails if DNS fails), then
# critical-path services (Anthropic, OSV, GitHub), then the
# nice-to-haves (NVD, distros).
PROBES = (
    probe_dns,
    probe_anthropic,
    probe_osv,
    probe_github,
    probe_nvd,
    probe_debian,
    probe_ubuntu,
    probe_redhat,
)

# Services that are CRITICAL — bench can't run productively without them.
CRITICAL_NAMES = frozenset({"DNS resolution", "Anthropic API", "OSV API", "GitHub API"})


def run_all() -> list[HealthResult]:
    """Run every probe sequentially. Returns results in display order."""
    return [probe() for probe in PROBES]


def render_table(results: list[HealthResult]) -> str:
    """Format results as a fixed-width table for terminal display."""
    lines = ["", "Service health probes:", ""]
    for r in results:
        lines.append(r.as_row())
    lines.append("")
    failing_critical = [r.name for r in results if not r.ok and r.name in CRITICAL_NAMES]
    if failing_critical:
        lines.append(
            f"⚠ {len(failing_critical)} CRITICAL service(s) unhealthy: "
            f"{', '.join(failing_critical)}. Bench will likely fail."
        )
    elif any(not r.ok for r in results):
        lines.append("Some non-critical services are degraded. Bench may run with reduced data sources.")
    else:
        lines.append("All probes passed.")
    return "\n".join(lines)


def has_critical_failure(results: list[HealthResult]) -> bool:
    return any(not r.ok and r.name in CRITICAL_NAMES for r in results)
