"""Unit tests for :mod:`cve_env.infra.service_health` (Phase 18.1).

HTTP probes are exercised against a scripted :mod:`core.http` client
double patched at ``service_health._client`` — the transport moved off
``requests`` in the citizenship pass (design record §4.7), taking the
operator-proxy inversion with it (see the last test).
"""

from __future__ import annotations

import json
import socket
from typing import Any
from unittest.mock import MagicMock, patch

from core.http import HttpError, Response

from cve_env.infra.service_health import (
    CRITICAL_NAMES,
    HealthResult,
    has_critical_failure,
    probe_dns,
    probe_docker_hub,
    probe_github,
    probe_nvd,
    probe_osv,
    render_table,
)


def _resp(status=200, body=b"{}", url="https://probe.example/x"):
    return Response(status=status, headers={"content-type": "application/json"},
                    body=body, url=url)


class _FakeHttp:
    """Scripted core.http client double: one queued Response or
    exception per ``request`` call; records call kwargs."""

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    def request(self, method, url, **kw):
        self.calls.append({"method": method, "url": url, **kw})
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _with_http(script):
    fake = _FakeHttp(script)
    return fake, patch("cve_env.infra.service_health._client", lambda: fake)


def test_health_result_as_row_ok() -> None:
    r = HealthResult("Foo", ok=True, latency_ms=42.0, detail="ok", rate_limit="60/h")
    row = r.as_row()
    assert "✓" in row
    assert "Foo" in row
    assert "42 ms" in row
    assert "ok" in row
    assert "60/h" in row


def test_health_result_as_row_failed() -> None:
    r = HealthResult("Bar", ok=False, latency_ms=5000.0, detail="http 503")
    row = r.as_row()
    assert "✗" in row
    assert "http 503" in row


# -- DNS canary -----------------------------------------------------------


@patch("cve_env.infra.service_health.socket.gethostbyname")
def test_probe_dns_ok(mock_resolve: Any) -> None:
    mock_resolve.return_value = "1.2.3.4"
    r = probe_dns()
    assert r.ok is True
    assert r.name == "DNS resolution"


@patch("cve_env.infra.service_health.socket.gethostbyname")
def test_probe_dns_fails(mock_resolve: Any) -> None:
    mock_resolve.side_effect = socket.gaierror("dns offline")
    r = probe_dns()
    assert r.ok is False
    assert "resolve failure" in r.detail


# -- NVD probe ------------------------------------------------------------


def test_probe_nvd_anonymous_tier(monkeypatch: Any) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    fake, ctx = _with_http([_resp(200)])
    with ctx:
        r = probe_nvd()
    assert r.ok is True
    assert "no API key" in r.rate_limit
    assert "5 req/30s" in r.rate_limit


def test_probe_nvd_with_api_key(monkeypatch: Any) -> None:
    monkeypatch.setenv("NVD_API_KEY", "test-key-abc")
    fake, ctx = _with_http([_resp(200)])
    with ctx:
        r = probe_nvd()
    assert r.ok is True
    assert "with API key" in r.rate_limit
    # And the apiKey header was sent.
    assert fake.calls[0]["headers"].get("apiKey") == "test-key-abc"


def test_probe_nvd_429_surfaced(monkeypatch: Any) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    _fake, ctx = _with_http([_resp(429)])
    with ctx:
        r = probe_nvd()
    assert r.ok is False
    assert "429" in r.detail


def test_probe_nvd_network_error() -> None:
    _fake, ctx = _with_http([HttpError("dns broken")])
    with ctx:
        r = probe_nvd()
    assert r.ok is False
    assert "network" in r.detail


def test_probe_single_shot_no_retries() -> None:
    """A probe measures the service as it is right now — the client's
    transient-retry machinery must be disabled."""
    fake, ctx = _with_http([_resp(200)])
    with ctx:
        probe_osv()
    assert fake.calls[0]["retries"] == 0
    assert fake.calls[0]["raise_on_status"] is False


# -- OSV probe ------------------------------------------------------------


def test_probe_osv_ok() -> None:
    _fake, ctx = _with_http([_resp(200)])
    with ctx:
        r = probe_osv()
    assert r.ok is True


def test_probe_osv_failure() -> None:
    _fake, ctx = _with_http([_resp(500)])
    with ctx:
        r = probe_osv()
    assert r.ok is False
    assert "500" in r.detail


# -- GitHub probe ---------------------------------------------------------


def _github_resp(limit: int, remaining: int) -> Response:
    body = json.dumps(
        {"resources": {"core": {"limit": limit, "remaining": remaining}}}
    ).encode()
    return _resp(200, body=body)


@patch("core.container.proc.subprocess.run")
def test_probe_github_with_gh_cli_token(mock_run: Any, monkeypatch: Any) -> None:
    """When GITHUB_TOKEN unset but `gh auth token` returns a token, that token
    should be sent and the higher rate-limit reported."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    mock_run.return_value = MagicMock(returncode=0, stdout="gho_test_token\n")
    fake, ctx = _with_http([_github_resp(5000, 4998)])
    with ctx:
        r = probe_github()
    assert r.ok is True
    assert "4998/5000" in r.rate_limit
    assert "authed" in r.rate_limit
    assert fake.calls[0]["headers"].get("Authorization") == "Bearer gho_test_token"


@patch("core.container.proc.subprocess.run")
def test_probe_github_anon_when_no_token(mock_run: Any, monkeypatch: Any) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not logged in")
    fake, ctx = _with_http([_github_resp(60, 59)])
    with ctx:
        r = probe_github()
    assert r.ok is True
    assert "59/60" in r.rate_limit
    assert "unauth" in r.rate_limit


@patch("core.container.proc.subprocess.run")
def test_probe_github_env_token_takes_precedence(
    mock_run: Any, monkeypatch: Any
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_explicit_env")
    fake, ctx = _with_http([_github_resp(5000, 4500)])
    with ctx:
        r = probe_github()
    assert fake.calls[0]["headers"].get("Authorization") == "Bearer ghp_explicit_env"
    # When env var is set, gh CLI should NOT be invoked.
    mock_run.assert_not_called()
    assert r.ok is True


@patch("core.container.proc.subprocess.run")
def test_probe_github_non_json_body_is_ok(mock_run: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    _fake, ctx = _with_http([_resp(200, body=b"<html>not json</html>")])
    with ctx:
        r = probe_github()
    assert r.ok is True
    assert "non-JSON" in r.detail


# -- Docker Hub probe ----------------------------------------------------


@patch("cve_env.infra.service_health._docker_authed")
@patch("core.container.proc.subprocess.run")
def test_probe_docker_hub_anonymous(mock_run: Any, mock_auth: Any) -> None:
    mock_auth.return_value = False
    mock_run.return_value = MagicMock(returncode=0, stdout="manifest", stderr="")
    r = probe_docker_hub()
    assert r.ok is True
    assert "anon" in r.rate_limit
    assert "100 pulls" in r.rate_limit


@patch("cve_env.infra.service_health._docker_authed")
@patch("core.container.proc.subprocess.run")
def test_probe_docker_hub_authed(mock_run: Any, mock_auth: Any) -> None:
    mock_auth.return_value = True
    mock_run.return_value = MagicMock(returncode=0, stdout="manifest", stderr="")
    r = probe_docker_hub()
    assert r.ok is True
    assert "authed" in r.rate_limit


@patch("cve_env.infra.service_health._docker_authed")
@patch("core.container.proc.subprocess.run")
def test_probe_docker_hub_rate_limited(mock_run: Any, mock_auth: Any) -> None:
    mock_auth.return_value = False
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="toomanyrequests: You have reached your unauthenticated pull rate limit",
    )
    r = probe_docker_hub()
    assert r.ok is False
    assert r.rate_limit == "rate-limited"


# -- aggregate render + critical-failure helpers --------------------------


def test_render_table_all_ok() -> None:
    results = [
        HealthResult("DNS resolution", ok=True, latency_ms=10),
        HealthResult("NVD API", ok=True, latency_ms=200, rate_limit="50/30s"),
        HealthResult("OSV API", ok=True, latency_ms=300),
        HealthResult("GitHub API", ok=True, latency_ms=80, rate_limit="5000/h"),
        HealthResult("Docker Hub", ok=True, latency_ms=400, rate_limit="anon"),
    ]
    table = render_table(results)
    assert "All probes passed" in table


def test_render_table_critical_failure() -> None:
    results = [
        HealthResult("DNS resolution", ok=False, latency_ms=10, detail="offline"),
        HealthResult("NVD API", ok=True, latency_ms=200),
    ]
    table = render_table(results)
    assert "CRITICAL service(s) unhealthy" in table


def test_render_table_nvd_down_osv_up_says_fallback_will_pick_up() -> None:
    """Phase 17.2 fallback: if NVD is down but OSV is up, that's fine."""
    results = [
        HealthResult("DNS resolution", ok=True, latency_ms=10),
        HealthResult("NVD API", ok=False, latency_ms=200, detail="429"),
        HealthResult("OSV API", ok=True, latency_ms=300),
        HealthResult("GitHub API", ok=True, latency_ms=80),
        HealthResult("Docker Hub", ok=True, latency_ms=400),
    ]
    table = render_table(results)
    assert "OSV fallback" in table


def test_render_table_both_nvd_and_osv_down_warns() -> None:
    results = [
        HealthResult("DNS resolution", ok=True, latency_ms=10),
        HealthResult("NVD API", ok=False, latency_ms=200, detail="429"),
        HealthResult("OSV API", ok=False, latency_ms=200, detail="500"),
        HealthResult("GitHub API", ok=True, latency_ms=80),
        HealthResult("Docker Hub", ok=True, latency_ms=400),
    ]
    table = render_table(results)
    assert "no working CVE-grounding source" in table


def test_has_critical_failure_true_when_dns_fails() -> None:
    results = [
        HealthResult("DNS resolution", ok=False, latency_ms=10),
        HealthResult("NVD API", ok=True, latency_ms=200),
    ]
    assert has_critical_failure(results) is True


def test_has_critical_failure_false_when_only_noncritical_fails() -> None:
    """NVD failure alone is NOT critical (OSV fallback covers it)."""
    results = [
        HealthResult("DNS resolution", ok=True, latency_ms=10),
        HealthResult("NVD API", ok=False, latency_ms=200, detail="429"),
        HealthResult("GitHub API", ok=True, latency_ms=80),
        HealthResult("Docker Hub", ok=True, latency_ms=400),
    ]
    assert has_critical_failure(results) is False


def test_critical_names_set_includes_dns_github_dockerhub() -> None:
    """Sanity: the CRITICAL_NAMES set covers what's actually critical."""
    assert "DNS resolution" in CRITICAL_NAMES
    assert "GitHub API" in CRITICAL_NAMES
    assert "Docker Hub" in CRITICAL_NAMES
    # NVD is intentionally NOT critical because OSV is the fallback.
    assert "NVD API" not in CRITICAL_NAMES


# ─── transport delegation (BUG-004b successor) ───────────────────────────


def test_operator_proxy_honoured_via_core_http() -> None:
    """Design inversion vs the requests-era BUG-004b lock: probes ride
    core.http's UrllibClient, which snapshots the OPERATOR's proxy env
    at construction — the doctor must measure the same network path the
    real fetches use, so proxy-only hosts report honestly instead of
    all-red. Child-process proxy hygiene is safe_subprocess_env's job."""
    import cve_env.infra.service_health as sh
    from core.http.urllib_backend import UrllibClient

    sh._client_singleton = None
    try:
        assert isinstance(sh._client(), UrllibClient)
    finally:
        sh._client_singleton = None
