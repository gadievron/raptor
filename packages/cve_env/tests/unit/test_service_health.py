"""Unit tests for :mod:`cve_env.infra.service_health` (Phase 18.1)."""

from __future__ import annotations

import socket
from typing import Any
from unittest.mock import MagicMock, patch

import requests

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


@patch("cve_env.infra.service_health.requests.get")
def test_probe_nvd_anonymous_tier(mock_get: Any, monkeypatch: Any) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    mock_get.return_value = MagicMock(status_code=200, headers={})
    r = probe_nvd()
    assert r.ok is True
    assert "no API key" in r.rate_limit
    assert "5 req/30s" in r.rate_limit


@patch("cve_env.infra.service_health.requests.get")
def test_probe_nvd_with_api_key(mock_get: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("NVD_API_KEY", "test-key-abc")
    mock_get.return_value = MagicMock(status_code=200, headers={})
    r = probe_nvd()
    assert r.ok is True
    assert "with API key" in r.rate_limit
    # And the apiKey header was sent.
    sent_headers = mock_get.call_args.kwargs.get("headers", {})
    assert sent_headers.get("apiKey") == "test-key-abc"


@patch("cve_env.infra.service_health.requests.get")
def test_probe_nvd_429_surfaced(mock_get: Any, monkeypatch: Any) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    mock_get.return_value = MagicMock(status_code=429, headers={"Retry-After": "30"})
    r = probe_nvd()
    assert r.ok is False
    assert "429" in r.detail


@patch("cve_env.infra.service_health.requests.get")
def test_probe_nvd_network_error(mock_get: Any) -> None:
    mock_get.side_effect = requests.ConnectionError("dns broken")
    r = probe_nvd()
    assert r.ok is False
    assert "network" in r.detail


# -- OSV probe ------------------------------------------------------------


@patch("cve_env.infra.service_health.requests.get")
def test_probe_osv_ok(mock_get: Any) -> None:
    mock_get.return_value = MagicMock(status_code=200)
    r = probe_osv()
    assert r.ok is True


@patch("cve_env.infra.service_health.requests.get")
def test_probe_osv_failure(mock_get: Any) -> None:
    mock_get.return_value = MagicMock(status_code=500)
    r = probe_osv()
    assert r.ok is False
    assert "500" in r.detail


# -- GitHub probe ---------------------------------------------------------


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.infra.service_health.requests.get")
def test_probe_github_with_gh_cli_token(
    mock_get: Any,
    mock_run: Any,
    monkeypatch: Any,
) -> None:
    """When GITHUB_TOKEN unset but `gh auth token` returns a token, that token
    should be sent and the higher rate-limit reported."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    mock_run.return_value = MagicMock(returncode=0, stdout="gho_test_token\n")
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {
        "resources": {"core": {"limit": 5000, "remaining": 4998}}
    }
    mock_get.return_value = mock_resp
    r = probe_github()
    assert r.ok is True
    assert "4998/5000" in r.rate_limit
    assert "authed" in r.rate_limit
    sent_headers = mock_get.call_args.kwargs.get("headers", {})
    assert sent_headers.get("Authorization") == "Bearer gho_test_token"


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.infra.service_health.requests.get")
def test_probe_github_anon_when_no_token(
    mock_get: Any,
    mock_run: Any,
    monkeypatch: Any,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not logged in")
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {
        "resources": {"core": {"limit": 60, "remaining": 59}}
    }
    mock_get.return_value = mock_resp
    r = probe_github()
    assert r.ok is True
    assert "59/60" in r.rate_limit
    assert "unauth" in r.rate_limit


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.infra.service_health.requests.get")
def test_probe_github_env_token_takes_precedence(
    mock_get: Any,
    mock_run: Any,
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_explicit_env")
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {
        "resources": {"core": {"limit": 5000, "remaining": 4500}}
    }
    mock_get.return_value = mock_resp
    r = probe_github()
    sent_headers = mock_get.call_args.kwargs.get("headers", {})
    assert sent_headers.get("Authorization") == "Bearer ghp_explicit_env"
    # When env var is set, gh CLI should NOT be invoked.
    mock_run.assert_not_called()
    assert r.ok is True


# -- Docker Hub probe ----------------------------------------------------


@patch("cve_env.infra.service_health._docker_authed")
@patch("cve_env.utils.run.subprocess.run")
def test_probe_docker_hub_anonymous(
    mock_run: Any,
    mock_auth: Any,
) -> None:
    mock_auth.return_value = False
    mock_run.return_value = MagicMock(returncode=0, stdout="manifest", stderr="")
    r = probe_docker_hub()
    assert r.ok is True
    assert "anon" in r.rate_limit
    assert "100 pulls" in r.rate_limit


@patch("cve_env.infra.service_health._docker_authed")
@patch("cve_env.utils.run.subprocess.run")
def test_probe_docker_hub_authed(
    mock_run: Any,
    mock_auth: Any,
) -> None:
    mock_auth.return_value = True
    mock_run.return_value = MagicMock(returncode=0, stdout="manifest", stderr="")
    r = probe_docker_hub()
    assert r.ok is True
    assert "authed" in r.rate_limit


@patch("cve_env.infra.service_health._docker_authed")
@patch("cve_env.utils.run.subprocess.run")
def test_probe_docker_hub_rate_limited(
    mock_run: Any,
    mock_auth: Any,
) -> None:
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


# ─── BUG-004b: env-based proxy injection regression lock ────────────────


@patch("cve_env.infra.service_health.requests.get")
def test_BUG004b_probe_passes_empty_proxies_kwarg(
    mock_get: Any, monkeypatch: Any
) -> None:
    """BUG-004b lock: service_health._http_get (line 67) must pass
    proxies={"http":"","https":""} to requests.get to defeat env-based
    proxy injection. Pattern matches the other 5 BUG-004b sites; tests in
    test_verify.py + test_web_fetch.py + test_source_build.py cover those.
    """
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    mock_get.return_value = MagicMock(status_code=200, headers={})
    probe_nvd()  # exercises service_health._http_get → requests.get
    assert mock_get.call_count == 1
    _args, kwargs = mock_get.call_args
    assert kwargs.get("proxies") == {"http": "", "https": ""}, (
        f"BUG-004b regression: service_health did not pass "
        f"proxies={{'http':'','https':''}}; got proxies={kwargs.get('proxies')!r}"
    )
