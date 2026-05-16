"""Tests for cve_diff/infra/service_health.py — probe formatting and orchestration."""
from __future__ import annotations

from cve_diff.infra import service_health
from cve_diff.infra.service_health import (
    HealthResult,
    has_critical_failure,
    render_table,
)


def test_health_result_row_renders_status_and_latency() -> None:
    r = HealthResult(name="OSV API", ok=True, latency_ms=320.5, detail="ok")
    row = r.as_row()
    assert "✓" in row
    assert "OSV API" in row
    assert "321 ms" in row or "320 ms" in row  # rounding-tolerant


def test_health_result_row_renders_failure() -> None:
    r = HealthResult(name="GitHub API", ok=False, latency_ms=10000.0, detail="http 503")
    row = r.as_row()
    assert "✗" in row
    assert "GitHub API" in row
    assert "http 503" in row


def test_render_table_flags_critical_failures() -> None:
    results = [
        HealthResult("DNS resolution", True, 5),
        HealthResult("Anthropic API", False, 1000, detail="auth (401)"),
        HealthResult("OSV API", True, 200),
    ]
    table = render_table(results)
    assert "Anthropic API" in table
    assert "CRITICAL" in table
    assert "1 CRITICAL" in table


def test_render_table_when_all_healthy() -> None:
    results = [
        HealthResult("DNS resolution", True, 5),
        HealthResult("Anthropic API", True, 1000),
        HealthResult("OSV API", True, 200),
        HealthResult("GitHub API", True, 250),
    ]
    table = render_table(results)
    assert "All probes passed" in table
    assert "CRITICAL" not in table


def test_render_table_when_only_noncritical_degraded() -> None:
    results = [
        HealthResult("DNS resolution", True, 5),
        HealthResult("Anthropic API", True, 1000),
        HealthResult("OSV API", True, 200),
        HealthResult("GitHub API", True, 250),
        HealthResult("Debian tracker", False, 5000, detail="http 502"),
    ]
    table = render_table(results)
    assert "Debian tracker" in table
    assert "non-critical" in table
    assert "CRITICAL" not in table


def test_has_critical_failure_detects_critical_only() -> None:
    assert has_critical_failure([
        HealthResult("Anthropic API", False, 1000, detail="auth"),
        HealthResult("OSV API", True, 200),
    ]) is True
    assert has_critical_failure([
        HealthResult("Anthropic API", True, 1000),
        HealthResult("Debian tracker", False, 5000),  # non-critical
        HealthResult("OSV API", True, 200),
    ]) is False
    assert has_critical_failure([]) is False


def test_probe_anthropic_requires_api_key(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    r = service_health.probe_anthropic()
    assert r.ok is False
    assert "ANTHROPIC_API_KEY not set" in r.detail


def test_probes_tuple_lists_dns_first() -> None:
    """DNS must be probed first — every other probe depends on it."""
    assert service_health.PROBES[0] is service_health.probe_dns


# ---------------------------------------------------------------------------
# Network-mocked probe tests (close the 38% → 80% coverage gap).
#
# Each probe gets exercised on its success path, network-error path, and
# non-200 path. Anthropic gets the auth/rate-limit/overload branches too.
# The ``_client()`` factory on ``service_health`` is monkeypatched so we
# never touch the network from these tests.
# ---------------------------------------------------------------------------

import json as _json

from core.http import HttpError, Response


def _stub_client(monkeypatch, *, request_fn=None):
    """Install a fake ``_client()`` on ``service_health``.

    ``request_fn(method, url, **kwargs)`` → ``Response``. If it raises
    ``HttpError`` the probe's error path is exercised.
    """
    class _FakeClient:
        def request(self, method, url, **kw):
            return request_fn(method, url, **kw)

    monkeypatch.setattr(service_health, "_client", lambda: _FakeClient())


def _ok_response(status=200, body=b"", json_body=None, headers=None):
    if json_body is not None:
        body = _json.dumps(json_body).encode()
    return Response(status=status, headers=headers or {}, body=body, url="")


def _error_response(status, retry_after=None):
    raise HttpError(f"http {status}", status=status, retry_after=retry_after)


# --- _timed_get ---

def test_timed_get_success_returns_body_and_no_error(monkeypatch) -> None:
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200, json_body={"ok": True}))
    latency, body, status, err = service_health._timed_get("https://example.com")
    assert err == ""
    assert status == 200
    assert isinstance(body, dict) and body.get("ok") is True
    assert latency >= 0


def test_timed_get_network_failure_returns_error_and_no_body(monkeypatch) -> None:
    def boom(m, u, **kw):
        raise HttpError("connection refused")
    _stub_client(monkeypatch, request_fn=boom)
    latency, body, status, err = service_health._timed_get("https://example.com")
    assert body is None
    assert "connection refused" in err
    assert latency >= 0


# --- probe_anthropic (POST, with explicit branches) ---

def test_probe_anthropic_success_when_post_returns_200(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200))
    r = service_health.probe_anthropic()
    assert r.ok is True
    assert "ok" in r.detail


def test_probe_anthropic_marks_401_as_auth_failure(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-bad")
    def raise_401(m, u, **kw):
        raise HttpError("unauthorized", status=401)
    _stub_client(monkeypatch, request_fn=raise_401)
    r = service_health.probe_anthropic()
    assert r.ok is False
    assert "auth" in r.detail.lower()


def test_probe_anthropic_marks_529_as_overloaded(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    def raise_529(m, u, **kw):
        raise HttpError("overloaded", status=529)
    _stub_client(monkeypatch, request_fn=raise_529)
    r = service_health.probe_anthropic()
    assert r.ok is False
    assert "overloaded" in r.detail.lower()


def test_probe_anthropic_marks_429_as_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    def raise_429(m, u, **kw):
        raise HttpError("rate limited", status=429, retry_after=30)
    _stub_client(monkeypatch, request_fn=raise_429)
    r = service_health.probe_anthropic()
    assert r.ok is False
    assert "rate" in r.detail.lower()
    assert r.rate_limit == "30"


def test_probe_anthropic_marks_other_http_codes_as_failure(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    def raise_503(m, u, **kw):
        raise HttpError("http 503", status=503)
    _stub_client(monkeypatch, request_fn=raise_503)
    r = service_health.probe_anthropic()
    assert r.ok is False
    assert "503" in r.detail


def test_probe_anthropic_handles_network_failure(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    def boom(m, u, **kw):
        raise HttpError("dns fail")
    _stub_client(monkeypatch, request_fn=boom)
    r = service_health.probe_anthropic()
    assert r.ok is False
    assert "network" in r.detail


# --- probe_nvd ---

def test_probe_nvd_success_with_api_key_includes_authed_rate_hint(monkeypatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "abc")
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200))
    r = service_health.probe_nvd()
    assert r.ok is True
    assert "API key" in r.rate_limit


def test_probe_nvd_success_without_api_key_includes_unauthed_hint(monkeypatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200))
    r = service_health.probe_nvd()
    assert r.ok is True
    assert "no API key" in r.rate_limit


def test_probe_nvd_marks_non_200_as_failure(monkeypatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    def raise_503(m, u, **kw):
        raise HttpError("http 503", status=503)
    _stub_client(monkeypatch, request_fn=raise_503)
    r = service_health.probe_nvd()
    assert r.ok is False
    assert "503" in r.detail


def test_probe_nvd_marks_network_error(monkeypatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    def boom(m, u, **kw):
        raise HttpError("eof")
    _stub_client(monkeypatch, request_fn=boom)
    r = service_health.probe_nvd()
    assert r.ok is False
    assert "network" in r.detail


# --- probe_osv ---

def test_probe_osv_success(monkeypatch) -> None:
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200))
    r = service_health.probe_osv()
    assert r.ok is True


def test_probe_osv_marks_non_200_as_failure(monkeypatch) -> None:
    def raise_404(m, u, **kw):
        raise HttpError("http 404", status=404)
    _stub_client(monkeypatch, request_fn=raise_404)
    r = service_health.probe_osv()
    assert r.ok is False
    assert "404" in r.detail


def test_probe_osv_marks_network_error(monkeypatch) -> None:
    def boom(m, u, **kw):
        raise HttpError("timeout")
    _stub_client(monkeypatch, request_fn=boom)
    r = service_health.probe_osv()
    assert r.ok is False
    assert "network" in r.detail


# --- probe_github ---

def _patch_github_token(monkeypatch, *, gh_cli_returns: str | None = None,
                        env_token: str | None = None) -> None:
    if gh_cli_returns is None:
        def fake_run(*a, **kw):
            raise FileNotFoundError("gh not found")
        monkeypatch.setattr(service_health.subprocess, "run", fake_run)
    else:
        class _Result:
            stdout = gh_cli_returns
        monkeypatch.setattr(service_health.subprocess, "run",
                            lambda *a, **kw: _Result())
    if env_token is None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    else:
        monkeypatch.setenv("GITHUB_TOKEN", env_token)


def test_probe_github_success_with_gh_cli_token(monkeypatch) -> None:
    _patch_github_token(monkeypatch, gh_cli_returns="ghp_xxx\n")
    body = {"resources": {"core": {"remaining": 4500, "limit": 5000}}}
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200, json_body=body))
    r = service_health.probe_github()
    assert r.ok is True
    assert "4500/5000" in r.rate_limit
    assert "authed" in r.rate_limit


def test_probe_github_falls_back_to_env_when_gh_cli_missing(monkeypatch) -> None:
    _patch_github_token(monkeypatch, gh_cli_returns=None, env_token="ghp_env")
    body = {"resources": {"core": {"remaining": 60, "limit": 60}}}
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200, json_body=body))
    r = service_health.probe_github()
    assert r.ok is True


def test_probe_github_marks_unauth_when_no_token(monkeypatch) -> None:
    _patch_github_token(monkeypatch, gh_cli_returns="", env_token=None)
    body = {"resources": {"core": {"remaining": 30, "limit": 60}}}
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200, json_body=body))
    r = service_health.probe_github()
    assert r.ok is True
    assert "unauth" in r.rate_limit


def test_probe_github_marks_non_200_as_failure(monkeypatch) -> None:
    _patch_github_token(monkeypatch, gh_cli_returns="ghp_xxx\n")
    def raise_401(m, u, **kw):
        raise HttpError("http 401", status=401)
    _stub_client(monkeypatch, request_fn=raise_401)
    r = service_health.probe_github()
    assert r.ok is False
    assert "401" in r.detail


def test_probe_github_marks_network_error(monkeypatch) -> None:
    _patch_github_token(monkeypatch, gh_cli_returns="ghp_xxx\n")
    def boom(m, u, **kw):
        raise HttpError("connection reset")
    _stub_client(monkeypatch, request_fn=boom)
    r = service_health.probe_github()
    assert r.ok is False
    assert "network" in r.detail


def test_probe_github_handles_gh_cli_timeout(monkeypatch) -> None:
    def fake_run(*a, **kw):
        raise service_health.subprocess.TimeoutExpired(cmd="gh", timeout=2.0)
    monkeypatch.setattr(service_health.subprocess, "run", fake_run)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fallback")
    body = {"resources": {"core": {"remaining": 1000, "limit": 5000}}}
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200, json_body=body))
    r = service_health.probe_github()
    assert r.ok is True


# --- probe_debian / probe_ubuntu / probe_redhat (parametrized — same shape) ---

import pytest


@pytest.mark.parametrize("probe", [
    service_health.probe_debian,
    service_health.probe_ubuntu,
    service_health.probe_redhat,
])
def test_distro_probes_succeed_on_200(probe, monkeypatch) -> None:
    _stub_client(monkeypatch, request_fn=lambda m, u, **kw: _ok_response(200))
    r = probe()
    assert r.ok is True


@pytest.mark.parametrize("probe", [
    service_health.probe_debian,
    service_health.probe_ubuntu,
    service_health.probe_redhat,
])
def test_distro_probes_mark_non_200(probe, monkeypatch) -> None:
    def raise_503(m, u, **kw):
        raise HttpError("http 503", status=503)
    _stub_client(monkeypatch, request_fn=raise_503)
    r = probe()
    assert r.ok is False
    assert "503" in r.detail


@pytest.mark.parametrize("probe", [
    service_health.probe_debian,
    service_health.probe_ubuntu,
    service_health.probe_redhat,
])
def test_distro_probes_handle_network_failure(probe, monkeypatch) -> None:
    def boom(m, u, **kw):
        raise HttpError("connect refused")
    _stub_client(monkeypatch, request_fn=boom)
    r = probe()
    assert r.ok is False
    assert "network" in r.detail


# --- probe_dns ---

def test_probe_dns_success(monkeypatch) -> None:
    monkeypatch.setattr(service_health.socket, "gethostbyname",
                        lambda host: "1.2.3.4")
    r = service_health.probe_dns()
    assert r.ok is True


def test_probe_dns_failure_on_gaierror(monkeypatch) -> None:
    def fail(host):
        raise service_health.socket.gaierror(8, "nodename nor servname provided")
    monkeypatch.setattr(service_health.socket, "gethostbyname", fail)
    r = service_health.probe_dns()
    assert r.ok is False
    assert "resolve failure" in r.detail


# --- run_all (orchestration) ---

def test_run_all_returns_one_result_per_probe(monkeypatch) -> None:
    # Stub every probe to a deterministic OK so we can verify the order.
    for i, name in enumerate([
        "probe_dns", "probe_anthropic", "probe_osv", "probe_github",
        "probe_nvd", "probe_debian", "probe_ubuntu", "probe_redhat",
    ]):
        monkeypatch.setattr(
            service_health, name,
            lambda i=i, name=name: HealthResult(name, True, float(i), detail="ok"),
        )
    # Re-bind PROBES so it picks up the patched callables.
    monkeypatch.setattr(service_health, "PROBES", tuple(
        getattr(service_health, n) for n in [
            "probe_dns", "probe_anthropic", "probe_osv", "probe_github",
            "probe_nvd", "probe_debian", "probe_ubuntu", "probe_redhat",
        ]
    ))
    results = service_health.run_all()
    assert len(results) == 8
    assert results[0].name == "probe_dns"  # DNS first invariant
