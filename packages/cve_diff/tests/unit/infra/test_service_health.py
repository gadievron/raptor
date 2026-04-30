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
