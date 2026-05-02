"""Tests for cve_diff/infra/api_status.py — rate-limit + key tracking + cache stats."""
from __future__ import annotations

from cve_diff.infra import api_status


# --- cache hit/miss counters (Action C) ---

def test_record_cache_hit_increments_hits() -> None:
    api_status.reset_cache_stats()
    api_status.record_cache_hit("github_client.get_commit")
    api_status.record_cache_hit("github_client.get_commit")
    snap = api_status.cache_stats()
    assert snap == {"github_client.get_commit": {"hits": 2, "misses": 0}}


def test_record_cache_miss_increments_misses() -> None:
    api_status.reset_cache_stats()
    api_status.record_cache_miss("github_client.get_commit")
    snap = api_status.cache_stats()
    assert snap == {"github_client.get_commit": {"hits": 0, "misses": 1}}


def test_cache_stats_returns_deep_copy() -> None:
    """Mutation of returned dict must not affect internal state."""
    api_status.reset_cache_stats()
    api_status.record_cache_hit("x")
    snap = api_status.cache_stats()
    snap["x"]["hits"] = 999
    snap["new"] = {"hits": 5, "misses": 5}
    fresh = api_status.cache_stats()
    assert fresh["x"]["hits"] == 1
    assert "new" not in fresh


def test_reset_cache_stats_clears() -> None:
    api_status.record_cache_hit("y")
    api_status.reset_cache_stats()
    assert api_status.cache_stats() == {}


def test_render_cache_summary_empty_when_no_events() -> None:
    api_status.reset_cache_stats()
    assert api_status.render_cache_summary() == ""


def test_render_cache_summary_lists_per_function_with_ratio() -> None:
    api_status.reset_cache_stats()
    for _ in range(8):
        api_status.record_cache_hit("github_client.get_commit")
    api_status.record_cache_miss("github_client.get_commit")
    text = api_status.render_cache_summary()
    assert "Cache hits" in text
    assert "github_client.get_commit" in text
    assert "8" in text and "1" in text  # hits and misses
    # Ratio should appear (8/(8+1) = 88.9%)
    assert "88" in text or "89" in text


def test_record_cache_hit_and_miss_for_same_function() -> None:
    api_status.reset_cache_stats()
    api_status.record_cache_hit("f")
    api_status.record_cache_miss("f")
    api_status.record_cache_hit("f")
    snap = api_status.cache_stats()
    assert snap["f"] == {"hits": 2, "misses": 1}


def test_record_and_snapshot_per_status(monkeypatch) -> None:
    api_status.reset_rate_limit_events()
    api_status.record_rate_limit("github", 429)
    api_status.record_rate_limit("github", 429)
    api_status.record_rate_limit("github", 403)
    api_status.record_rate_limit("nvd", 429)

    snap = api_status.rate_limit_events()
    assert snap == {"github": {429: 2, 403: 1}, "nvd": {429: 1}}


def test_reset_clears_events() -> None:
    api_status.reset_rate_limit_events()
    api_status.record_rate_limit("github", 429)
    assert api_status.rate_limit_events() == {"github": {429: 1}}
    api_status.reset_rate_limit_events()
    assert api_status.rate_limit_events() == {}


def test_api_key_status_present_and_missing(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    keys = {spec.name: present for spec, present in api_status.api_key_status()}
    assert keys["Anthropic"] is True
    assert keys["GitHub"] is True
    assert keys["NVD"] is False


def test_startup_banner_shows_set_and_missing(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    banner = api_status.render_startup_banner()
    assert "API keys:" in banner
    assert "Anthropic" in banner and "set" in banner
    # NVD is optional → "—" tag, not "✗"
    assert "✗ GitHub" in banner
    assert "— NVD" in banner or "NVD       (NVD_API_KEY) NOT set" in banner


def test_rate_limit_summary_empty_when_no_events() -> None:
    api_status.reset_rate_limit_events()
    assert api_status.render_rate_limit_summary() == ""


def test_rate_limit_summary_lists_per_service_per_status() -> None:
    api_status.reset_rate_limit_events()
    api_status.record_rate_limit("github", 429)
    api_status.record_rate_limit("github", 429)
    api_status.record_rate_limit("nvd", 429)
    text = api_status.render_rate_limit_summary()
    assert "Rate-limit events" in text
    assert "github" in text and "nvd" in text
    assert "429: 2" in text
    assert "429: 1" in text
