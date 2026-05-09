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
    """Non-LLM API keys (GitHub, NVD) are still tracked here.
    LLM-provider env vars moved out of ``api_key_status`` after
    cve-diff went model-agnostic — they're rendered by
    ``llm_auth_status`` which iterates over the central
    ``RaptorConfig.LLM_API_KEY_VARS`` list."""
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    keys = {spec.name: present for spec, present in api_status.api_key_status()}
    assert keys["GitHub"] is True
    assert keys["NVD"] is False
    # Anthropic / OpenAI / etc. are no longer tracked here:
    assert "Anthropic" not in keys


def test_llm_auth_status_reflects_central_env_var_list(monkeypatch) -> None:
    """``llm_auth_status`` reads the LLM-provider env-var list from
    ``RaptorConfig.LLM_API_KEY_VARS`` (single source of truth) — no
    cve-diff-local enumeration. Result is a *count* of configured
    vars, not their names — see ``llm_auth_status`` docstring for
    the CodeQL-false-positive rationale."""
    from core.config import RaptorConfig
    for var in RaptorConfig.LLM_API_KEY_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)

    monkeypatch.setenv("GEMINI_API_KEY", "g")
    monkeypatch.setenv("MISTRAL_API_KEY", "m")
    _, n_configured, via_dispatcher = api_status.llm_auth_status()
    assert n_configured == 2
    assert via_dispatcher is False

    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/fake.sock")
    _, _, via_dispatcher = api_status.llm_auth_status()
    assert via_dispatcher is True


def test_banner_does_not_leak_provider_env_var_names(monkeypatch) -> None:
    """The banner must not name specific LLM-provider env vars.
    CodeQL flags ``LLM_API_KEY_VARS`` strings flowing into print
    as a clear-text-credential leak (false positive — the strings
    are env-var *names*, not values), and the count-only design is
    cheaper than arguing with the heuristic. Pin so a future
    "helpful" PR doesn't put them back into the output."""
    from core.config import RaptorConfig
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    banner = api_status.render_startup_banner()
    # No provider env-var name appears verbatim:
    for var in RaptorConfig.LLM_API_KEY_VARS:
        assert var not in banner, (
            f"banner leaks provider env-var name {var!r} — "
            f"CodeQL will flag this as clear-text credential "
            f"logging. Use the count-only output."
        )


def test_startup_banner_shows_set_and_missing(monkeypatch) -> None:
    """LLM auth is rendered in its own ``LLM auth:`` section as a
    count of configured providers (see ``llm_auth_status``).
    GitHub/NVD render with their full names as before."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)

    banner = api_status.render_startup_banner()
    assert "API keys:" in banner
    # LLM auth section present with a count, no specific env var
    # name (CodeQL-false-positive defuse):
    assert "LLM auth:" in banner
    assert "1 LLM provider env var" in banner
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
