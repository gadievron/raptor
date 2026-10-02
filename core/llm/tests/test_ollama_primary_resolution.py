"""Tests for Ollama models.json primary-selection eligibility.

A configured local (Ollama) model must be able to become the default
primary from ``~/.config/raptor/models.json``.  Before the Step 2c hook
(``_config_ollama_primary``), the thinking-model scorer only knew cloud
models and the env builder ignored the file, so a role-less Ollama entry
could never be selected as primary — the run silently fell through to raw
``/api/tags`` autodetect and picked whatever model the probe returned
first.

These tests pin ``RAPTOR_CONFIG`` at a temp file and stub the Ollama
probe to return a DIFFERENT model list than the file, so a passing
assertion proves the FILE drove selection, not autodetect.
"""

from __future__ import annotations

import json

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """Hermetic selection env: no cloud provider keys, cold caches, no
    live Claude Code probe, and a stubbed availability object so
    fallback resolution doesn't short-circuit on "no external LLM"."""
    for var in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "MISTRAL_API_KEY",
        "AWS_BEARER_TOKEN_BEDROCK",
        "AWS_PROFILE",
        "RAPTOR_CONFIG",
    ):
        monkeypatch.delenv(var, raising=False)

    import core.llm.config as cfg
    import core.llm.detection as det

    det._cached_llm_availability = None
    cfg._cached_thinking_model = None
    cfg._thinking_model_checked = False
    monkeypatch.setattr(cfg, "_operator_primary_override", None)
    # External LLM is "available" so _get_default_fallback_models and the
    # availability gates don't bail; the thinking-model scorer stays live
    # (we want to prove cloud still wins when present).
    monkeypatch.setattr(
        cfg, "detect_llm_availability",
        lambda: type("A", (), {"external_llm": True})(),
    )
    # No live `claude` binary → claudecode never resolves as a competitor.
    monkeypatch.setattr("shutil.which", lambda _bin: None)
    yield
    det._cached_llm_availability = None
    cfg._cached_thinking_model = None
    cfg._thinking_model_checked = False


def _write_config(tmp_path, monkeypatch, models):
    cfg_path = tmp_path / "models.json"
    cfg_path.write_text(json.dumps({"models": models}))
    monkeypatch.setenv("RAPTOR_CONFIG", str(cfg_path))
    return cfg_path


def _stub_autodetect(monkeypatch, names):
    """Make the Ollama /api/tags probe return ``names`` — distinct from
    the configured model so a match on the configured name proves the
    file, not the probe, drove selection."""
    import core.llm.config as cfg
    monkeypatch.setattr(cfg, "_get_available_ollama_models", lambda: list(names))


class TestOllamaConfigPrimary:
    def test_roleless_ollama_entry_becomes_primary(self, tmp_path, monkeypatch):
        """A role-less Ollama entry wins over whatever autodetect would
        have returned, and its max_context/max_output are preserved."""
        _write_config(tmp_path, monkeypatch, [
            {
                "provider": "ollama",
                "model": "local-primary",
                "max_context": 60000,
                "max_output": 8192,
            },
        ])
        # Autodetect would otherwise return a DIFFERENT model first.
        _stub_autodetect(monkeypatch, ["local-big:latest"])

        import core.llm.config as cfg
        picked = cfg._get_default_primary_model()

        assert picked is not None
        assert picked.provider == "ollama"
        assert picked.model_name == "local-primary"
        assert picked.max_context == 60000
        assert picked.max_tokens == 8192

    def test_first_roleless_ollama_entry_wins(self, tmp_path, monkeypatch):
        """File order decides: the FIRST eligible Ollama entry is primary,
        later eligible entries are not."""
        _write_config(tmp_path, monkeypatch, [
            {"provider": "ollama", "model": "local-primary"},
            {"provider": "ollama", "model": "local-coder"},
        ])
        _stub_autodetect(monkeypatch, ["something-else:latest"])

        import core.llm.config as cfg
        picked = cfg._get_default_primary_model()

        assert picked is not None
        assert picked.model_name == "local-primary"

    def test_ollama_auxiliary_role_not_primary(self, tmp_path, monkeypatch):
        """An Ollama entry with an auxiliary role (judge) is NOT selected
        as primary — it falls through to autodetect."""
        _write_config(tmp_path, monkeypatch, [
            {"provider": "ollama", "model": "local-big", "role": "judge"},
        ])
        _stub_autodetect(monkeypatch, ["autodetected-model:latest"])

        import core.llm.config as cfg
        picked = cfg._get_default_primary_model()

        # Step 2c skipped the judge entry; Step 3 autodetect ran instead.
        assert picked is not None
        assert picked.model_name == "autodetected-model:latest"

    def test_ollama_analysis_role_is_primary(self, tmp_path, monkeypatch):
        """An explicit analysis/code role is primary-eligible (matches the
        Bedrock hook's eligibility set)."""
        _write_config(tmp_path, monkeypatch, [
            {"provider": "ollama", "model": "local-primary", "role": "analysis"},
        ])
        _stub_autodetect(monkeypatch, ["other:latest"])

        import core.llm.config as cfg
        picked = cfg._get_default_primary_model()

        assert picked is not None
        assert picked.model_name == "local-primary"

    def test_cloud_thinking_model_still_wins_over_ollama(self, tmp_path, monkeypatch):
        """Step 2 (cloud thinking model) precedes Step 2c: a matching cloud
        entry still beats a role-less Ollama entry."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        _write_config(tmp_path, monkeypatch, [
            {"provider": "anthropic", "model": "claude-opus-4-6"},
            {"provider": "ollama", "model": "local-primary"},
        ])
        _stub_autodetect(monkeypatch, ["local-primary:latest"])

        import core.llm.config as cfg
        picked = cfg._get_default_primary_model()

        assert picked is not None
        assert picked.provider == "anthropic"

    def test_offline_skips_ollama_primary(self, tmp_path, monkeypatch):
        """offline=True skips Step 2c (Ollama is a network-probing provider),
        matching how Steps 1/3 skip it."""
        _write_config(tmp_path, monkeypatch, [
            {"provider": "ollama", "model": "local-primary"},
        ])
        _stub_autodetect(monkeypatch, ["local-primary:latest"])

        import core.llm.config as cfg
        picked = cfg._get_default_primary_model(offline=True)

        # No cloud keys, Ollama skipped when offline → nothing resolves.
        assert picked is None
