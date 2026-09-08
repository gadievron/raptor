"""Copilot CLI configuration and availability tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.llm import config as config_mod
from core.llm.config import (
    COPILOT_DEFAULT_MODEL,
    LLMConfig,
    ModelConfig,
    _get_default_primary_model,
    canonical_agent_cli_provider,
    filter_agent_cli_models,
    model_config_from_entry,
)


@pytest.fixture
def isolated_resolution(monkeypatch):
    for name in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "MISTRAL_API_KEY",
        "AWS_BEARER_TOKEN_BEDROCK",
        "RAPTOR_BEDROCK_MODEL",
        "RAPTOR_BEDROCK_PROFILE",
        "RAPTOR_LLM_SOCKET",
        "RAPTOR_AGENT_CLI",
        "RAPTOR_COPILOT_MODEL",
        "RAPTOR_COPILOT_MODEL_EXPLICIT",
        "RAPTOR_CC_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config_mod, "_operator_primary_override", None)
    monkeypatch.setattr(config_mod, "_get_best_thinking_model", lambda: None)
    monkeypatch.setattr(config_mod, "_config_bedrock_primary", lambda: None)
    monkeypatch.setattr(config_mod, "_get_available_ollama_models", list)
    return monkeypatch


def test_copilot_mode_selects_keyless_provider_before_claudecode(
    isolated_resolution,
) -> None:
    isolated_resolution.setenv("RAPTOR_AGENT_CLI", "copilot")
    isolated_resolution.setattr(
        "shutil.which",
        lambda name: f"/usr/bin/{name}"
        if name in ("copilot", "claude") else None,
    )

    config = _get_default_primary_model()

    assert config is not None
    assert config.provider == "copilotcli"
    assert config.model_name == COPILOT_DEFAULT_MODEL
    assert config.api_key is None


def test_copilot_binary_does_not_change_claude_mode(
    isolated_resolution,
) -> None:
    isolated_resolution.setenv("RAPTOR_AGENT_CLI", "claude")
    isolated_resolution.setattr(
        "shutil.which",
        lambda name: f"/usr/bin/{name}"
        if name in ("copilot", "claude") else None,
    )

    config = _get_default_primary_model()

    assert config is not None
    assert config.provider == "claudecode"


def test_copilot_model_env_overrides_default(isolated_resolution) -> None:
    isolated_resolution.setenv("RAPTOR_AGENT_CLI", "copilot")
    isolated_resolution.setenv(
        "RAPTOR_COPILOT_MODEL", "claude-fable-5.1",
    )
    isolated_resolution.setattr(
        "shutil.which",
        lambda name: "/usr/bin/copilot" if name == "copilot" else None,
    )

    config = _get_default_primary_model()

    assert config is not None
    assert config.provider == "copilotcli"
    assert config.model_name == "claude-fable-5.1"


def test_dotted_copilot_model_uses_catalog_limits() -> None:
    config = model_config_from_entry({
        "provider": "copilotcli",
        "model": "claude-fable-5.1",
    })

    assert config.max_context == 1_000_000
    assert config.max_tokens == 128_000
    assert config.cost_per_1k_tokens == pytest.approx(0.03)


@pytest.mark.parametrize(
    ("provider", "expected"),
    [
        ("copilotcli", "copilotcli"),
        ("copilot-cli-resumable", "copilotcli"),
        ("copilot_cli", "copilotcli"),
        ("claudecode", "claudecode"),
        ("claude-code-resumable", "claudecode"),
        ("anthropic", None),
    ],
)
def test_agent_cli_provider_aliases(provider, expected) -> None:
    assert canonical_agent_cli_provider(provider) == expected


def test_filter_agent_cli_models_preserves_external_primary() -> None:
    external = ModelConfig(provider="anthropic", model_name="claude-opus-5")
    copilot = ModelConfig(provider="copilot-cli", model_name="gpt-5.6-sol")
    claude = ModelConfig(provider="claudecode", model_name="session-default")
    config = LLMConfig(
        primary_model=external,
        fallback_models=[copilot, claude],
        specialized_models={"ranking": copilot},
    )

    filtered, removed = filter_agent_cli_models(
        config,
        selected_agent_cli="copilot",
        allow_selected_agent_cli=False,
    )

    assert filtered is not None
    assert filtered.primary_model is external
    assert filtered.fallback_models == []
    assert "ranking" not in filtered.specialized_models
    assert {model.provider for model in removed} == {
        "copilot-cli",
        "claudecode",
    }


def test_external_api_provider_still_beats_copilot(
    isolated_resolution,
) -> None:
    isolated_resolution.setenv("RAPTOR_AGENT_CLI", "copilot")
    isolated_resolution.setenv("ANTHROPIC_API_KEY", "key")
    isolated_resolution.setattr(
        "shutil.which",
        lambda name: "/usr/bin/copilot" if name == "copilot" else None,
    )

    config = _get_default_primary_model()

    assert config is not None
    assert config.provider == "anthropic"


def test_external_primary_gets_selected_copilot_fallback(
    isolated_resolution,
) -> None:
    isolated_resolution.setenv("RAPTOR_AGENT_CLI", "copilot")
    isolated_resolution.setenv("ANTHROPIC_API_KEY", "key")
    isolated_resolution.setattr(
        "shutil.which",
        lambda name: "/usr/bin/copilot" if name == "copilot" else None,
    )
    isolated_resolution.setattr(
        config_mod,
        "detect_llm_availability",
        lambda: SimpleNamespace(
            external_llm=True,
            copilot_cli=True,
        ),
    )
    isolated_resolution.setattr(config_mod, "_get_configured_models", list)

    fallbacks = config_mod._get_default_fallback_models()

    assert any(model.provider == "copilotcli" for model in fallbacks)


def test_copilot_mode_ignores_configured_claude_cli_fallback(
    isolated_resolution,
) -> None:
    isolated_resolution.setenv("RAPTOR_AGENT_CLI", "copilot")
    isolated_resolution.setenv("ANTHROPIC_API_KEY", "key")
    isolated_resolution.setattr(
        "shutil.which",
        lambda name: f"/usr/bin/{name}"
        if name in ("copilot", "claude") else None,
    )
    isolated_resolution.setattr(
        config_mod,
        "detect_llm_availability",
        lambda: SimpleNamespace(
            external_llm=True,
            copilot_cli=True,
        ),
    )
    isolated_resolution.setattr(
        config_mod,
        "_get_configured_models",
        lambda: [{
            "provider": "claudecode",
            "model": "session-default",
            "role": "fallback",
        }],
    )

    fallbacks = config_mod._get_default_fallback_models()

    assert all(
        canonical_agent_cli_provider(model.provider) != "claudecode"
        for model in fallbacks
    )
    assert any(model.provider == "copilotcli" for model in fallbacks)


def test_availability_positional_constructor_remains_compatible() -> None:
    from core.llm.detection import LLMAvailability

    availability = LLMAvailability(False, True, True)

    assert availability.copilot_cli is False
    assert availability.agent_cli_available is True


def test_detection_marks_selected_copilot_as_orchestrated_llm(
    monkeypatch,
) -> None:
    import core.llm.detection as detection

    for name in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "MISTRAL_API_KEY",
        "AWS_BEARER_TOKEN_BEDROCK",
        "RAPTOR_BEDROCK_MODEL",
        "RAPTOR_BEDROCK_PROFILE",
        "RAPTOR_LLM_SOCKET",
        "CLAUDECODE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RAPTOR_AGENT_CLI", "copilot")
    monkeypatch.setattr(detection, "_cached_llm_availability", None)
    monkeypatch.setattr(detection, "_check_litellm_installed", lambda: False)
    monkeypatch.setattr(detection, "_check_litellm_migration", lambda: None)
    monkeypatch.setattr(detection, "_config_has_keyed_models", lambda: False)
    monkeypatch.setattr(detection, "_get_available_ollama_models", list)
    monkeypatch.setattr(detection, "_warn_unusable_keys", lambda: None)
    monkeypatch.setattr(detection, "OPENAI_SDK_AVAILABLE", False)
    monkeypatch.setattr(detection, "ANTHROPIC_SDK_AVAILABLE", False)
    monkeypatch.setattr(detection, "GENAI_SDK_AVAILABLE", False)
    monkeypatch.setattr(detection, "BOTOCORE_SDK_AVAILABLE", False)
    monkeypatch.setattr(
        detection.shutil,
        "which",
        lambda name: "/usr/bin/copilot" if name == "copilot" else None,
    )

    availability = detection.detect_llm_availability()

    assert availability.copilot_cli is True
    assert availability.external_llm is False
    assert availability.llm_available is True
    assert availability.claude_code is False


def test_copilot_resolution_failure_never_falls_to_claude(
    isolated_resolution,
) -> None:
    isolated_resolution.setenv("RAPTOR_AGENT_CLI", "copilot")
    isolated_resolution.setattr(
        "shutil.which",
        lambda name: "/usr/bin/claude" if name == "claude" else None,
    )

    assert _get_default_primary_model() is None


def test_copilot_primary_uses_subprocess_worker_cap(
    isolated_resolution,
) -> None:
    import core.llm.concurrency as concurrency

    isolated_resolution.setenv("RAPTOR_AGENT_CLI", "copilot")
    isolated_resolution.setattr(
        "shutil.which",
        lambda name: "/usr/bin/copilot" if name == "copilot" else None,
    )
    isolated_resolution.setattr(
        concurrency, "read_tuning_max_llm_workers", lambda: None,
    )

    assert concurrency.derive_max_workers(COPILOT_DEFAULT_MODEL) == 4


@pytest.mark.parametrize(
    "provider",
    ("copilotcli", "copilot-cli", "copilot_cli-resumable"),
)
def test_copilot_provider_hint_always_uses_subprocess_worker_cap(
    isolated_resolution,
    provider,
) -> None:
    import core.llm.concurrency as concurrency

    isolated_resolution.setattr(
        concurrency, "read_tuning_max_llm_workers", lambda: None,
    )

    assert concurrency.derive_max_workers(
        "gpt-5.3-codex",
        provider=provider,
    ) == 4
