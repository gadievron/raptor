"""Offline layer of :func:`core.llm.config._get_default_primary_model`.

``offline=True`` exists for callers that must never block on a socket
(the startup banner): the Ollama builder — the only provider whose
availability detection is a network probe — is skipped, while env-var
and config-file detection still run, so an offline caller resolves
the same primary a real run would except when that primary could only
be a live Ollama endpoint.

Hermetic: every ambient resolution source (env keys, config-file
lookups, PATH probes, the Ollama builder itself) is stubbed.
"""

from __future__ import annotations

import pytest

from core.llm import config as llm_config
from core.llm.config import _get_default_primary_model


from types import ModuleType
from core.testing.module_bindings import patch_module_attribute

_discovery_imports = ModuleType("discovery_fixture_imports")


@pytest.fixture(autouse=True)
def _owned_discovery_imports(monkeypatch):
    import core.llm.config as owner
    import core.llm.detection as detection
    from core.testing.llm_state import scoped_claudecode_discovery

    with scoped_claudecode_discovery(owner, detection) as imports:
        try:
            monkeypatch.setitem(globals(), "_discovery_imports", imports)
            yield
        finally:
            monkeypatch.undo()



@pytest.fixture
def clean_resolution(monkeypatch):
    """Neutralise ambient resolution sources so each test controls
    exactly which providers are available."""
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
                "MISTRAL_API_KEY",
                "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN", "AWS_BEARER_TOKEN_BEDROCK",
                "AWS_ENDPOINT_URL_BEDROCK", "CLAUDE_CODE_USE_BEDROCK",
                "RAPTOR_BEDROCK_MODEL", "RAPTOR_BEDROCK_PROFILE",
                "RAPTOR_LLM_SOCKET", "RAPTOR_CC_MODEL",
                "RAPTOR_CC_PIN_MODEL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(llm_config, "_operator_primary_override", None)
    monkeypatch.setattr(llm_config, "_get_best_thinking_model", lambda: None)
    monkeypatch.setattr(llm_config, "_config_bedrock_primary", lambda: None)
    patch_module_attribute(monkeypatch, _discovery_imports, 'shutil', 'which', lambda _bin: None)
    return monkeypatch


@pytest.fixture
def recorded_ollama(clean_resolution):
    """Replace the Ollama builder with a call recorder that resolves
    to nothing."""
    calls: list[str] = []

    def _probe() -> None:
        calls.append("ollama")
        return None

    clean_resolution.setitem(
        llm_config._PROVIDER_BUILDERS, "ollama", _probe,
    )
    return calls


def test_offline_skips_ollama_builder(recorded_ollama) -> None:
    assert _get_default_primary_model(offline=True) is None
    assert recorded_ollama == []


def test_online_default_still_reaches_ollama_builder(recorded_ollama) -> None:
    assert _get_default_primary_model() is None
    assert recorded_ollama == ["ollama"]


def test_offline_skips_ollama_even_when_preferred(recorded_ollama) -> None:
    assert _get_default_primary_model(
        prefer=["ollama"], offline=True,
    ) is None
    assert recorded_ollama == []


def test_offline_env_detection_still_resolves(recorded_ollama, clean_resolution) -> None:
    clean_resolution.setenv("ANTHROPIC_API_KEY", "test-key")
    config = _get_default_primary_model(offline=True)
    assert config is not None
    assert config.provider == "anthropic"
    assert recorded_ollama == []


def test_offline_skips_exactly_the_declared_network_probing_set(
    clean_resolution,
) -> None:
    """The skip sites key on ``_NETWORK_PROBING_PROVIDERS``, so a new
    network-probing provider is excluded from offline resolution by
    declaring it once, and every declared name is a real builder."""
    called: set[str] = set()
    for name in list(llm_config._PROVIDER_BUILDERS):
        clean_resolution.setitem(
            llm_config._PROVIDER_BUILDERS, name,
            lambda _n=name: called.add(_n),
        )
    assert _get_default_primary_model(offline=True) is None
    assert llm_config._NETWORK_PROBING_PROVIDERS <= set(
        llm_config._PROVIDER_BUILDERS
    )
    assert called == (
        set(llm_config._DEFAULT_PROVIDER_ORDER)
        - llm_config._NETWORK_PROBING_PROVIDERS
    )
