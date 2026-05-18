"""Tests for ``seed_from_config`` — the ``models.json`` bridge.

The dispatcher's ``CredentialStore`` reads keys from env at
construction time. ``seed_from_config`` fills remaining empty slots
from ``~/.config/raptor/models.json`` so operators who keep their
keys in the documented config file don't see 503s from the proxy.
"""

from __future__ import annotations

import json

from core.llm.dispatcher.auth import CredentialStore, seed_from_config


def _make_empty_store() -> CredentialStore:
    """Build a CredentialStore with all slots empty.

    Bypasses ``__init__`` so the test runner's own env vars (if any
    leaked through) can't seed the store from underneath us.
    """
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": None,
        "openai": None,
        "gemini": None,
        "mistral": None,
        "groq": None,
        "together": None,
        "openrouter": None,
        "fireworks": None,
        "deepinfra": None,
        "perplexity": None,
        "cohere": None,
        "replicate": None,
        "azure_openai": None,
        "azure_openai_endpoint": None,
    }
    return creds


def test_seed_fills_empty_slots(tmp_path, monkeypatch):
    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [
            {"provider": "gemini",    "api_key": "AIza-test"},
            {"provider": "anthropic", "api_key": "sk-ant-test"},
        ]
    }))
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    creds = _make_empty_store()
    seed_from_config(creds)

    assert creds.get("gemini") == "AIza-test"
    assert creds.get("anthropic") == "sk-ant-test"
    # Untouched providers stay None.
    assert creds.get("openai") is None


def test_env_supplied_keys_are_not_overridden(tmp_path, monkeypatch):
    """If env already supplied a key, ``models.json`` does not replace it."""
    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [{"provider": "gemini", "api_key": "AIza-from-config"}]
    }))
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    creds = _make_empty_store()
    creds.set("gemini", "AIza-from-env")  # simulate the env-read
    seed_from_config(creds)

    assert creds.get("gemini") == "AIza-from-env"


def test_duplicate_provider_entries_first_wins(tmp_path, monkeypatch):
    """Two gemini entries (analysis + fallback) — first match seeds."""
    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [
            {"provider": "gemini", "role": "analysis", "api_key": "AIza-first"},
            {"provider": "gemini", "role": "fallback", "api_key": "AIza-second"},
        ]
    }))
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    creds = _make_empty_store()
    seed_from_config(creds)

    assert creds.get("gemini") == "AIza-first"


def test_silent_on_missing_file(tmp_path, monkeypatch):
    monkeypatch.setenv("RAPTOR_CONFIG", str(tmp_path / "does-not-exist.json"))

    creds = _make_empty_store()
    seed_from_config(creds)  # must not raise

    assert creds.get("gemini") is None


def test_silent_on_malformed_json(tmp_path, monkeypatch):
    config = tmp_path / "models.json"
    config.write_text("{ this is not json")
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    creds = _make_empty_store()
    seed_from_config(creds)  # must not raise

    assert creds.get("gemini") is None


def test_entries_without_api_key_are_skipped(tmp_path, monkeypatch):
    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [
            {"provider": "gemini",    "model": "gemini-2.5-pro"},  # no key
            {"provider": "anthropic", "api_key": "sk-ant-test"},
        ]
    }))
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    creds = _make_empty_store()
    seed_from_config(creds)

    assert creds.get("gemini") is None
    assert creds.get("anthropic") == "sk-ant-test"


def test_bare_list_shape_is_accepted(tmp_path, monkeypatch):
    """Config can be ``{"models": [...]}`` or a bare ``[...]``."""
    config = tmp_path / "models.json"
    config.write_text(json.dumps([
        {"provider": "gemini", "api_key": "AIza-bare-list"},
    ]))
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    creds = _make_empty_store()
    seed_from_config(creds)

    assert creds.get("gemini") == "AIza-bare-list"


def test_non_string_provider_or_key_is_skipped(tmp_path, monkeypatch):
    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [
            {"provider": "gemini",     "api_key": 12345},          # non-str key
            {"provider": ["anthropic"], "api_key": "sk-ant-test"},  # non-str provider
            {"provider": "openai",      "api_key": "sk-openai-ok"},
        ]
    }))
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    creds = _make_empty_store()
    seed_from_config(creds)

    assert creds.get("gemini") is None
    assert creds.get("anthropic") is None
    assert creds.get("openai") == "sk-openai-ok"
