"""Tests for ``seed_from_config`` — the ``models.json`` bridge.

The dispatcher's ``CredentialStore`` reads keys from env at
construction time. ``seed_from_config`` fills remaining empty slots
from ``~/.config/raptor/models.json`` so operators who keep their
keys in the documented config file don't see 503s from the proxy.
"""

from __future__ import annotations

import json
import sys

import pytest

from core.llm.dispatcher.auth import (
    CredentialStore,
    WorldReadableModelsConfigError,
    seed_from_config,
)


def _write_config(config, payload) -> None:
    """Write a models.json with private (0600) permissions.

    Key-bearing fixtures must be mode-0600: ``seed_from_config``
    fail-closes on a group/other-readable file that carries inline
    API keys, and pytest's tmp files otherwise inherit the runner's
    umask (frequently 0644)."""
    config.write_text(
        payload if isinstance(payload, str) else json.dumps(payload),
    )
    config.chmod(0o600)


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
        "orcarouter": None,
        "cheaperinference": None,
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
    _write_config(config, ({
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
    _write_config(config, ({
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
    _write_config(config, ({
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
    _write_config(config, ({
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
    _write_config(config, ([
        {"provider": "gemini", "api_key": "AIza-bare-list"},
    ]))
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    creds = _make_empty_store()
    seed_from_config(creds)

    assert creds.get("gemini") == "AIza-bare-list"


def test_non_string_provider_or_key_is_skipped(tmp_path, monkeypatch):
    config = tmp_path / "models.json"
    _write_config(config, ({
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


# ---------------------------------------------------------------------------
# World-readable models.json — fail-closed credential-exposure gate
# ---------------------------------------------------------------------------

_KEYED = {"models": [{"provider": "gemini", "api_key": "AIza-exposed"}]}

_perm_bits = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits have no meaning on Windows",
)


@_perm_bits
def test_world_readable_with_inline_keys_refuses(tmp_path, monkeypatch):
    """A group/other-readable models.json that carries inline API keys
    refuses to load: dedicated exception, actionable chmod remedy, the
    override env named — and never the key value itself."""
    config = tmp_path / "models.json"
    config.write_text(json.dumps(_KEYED))
    config.chmod(0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.delenv(
        "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", raising=False,
    )

    creds = _make_empty_store()
    with pytest.raises(WorldReadableModelsConfigError) as excinfo:
        seed_from_config(creds)

    msg = str(excinfo.value)
    assert f"chmod 600 {config}" in msg
    assert "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON" in msg
    assert "0644" in msg
    assert "AIza-exposed" not in msg          # never the key value
    # Fail-closed: nothing was seeded.
    assert creds.get("gemini") is None


@_perm_bits
def test_group_readable_also_refuses(tmp_path, monkeypatch):
    """Group-readable (0640) counts — another UID in the group can
    read the file on a multi-user box."""
    config = tmp_path / "models.json"
    config.write_text(json.dumps(_KEYED))
    config.chmod(0o640)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.delenv(
        "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", raising=False,
    )

    creds = _make_empty_store()
    with pytest.raises(WorldReadableModelsConfigError):
        seed_from_config(creds)


@_perm_bits
def test_override_env_loads_with_loud_warning(tmp_path, monkeypatch,
                                              caplog):
    """RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON=1 is the operator
    escape hatch: the file loads, with an acknowledged-override
    warning naming the env and the chmod remedy."""
    import logging

    config = tmp_path / "models.json"
    config.write_text(json.dumps(_KEYED))
    config.chmod(0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.setenv("RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", "1")

    creds = _make_empty_store()
    with caplog.at_level(logging.WARNING):
        seed_from_config(creds)

    assert creds.get("gemini") == "AIza-exposed"
    warned = " ".join(r.getMessage() for r in caplog.records)
    assert "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON" in warned
    assert "chmod 600" in warned
    assert "AIza-exposed" not in warned       # never the key value


@_perm_bits
def test_override_env_requires_exact_one(tmp_path, monkeypatch):
    """The consent value must be exactly "1" — truthy-looking values
    like "true" do not grant it."""
    config = tmp_path / "models.json"
    config.write_text(json.dumps(_KEYED))
    config.chmod(0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.setenv("RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", "true")

    creds = _make_empty_store()
    with pytest.raises(WorldReadableModelsConfigError):
        seed_from_config(creds)


@_perm_bits
def test_world_readable_without_keys_only_warns(tmp_path, monkeypatch,
                                                caplog):
    """A loose-mode file with NO inline api_key entries (routing-only
    config) is a hygiene warning, never a refusal — there is nothing
    sensitive in it to protect."""
    import logging

    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [{"provider": "gemini", "model": "gemini-2.5-pro"}],
    }))
    config.chmod(0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.delenv(
        "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", raising=False,
    )

    creds = _make_empty_store()
    with caplog.at_level(logging.WARNING):
        seed_from_config(creds)          # must not raise

    warned = " ".join(r.getMessage() for r in caplog.records)
    assert "chmod 600" in warned


@_perm_bits
def test_ensure_route_for_client_surfaces_the_refusal(tmp_path,
                                                      monkeypatch,
                                                      capsys):
    """The standalone-CLI seam (``ensure_route_for_client``) must not
    swallow the fail-closed refusal into its never-raises contract:
    the CLI keeps running (no raise), but the operator's remedy —
    ``chmod 600`` + the override env name — lands on stderr instead
    of vanishing into ``except Exception: pass``."""
    from types import SimpleNamespace

    from core.llm.dispatcher.lifecycle import ensure_route_for_client

    config = tmp_path / "models.json"
    config.write_text(json.dumps(_KEYED))
    config.chmod(0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.delenv(
        "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", raising=False,
    )
    # No pre-existing route, and a bedrock primary so the self-serve
    # gate actually attempts the dispatcher bring-up (which seeds
    # credentials BEFORE constructing anything).
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)
    client = SimpleNamespace(config=SimpleNamespace(
        primary_model=SimpleNamespace(provider="bedrock"),
        fallback_models=[],
    ))

    ensure_route_for_client(client, "study-run")   # must not raise

    err = capsys.readouterr().err
    assert "dispatcher credential seeding refused" in err
    assert "chmod 600" in err
    assert "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON" in err
    assert "AIza-exposed" not in err          # never the key value
    # And no route was exported — the refusal happened before any
    # dispatcher existed.
    assert "RAPTOR_LLM_SOCKET" not in __import__("os").environ


@_perm_bits
def test_private_file_with_keys_loads_silently(tmp_path, monkeypatch,
                                               caplog):
    """The happy path: a 0600 file with inline keys loads with no
    permission warning at all."""
    import logging

    config = tmp_path / "models.json"
    _write_config(config, _KEYED)        # helper writes mode 0600
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    creds = _make_empty_store()
    with caplog.at_level(logging.WARNING):
        seed_from_config(creds)

    assert creds.get("gemini") == "AIza-exposed"
    assert not [r for r in caplog.records
                if "chmod" in r.getMessage()]
