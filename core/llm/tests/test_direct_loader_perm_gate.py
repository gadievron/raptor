"""The DIRECT model-config loader applies the models.json permission
gate.

``core.llm.config._get_configured_models`` (via
``core.llm.detection._read_config_models``) reads the identical file
the dispatcher credential seeder does — and its consumers carry inline
``api_key`` entries into live transports (``_pinned_llm_config`` for
every ``--model`` run and ``raptor-llm-ask``, default-primary
resolution). Gating only the seeder left a compose hole: the seeder's
refusal became the env-direct fallback reason, and the child re-read
the same loose file through this ungated loader.

These tests mirror the seeder's gate matrix on the direct-loader path
and pin that the compose hole is closed (both loaders refuse the same
file).
"""

from __future__ import annotations

import json
import logging
import sys

import pytest

from core.llm.config import _get_configured_models
from core.llm.models_config_perm import WorldReadableModelsConfigError

_KEYED = {"models": [{"provider": "gemini", "api_key": "AIza-exposed"}]}

_perm_bits = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits have no meaning on Windows",
)


def _keyed_config(tmp_path, mode: int):
    config = tmp_path / "models.json"
    config.write_text(json.dumps(_KEYED))
    config.chmod(mode)
    return config


@_perm_bits
def test_direct_loader_refuses_world_readable_keyed(tmp_path,
                                                    monkeypatch):
    """0644 + inline keys → the direct loader refuses with the same
    exception, remedy, and override-env naming as the seeder — and the
    refusal is NOT swallowed into the loader's return-[] posture."""
    config = _keyed_config(tmp_path, 0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.delenv(
        "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", raising=False,
    )

    with pytest.raises(WorldReadableModelsConfigError) as excinfo:
        _get_configured_models()

    msg = str(excinfo.value)
    assert f"chmod 600 {config}" in msg
    assert "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON" in msg
    assert "0644" in msg
    assert "AIza-exposed" not in msg          # never the key value


@_perm_bits
def test_direct_loader_group_readable_also_refuses(tmp_path,
                                                   monkeypatch):
    config = _keyed_config(tmp_path, 0o640)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.delenv(
        "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", raising=False,
    )

    with pytest.raises(WorldReadableModelsConfigError):
        _get_configured_models()


@_perm_bits
def test_direct_loader_override_env_loads_with_warning(tmp_path,
                                                       monkeypatch,
                                                       caplog):
    """RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON=1 loads with the
    acknowledged-override warning — same escape hatch as the seeder."""
    config = _keyed_config(tmp_path, 0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.setenv("RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", "1")

    with caplog.at_level(logging.WARNING):
        models = _get_configured_models()

    assert any(m.get("provider") == "gemini" for m in models)
    warned = " ".join(r.getMessage() for r in caplog.records)
    assert "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON" in warned
    assert "chmod 600" in warned
    assert "AIza-exposed" not in warned       # never the key value


@_perm_bits
def test_direct_loader_override_requires_exact_one(tmp_path,
                                                   monkeypatch):
    config = _keyed_config(tmp_path, 0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.setenv("RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", "true")

    with pytest.raises(WorldReadableModelsConfigError):
        _get_configured_models()


@_perm_bits
def test_direct_loader_keyless_loose_only_warns(tmp_path, monkeypatch,
                                                caplog):
    """A loose-mode routing-only config (no inline keys) still loads —
    hygiene warning, never a refusal."""
    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [{"provider": "gemini", "model": "gemini-2.5-pro"}],
    }))
    config.chmod(0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.delenv(
        "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", raising=False,
    )

    with caplog.at_level(logging.WARNING):
        models = _get_configured_models()     # must not raise

    assert any(m.get("provider") == "gemini" for m in models)
    warned = " ".join(r.getMessage() for r in caplog.records)
    assert "chmod 600" in warned


@_perm_bits
def test_direct_loader_private_file_loads_silently(tmp_path,
                                                   monkeypatch,
                                                   caplog):
    config = _keyed_config(tmp_path, 0o600)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))

    with caplog.at_level(logging.WARNING):
        models = _get_configured_models()

    assert any(m.get("provider") == "gemini" for m in models)
    assert not [r for r in caplog.records
                if "chmod" in r.getMessage()]


@_perm_bits
def test_direct_loader_symlink_to_loose_target_refuses(tmp_path,
                                                       monkeypatch):
    """The gate stats through symlinks — the verdict is about the
    TARGET the keys actually live in, so a private-looking symlink to
    a loose keyed file still refuses."""
    target = _keyed_config(tmp_path, 0o644)
    link = tmp_path / "models-link.json"
    link.symlink_to(target)
    monkeypatch.setenv("RAPTOR_CONFIG", str(link))
    monkeypatch.delenv(
        "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", raising=False,
    )

    with pytest.raises(WorldReadableModelsConfigError):
        _get_configured_models()


@_perm_bits
def test_compose_hole_closed_both_loaders_refuse(tmp_path,
                                                 monkeypatch):
    """The fix3×fix4 compose pin: when the dispatcher seeder refuses a
    loose keyed models.json (parent falls back env-direct), the child's
    DIRECT loader re-reading the SAME file also refuses — the refusal
    can no longer be routed around through the sibling loader."""
    from core.llm.dispatcher.auth import CredentialStore, seed_from_config

    config = _keyed_config(tmp_path, 0o644)
    monkeypatch.setenv("RAPTOR_CONFIG", str(config))
    monkeypatch.delenv(
        "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON", raising=False,
    )

    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {"gemini": None}
    with pytest.raises(WorldReadableModelsConfigError):
        seed_from_config(creds)               # parent-side refusal

    with pytest.raises(WorldReadableModelsConfigError):
        _get_configured_models()              # child-side refusal too

    assert creds.get("gemini") is None        # nothing seeded either way
