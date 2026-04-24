"""Tests for raptor models.json reader/writer."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from packages.studio.services.models_reader import (
    ENV_VARS,
    ROLES,
    ModelConfig,
    ModelEntry,
    current_budget_cap,
    env_status,
    load_models_config,
    save_models_config,
)


def test_load_models_config_missing_file(tmp_path: Path):
    config = load_models_config(tmp_path / "nope.json")
    assert config.entries == []


def test_load_models_config_malformed_returns_empty(tmp_path: Path):
    path = tmp_path / "models.json"
    path.write_text("{not valid json")
    config = load_models_config(path)
    assert config.entries == []


def test_load_models_config_reads_roles(tmp_path: Path):
    path = tmp_path / "models.json"
    path.write_text(json.dumps({
        "models": [
            {"provider": "anthropic", "model": "claude-opus-4-6", "api_key": "${ANTHROPIC_API_KEY}", "role": "analysis"},
            {"provider": "openai", "model": "gpt-5.4", "api_key": "sk-foo", "role": "code"},
        ]
    }))
    config = load_models_config(path)
    assert len(config.entries) == 2
    assert config.by_role("analysis").provider == "anthropic"
    assert config.by_role("code").model == "gpt-5.4"
    assert config.by_role("consensus") is None


def test_save_models_config_roundtrip(tmp_path: Path):
    path = tmp_path / "models.json"
    config = ModelConfig(entries=[
        ModelEntry(provider="anthropic", model="claude", api_key="${X}", role="analysis"),
    ])
    save_models_config(config, path)
    assert path.is_file()
    reloaded = load_models_config(path)
    assert reloaded.entries[0].provider == "anthropic"
    assert reloaded.entries[0].role == "analysis"


def test_save_models_config_creates_parent_dirs(tmp_path: Path):
    path = tmp_path / "nested" / "deeper" / "models.json"
    save_models_config(ModelConfig(entries=[]), path)
    assert path.is_file()


def test_env_status_reports_all_providers(monkeypatch):
    for var in ENV_VARS.values():
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    status = env_status()
    assert status["anthropic"]["is_set"] is True
    assert status["openai"]["is_set"] is False
    assert status["anthropic"]["env_var"] == "ANTHROPIC_API_KEY"


def test_budget_cap_parses_env(monkeypatch):
    monkeypatch.setenv("RAPTOR_MAX_COST", "5.00")
    assert current_budget_cap() == 5.0
    monkeypatch.setenv("RAPTOR_MAX_COST", "not-a-number")
    assert current_budget_cap() is None
    monkeypatch.delenv("RAPTOR_MAX_COST")
    assert current_budget_cap() is None


def test_api_key_display_preserves_env_refs():
    entry = ModelEntry(api_key="${ANTHROPIC_API_KEY}")
    assert entry.api_key_display == "${ANTHROPIC_API_KEY}"


def test_api_key_display_masks_raw_keys():
    entry = ModelEntry(api_key="sk-1234567890abcdef")
    display = entry.api_key_display
    assert "…" in display
    assert "1234" not in display[5:]  # only the prefix leaks
    assert entry.api_key not in display


def test_roles_are_the_expected_four():
    assert set(ROLES) == {"analysis", "code", "consensus", "fallback"}
