"""Malformed persisted modes cannot replace an active operator configuration."""

import json
import os

import pytest

from core.dataflow import sanitizer_cut_config as cfg


@pytest.fixture(autouse=True)
def owned_configuration(monkeypatch):
    monkeypatch.setattr(cfg, "_active", None)
    for name in (
        "RAPTOR_SANITIZER_CUT", "RAPTOR_SANITIZER_CUT_NO_LEXICAL",
        "RAPTOR_SANITIZER_CUT_PARITY_LOG", "RAPTOR_SANITIZER_CUT_AUDIT_DIR",
    ):
        monkeypatch.setenv(name, "owned-original")


@pytest.mark.parametrize("mode", [False, 0, 0.0, [], {}, None])
def test_malformed_mode_preserves_active_config_and_environment(tmp_path, mode):
    active = cfg.configure("strict", run_dir=str(tmp_path))
    environment = dict(os.environ)
    (tmp_path / "sanitizer-cut-config.json").write_text(
        json.dumps({"mode": mode}), encoding="utf-8",
    )
    assert cfg.load_persisted(str(tmp_path), export_env=True) is None
    assert cfg.current() is active
    assert dict(os.environ) == environment


@pytest.mark.parametrize("mode", cfg.VALID_MODES)
def test_valid_persisted_mode_replaces_active_config(tmp_path, mode):
    cfg.configure("strict")
    (tmp_path / "sanitizer-cut-config.json").write_text(
        json.dumps({"mode": mode}), encoding="utf-8",
    )
    loaded = cfg.load_persisted(str(tmp_path), export_env=False)
    assert loaded is not None
    assert loaded.mode == mode
    assert cfg.current() is loaded


def test_missing_mode_retains_legacy_off_default(tmp_path):
    cfg.configure("strict")
    (tmp_path / "sanitizer-cut-config.json").write_text("{}", encoding="utf-8")
    loaded = cfg.load_persisted(str(tmp_path), export_env=False)
    assert loaded is not None
    assert loaded.mode == "off"
