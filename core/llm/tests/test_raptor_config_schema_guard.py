"""RAPTOR_CONFIG / RAPTOR_EF_CONFIG schema guards.

``RAPTOR_CONFIG`` is ``core.llm``'s models.json path;
``packages/exploit_feasibility`` reads its analysis-settings JSON
from ``RAPTOR_EF_CONFIG`` (it historically shared ``RAPTOR_CONFIG``).
Each reader validates the schema it expects and errors actionably
naming the right variable on mismatch — stale environments may still
point one variable at the other reader's file.
"""

from __future__ import annotations

import json
import logging

import pytest

from core.llm import detection
from core.llm.detection import _read_config_models, looks_like_analysis_settings
from core.llm.dispatcher.auth import seed_from_config
from packages.exploit_feasibility.config import AnalysisConfig, load_config

_ANALYSIS_SETTINGS = {
    "checksec_path": "/usr/bin/checksec",
    "timeout_fast": 5,
    "enable_caching": False,
}

_MODELS_CONFIG = {
    "models": [
        {"provider": "openai", "model": "gpt-5.2"},
    ]
}


@pytest.fixture(autouse=True)
def _fresh_warn_latch():
    saved = set(detection._schema_mismatch_warned)
    detection._schema_mismatch_warned.clear()
    yield
    detection._schema_mismatch_warned.clear()
    detection._schema_mismatch_warned.update(saved)


def test_looks_like_analysis_settings_shapes():
    assert looks_like_analysis_settings(_ANALYSIS_SETTINGS)
    assert not looks_like_analysis_settings(_MODELS_CONFIG)
    assert not looks_like_analysis_settings([{"provider": "openai"}])
    assert not looks_like_analysis_settings({})
    # A models config that ALSO carries a stray settings-ish key stays
    # a models config — "models" wins.
    assert not looks_like_analysis_settings(
        {"models": [], "cache_dir": "/tmp/x"}
    )


class TestDetectionReader:
    def test_analysis_settings_file_errors_and_loads_nothing(
        self, tmp_path, monkeypatch, caplog,
    ):
        path = tmp_path / "config.json"
        path.write_text(json.dumps(_ANALYSIS_SETTINGS))
        monkeypatch.setenv("RAPTOR_CONFIG", str(path))
        with caplog.at_level(logging.ERROR):
            assert _read_config_models() == []
        msgs = [r.getMessage() for r in caplog.records
                if r.levelno >= logging.ERROR]
        assert any("exploit_feasibility" in m and "models" in m
                   for m in msgs), msgs

    def test_error_logged_once_per_path(self, tmp_path, monkeypatch, caplog):
        path = tmp_path / "config.json"
        path.write_text(json.dumps(_ANALYSIS_SETTINGS))
        monkeypatch.setenv("RAPTOR_CONFIG", str(path))
        with caplog.at_level(logging.ERROR):
            _read_config_models()
            _read_config_models()
        errors = [r for r in caplog.records
                  if "exploit_feasibility" in r.getMessage()]
        assert len(errors) == 1

    def test_models_config_still_loads_without_error(
        self, tmp_path, monkeypatch, caplog,
    ):
        path = tmp_path / "models.json"
        path.write_text(json.dumps(_MODELS_CONFIG))
        monkeypatch.setenv("RAPTOR_CONFIG", str(path))
        with caplog.at_level(logging.ERROR):
            models = _read_config_models()
        assert models and models[0]["provider"] == "openai"
        assert not [r for r in caplog.records
                    if "exploit_feasibility" in r.getMessage()]


class TestCredentialSeeder:
    def test_analysis_settings_file_warns_and_seeds_nothing(
        self, tmp_path, monkeypatch, caplog,
    ):
        from core.llm.dispatcher.auth import CredentialStore

        path = tmp_path / "config.json"
        # Give it an api_key-bearing entry-like field to prove we bail
        # on shape, not on missing keys.
        path.write_text(json.dumps({**_ANALYSIS_SETTINGS}))
        monkeypatch.setenv("RAPTOR_CONFIG", str(path))
        creds = CredentialStore.__new__(CredentialStore)
        creds._keys = {"anthropic": None}
        with caplog.at_level(logging.WARNING):
            seed_from_config(creds)
        assert creds.get("anthropic") is None
        assert any("exploit_feasibility" in r.getMessage()
                   for r in caplog.records)


class TestExploitFeasibilityReader:
    @pytest.mark.parametrize("payload", [
        _MODELS_CONFIG,
        [{"provider": "openai", "model": "gpt-5.2"}],
    ])
    def test_models_config_shape_raises_actionably(self, tmp_path, payload):
        path = tmp_path / "models.json"
        path.write_text(json.dumps(payload))
        with pytest.raises(ValueError, match=r"core\.llm"):
            AnalysisConfig.from_file(str(path))

    def test_load_config_ignores_raptor_config(self, tmp_path, monkeypatch):
        """The feasibility reader cut over to RAPTOR_EF_CONFIG;
        RAPTOR_CONFIG belongs to core.llm and must not be consulted."""
        from packages.exploit_feasibility.config import reset_config

        path = tmp_path / "models.json"
        path.write_text(json.dumps(_MODELS_CONFIG))
        monkeypatch.setenv("RAPTOR_CONFIG", str(path))
        monkeypatch.delenv("RAPTOR_EF_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)  # no ./.raptor.json interference
        reset_config()
        try:
            config = load_config()  # models file NOT read: defaults
            assert config.checksec_path == AnalysisConfig().checksec_path
        finally:
            reset_config()

    def test_load_config_via_ef_config(self, tmp_path, monkeypatch):
        from packages.exploit_feasibility.config import reset_config

        path = tmp_path / "config.json"
        path.write_text(json.dumps(_ANALYSIS_SETTINGS))
        monkeypatch.delenv("RAPTOR_CONFIG", raising=False)
        monkeypatch.setenv("RAPTOR_EF_CONFIG", str(path))
        monkeypatch.chdir(tmp_path)
        reset_config()
        try:
            config = load_config()
            assert config.checksec_path == "/usr/bin/checksec"
        finally:
            reset_config()

    def test_ef_config_models_shape_raises_naming_ef_var(
        self, tmp_path, monkeypatch,
    ):
        from packages.exploit_feasibility.config import reset_config

        path = tmp_path / "models.json"
        path.write_text(json.dumps(_MODELS_CONFIG))
        monkeypatch.setenv("RAPTOR_EF_CONFIG", str(path))
        monkeypatch.chdir(tmp_path)
        reset_config()
        try:
            with pytest.raises(ValueError, match="RAPTOR_EF_CONFIG"):
                load_config()
        finally:
            reset_config()

    def test_analysis_settings_file_still_loads(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps(_ANALYSIS_SETTINGS))
        config = AnalysisConfig.from_file(str(path))
        assert config.checksec_path == "/usr/bin/checksec"
        assert config.timeout_fast == 5
        assert config.enable_caching is False


class TestExploitFeasibilityEnvFamily:
    """The feasibility env family is RAPTOR_EF_*-prefixed; the bare
    RAPTOR_ spellings it once used read as framework-wide knobs and
    are no longer consulted."""

    def test_ef_prefixed_names_honoured(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_EF_TIMEOUT_FAST", "42")
        monkeypatch.setenv("RAPTOR_EF_CACHE_DIR", "/tmp/ef-cache")
        config = AnalysisConfig.from_env()
        assert config.timeout_fast == 42
        assert config.cache_dir == "/tmp/ef-cache"

    def test_bare_legacy_names_ignored(self, monkeypatch):
        defaults = AnalysisConfig()
        monkeypatch.setenv("RAPTOR_TIMEOUT_FAST", "42")
        monkeypatch.setenv("RAPTOR_CACHE_DIR", "/tmp/ef-cache")
        monkeypatch.setenv("RAPTOR_VERBOSE", "true")
        config = AnalysisConfig.from_env()
        assert config.timeout_fast == defaults.timeout_fast
        assert config.cache_dir == defaults.cache_dir
        assert config.verbose == defaults.verbose

    @pytest.mark.parametrize("raw,expected", [
        ("true", True), ("YES", True), ("on", True), ("1", True),
        ("false", False), ("no", False), ("OFF", False), ("0", False),
    ])
    def test_booleans_use_shared_toggle_spellings(
        self, monkeypatch, raw, expected,
    ):
        monkeypatch.setenv("RAPTOR_EF_VERBOSE", raw)
        assert AnalysisConfig.from_env().verbose is expected

    def test_invalid_boolean_keeps_default(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_EF_ENABLE_CACHING", "ture")
        config = AnalysisConfig.from_env()
        assert config.enable_caching is AnalysisConfig().enable_caching
