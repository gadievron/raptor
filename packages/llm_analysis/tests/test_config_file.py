"""Tests for config file reading, model defaulting, and migration detection."""

import json
import os
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.llm_analysis.llm.config import _get_configured_models, _get_best_thinking_model
from packages.llm_analysis.llm.model_data import PROVIDER_DEFAULT_MODELS, MODEL_COSTS, MODEL_LIMITS


class TestGetConfiguredModels:
    """Test config file reading with various formats."""

    def test_dict_format_with_models_key(self, tmp_path):
        """Accept {"models": [...]} format."""
        config = tmp_path / "models.json"
        config.write_text(json.dumps({
            "models": [
                {"provider": "anthropic", "model": "claude-opus-4-6"}
            ]
        }))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            result = _get_configured_models()
        assert len(result) == 1
        assert result[0]["provider"] == "anthropic"

    def test_bare_list_format(self, tmp_path):
        """Accept bare [...] format."""
        config = tmp_path / "models.json"
        config.write_text(json.dumps([
            {"provider": "openai", "model": "gpt-5.2"}
        ]))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            result = _get_configured_models()
        assert len(result) == 1
        assert result[0]["provider"] == "openai"

    def test_strips_line_comments(self, tmp_path):
        """Strip // comments before parsing."""
        config = tmp_path / "models.json"
        config.write_text(
            '// This is a comment\n'
            '{\n'
            '  // Another comment\n'
            '  "models": [\n'
            '    {"provider": "anthropic", "model": "claude-opus-4-6"}\n'
            '  ]\n'
            '}\n'
        )
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            result = _get_configured_models()
        assert len(result) == 1

    def test_empty_file_returns_empty(self, tmp_path):
        """Empty file returns empty list."""
        config = tmp_path / "models.json"
        config.write_text("")
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            result = _get_configured_models()
        assert result == []

    def test_invalid_json_returns_empty(self, tmp_path):
        """Invalid JSON returns empty list, no crash."""
        config = tmp_path / "models.json"
        config.write_text("{not valid json")
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            result = _get_configured_models()
        assert result == []

    def test_missing_file_returns_empty(self):
        """Missing file returns empty list."""
        with patch.dict(os.environ, {"RAPTOR_CONFIG": "/nonexistent/path/models.json"}):
            result = _get_configured_models()
        assert result == []

    def test_non_list_models_returns_empty(self, tmp_path):
        """models key that isn't a list returns empty."""
        config = tmp_path / "models.json"
        config.write_text(json.dumps({"models": "not a list"}))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            result = _get_configured_models()
        assert result == []

    def test_preserves_all_fields(self, tmp_path):
        """All config fields are preserved."""
        config = tmp_path / "models.json"
        entry = {
            "provider": "anthropic",
            "model": "claude-opus-4-6",
            "api_key": "sk-ant-test",
            "role": "analysis",
            "max_context": 500000,
            "max_output": 16000,
            "timeout": 300,
        }
        config.write_text(json.dumps({"models": [entry]}))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            result = _get_configured_models()
        assert result[0] == entry


class TestProviderDefaultModels:
    """Test that provider defaults are the best models."""

    def test_anthropic_defaults_to_opus(self):
        assert PROVIDER_DEFAULT_MODELS["anthropic"] == "claude-opus-4-6"

    def test_openai_defaults_to_thinking(self):
        assert PROVIDER_DEFAULT_MODELS["openai"] == "gpt-5.2-thinking"

    def test_gemini_defaults_to_pro(self):
        assert PROVIDER_DEFAULT_MODELS["gemini"] == "gemini-2.5-pro"

    def test_all_defaults_have_costs(self):
        """Every default model should be in MODEL_COSTS."""
        for provider, model in PROVIDER_DEFAULT_MODELS.items():
            if model != "mistral-large-latest":  # Mistral not in costs table
                assert model in MODEL_COSTS, f"Default {provider} model '{model}' not in MODEL_COSTS"

    def test_all_defaults_have_limits(self):
        """Every default model should be in MODEL_LIMITS."""
        for provider, model in PROVIDER_DEFAULT_MODELS.items():
            if model != "mistral-large-latest":
                assert model in MODEL_LIMITS, f"Default {provider} model '{model}' not in MODEL_LIMITS"


class TestModelDefaulting:
    """Test that provider-without-model defaults correctly."""

    def test_anthropic_without_model_gets_opus(self, tmp_path):
        """Config with just provider defaults to best model."""
        config = tmp_path / "models.json"
        config.write_text(json.dumps([
            {"provider": "anthropic", "api_key": "sk-ant-test"}
        ]))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            # Reset cache
            import packages.llm_analysis.llm.config as cfg
            cfg._thinking_model_checked = False
            cfg._cached_thinking_model = None

            result = _get_best_thinking_model()

        assert result is not None
        assert result.model_name == "claude-opus-4-6"
        assert result.api_key == "sk-ant-test"

    def test_openai_without_model_gets_thinking(self, tmp_path):
        config = tmp_path / "models.json"
        config.write_text(json.dumps([
            {"provider": "openai", "api_key": "sk-test"}
        ]))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            import packages.llm_analysis.llm.config as cfg
            cfg._thinking_model_checked = False
            cfg._cached_thinking_model = None

            result = _get_best_thinking_model()

        assert result is not None
        assert result.model_name == "gpt-5.2-thinking"

    def test_api_key_falls_back_to_env_var(self, tmp_path):
        """Config without api_key uses env var."""
        config = tmp_path / "models.json"
        config.write_text(json.dumps([
            {"provider": "anthropic", "model": "claude-opus-4-6"}
        ]))
        with patch.dict(os.environ, {
            "RAPTOR_CONFIG": str(config),
            "ANTHROPIC_API_KEY": "sk-ant-from-env",
        }):
            import packages.llm_analysis.llm.config as cfg
            cfg._thinking_model_checked = False
            cfg._cached_thinking_model = None

            result = _get_best_thinking_model()

        assert result is not None
        assert result.api_key == "sk-ant-from-env"


class TestTimeoutFromConfig:
    """Test that timeout flows through from config file."""

    def test_custom_timeout_preserved(self, tmp_path):
        config = tmp_path / "models.json"
        config.write_text(json.dumps([
            {"provider": "anthropic", "model": "claude-opus-4-6",
             "api_key": "sk-test", "timeout": 300}
        ]))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            import packages.llm_analysis.llm.config as cfg
            cfg._thinking_model_checked = False
            cfg._cached_thinking_model = None

            result = _get_best_thinking_model()

        assert result is not None
        assert result.timeout == 300

    def test_default_timeout_is_120(self, tmp_path):
        config = tmp_path / "models.json"
        config.write_text(json.dumps([
            {"provider": "anthropic", "model": "claude-opus-4-6",
             "api_key": "sk-test"}
        ]))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            import packages.llm_analysis.llm.config as cfg
            cfg._thinking_model_checked = False
            cfg._cached_thinking_model = None

            result = _get_best_thinking_model()

        assert result is not None
        assert result.timeout == 120


class TestMigrationDetection:
    """Test LiteLLM migration guidance."""

    def test_prints_guidance_when_old_exists_new_missing(self, tmp_path, capsys):
        """Should print guidance when old config exists but new doesn't."""
        old_config = tmp_path / ".config" / "litellm" / "config.yaml"
        old_config.parent.mkdir(parents=True)
        old_config.write_text("model_list: []")

        from packages.llm_analysis.llm.detection import _check_litellm_migration
        with patch("packages.llm_analysis.llm.detection.Path.home", return_value=tmp_path):
            _check_litellm_migration()

        captured = capsys.readouterr()
        assert "LiteLLM is no longer used" in captured.out

    def test_no_guidance_when_both_exist(self, tmp_path, capsys):
        """Should not print when both configs exist."""
        old_config = tmp_path / ".config" / "litellm" / "config.yaml"
        old_config.parent.mkdir(parents=True)
        old_config.write_text("model_list: []")

        new_config = tmp_path / ".config" / "raptor" / "models.json"
        new_config.parent.mkdir(parents=True)
        new_config.write_text("[]")

        from packages.llm_analysis.llm.detection import _check_litellm_migration
        with patch("packages.llm_analysis.llm.detection.Path.home", return_value=tmp_path):
            _check_litellm_migration()

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_no_guidance_when_neither_exists(self, tmp_path, capsys):
        """Should not print when no configs exist."""
        from packages.llm_analysis.llm.detection import _check_litellm_migration
        with patch("packages.llm_analysis.llm.detection.Path.home", return_value=tmp_path):
            _check_litellm_migration()

        captured = capsys.readouterr()
        assert captured.out == ""


class TestModelDataConsistency:
    """Verify model data tables are internally consistent."""

    def test_all_cost_models_have_limits(self):
        """Every model in MODEL_COSTS should have MODEL_LIMITS."""
        for model in MODEL_COSTS:
            assert model in MODEL_LIMITS, f"'{model}' in MODEL_COSTS but not MODEL_LIMITS"

    def test_all_limit_models_have_costs(self):
        """Every model in MODEL_LIMITS should have MODEL_COSTS."""
        for model in MODEL_LIMITS:
            assert model in MODEL_COSTS, f"'{model}' in MODEL_LIMITS but not MODEL_COSTS"

    def test_all_costs_have_input_and_output(self):
        """Every cost entry must have both input and output."""
        for model, costs in MODEL_COSTS.items():
            assert "input" in costs, f"'{model}' missing 'input' cost"
            assert "output" in costs, f"'{model}' missing 'output' cost"

    def test_all_limits_have_context_and_output(self):
        """Every limit entry must have both max_context and max_output."""
        for model, limits in MODEL_LIMITS.items():
            assert "max_context" in limits, f"'{model}' missing 'max_context'"
            assert "max_output" in limits, f"'{model}' missing 'max_output'"
