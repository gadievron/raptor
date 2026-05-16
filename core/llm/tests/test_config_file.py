"""Tests for config file reading, model defaulting, and migration detection."""

import json
import os
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# packages/llm_analysis/tests/test_config_file.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.llm.config import (
    _get_configured_models, _get_best_thinking_model,
    _get_default_fallback_models, _model_config_from_entry,
)
from core.llm.model_data import PROVIDER_DEFAULT_MODELS, MODEL_COSTS, MODEL_LIMITS


@pytest.fixture(autouse=True)
def _restore_thinking_model_cache():
    """Snapshot core.llm.config's module-level cache before each test and
    restore after. Many tests in this file deliberately poke
    `_thinking_model_checked` / `_cached_thinking_model` to force a
    re-evaluation against tmp_path config; without restore, the module
    is left in an inconsistent state and later tests in the suite (e.g.
    packages/llm_analysis/tests/test_dispatch.py::test_multi_model_flags)
    re-read the real environment and pick up unintended fallbacks.
    """
    import core.llm.config as cfg
    saved_checked = getattr(cfg, "_thinking_model_checked", None)
    saved_cached = getattr(cfg, "_cached_thinking_model", None)
    try:
        yield
    finally:
        cfg._thinking_model_checked = saved_checked
        cfg._cached_thinking_model = saved_cached


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

    def test_openai_defaults_to_gpt54(self):
        assert PROVIDER_DEFAULT_MODELS["openai"] == "gpt-5.4"

    def test_gemini_defaults_to_pro(self):
        assert PROVIDER_DEFAULT_MODELS["gemini"] == "gemini-2.5-pro"

    def test_all_defaults_have_costs(self):
        """Every default model should be in MODEL_COSTS."""
        for provider, model in PROVIDER_DEFAULT_MODELS.items():
            assert model in MODEL_COSTS, f"Default {provider} model '{model}' not in MODEL_COSTS"

    def test_all_defaults_have_limits(self):
        """Every default model should be in MODEL_LIMITS."""
        for provider, model in PROVIDER_DEFAULT_MODELS.items():
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
            import core.llm.config as cfg
            cfg._thinking_model_checked = False
            cfg._cached_thinking_model = None
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "claude-opus-4-6"
        assert result.api_key == "sk-ant-test"

    def test_openai_without_model_gets_gpt54(self, tmp_path):
        config = tmp_path / "models.json"
        config.write_text(json.dumps([
            {"provider": "openai", "api_key": "sk-test"}
        ]))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}):
            import core.llm.config as cfg
            cfg._thinking_model_checked = False
            cfg._cached_thinking_model = None
            result = _get_best_thinking_model()
        assert result is not None
        assert result.model_name == "gpt-5.4"

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
            import core.llm.config as cfg
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
            import core.llm.config as cfg
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
            import core.llm.config as cfg
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

        from core.llm.detection import _check_litellm_migration
        with patch("core.llm.detection.Path.home", return_value=tmp_path):
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

        from core.llm.detection import _check_litellm_migration
        with patch("core.llm.detection.Path.home", return_value=tmp_path):
            _check_litellm_migration()

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_no_guidance_when_neither_exists(self, tmp_path, capsys):
        """Should not print when no configs exist."""
        from core.llm.detection import _check_litellm_migration
        with patch("core.llm.detection.Path.home", return_value=tmp_path):
            _check_litellm_migration()

        captured = capsys.readouterr()
        assert captured.out == ""


try:
    import yaml
    HAS_PYYAML = True
except ImportError:
    HAS_PYYAML = False


@pytest.mark.skipif(not HAS_PYYAML, reason="PyYAML not installed")
class TestAutoMigration:
    """Test auto-migration from LiteLLM YAML to RAPTOR JSON."""

    def _make_litellm_config(self, tmp_path, yaml_content):
        old = tmp_path / ".config" / "litellm" / "config.yaml"
        new = tmp_path / ".config" / "raptor" / "models.json"
        old.parent.mkdir(parents=True)
        old.write_text(yaml_content)
        return old, new

    def test_migrates_basic_config(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, """
model_list:
  - model_name: my-claude
    litellm_params:
      model: anthropic/claude-opus-4-6
      api_key: sk-ant-real-key
""")
        result = _try_auto_migrate(old, new)
        assert result is True
        assert new.exists()
        data = json.loads(new.read_text())
        assert len(data["models"]) == 1
        assert data["models"][0]["provider"] == "anthropic"
        assert data["models"][0]["model"] == "claude-opus-4-6"
        assert data["models"][0]["api_key"] == "sk-ant-real-key"

    def test_preserves_literal_api_keys(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, """
model_list:
  - model_name: gpt
    litellm_params:
      model: openai/gpt-5.2
      api_key: sk-literal-key-value
""")
        _try_auto_migrate(old, new)
        data = json.loads(new.read_text())
        assert data["models"][0]["api_key"] == "sk-literal-key-value"

    def test_env_var_keys_become_placeholders(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, """
model_list:
  - model_name: claude
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/ANTHROPIC_API_KEY
""")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            _try_auto_migrate(old, new)
        data = json.loads(new.read_text())
        assert data["models"][0]["api_key"] == "${ANTHROPIC_API_KEY}"

    def test_env_var_keys_omitted_when_set(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, """
model_list:
  - model_name: claude
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/ANTHROPIC_API_KEY
""")
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-real"}):
            _try_auto_migrate(old, new)
        data = json.loads(new.read_text())
        assert "api_key" not in data["models"][0]

    def test_multiple_models_migrated(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, """
model_list:
  - model_name: claude
    litellm_params:
      model: anthropic/claude-opus-4-6
      api_key: key1
  - model_name: gpt
    litellm_params:
      model: openai/gpt-5.2
      api_key: key2
  - model_name: gemini
    litellm_params:
      model: gemini/gemini-2.5-pro
      api_key: key3
""")
        _try_auto_migrate(old, new)
        data = json.loads(new.read_text())
        assert len(data["models"]) == 3
        providers = [m["provider"] for m in data["models"]]
        assert "anthropic" in providers
        assert "openai" in providers
        assert "gemini" in providers

    def test_sets_chmod_600(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, """
model_list:
  - model_name: claude
    litellm_params:
      model: anthropic/claude-opus-4-6
      api_key: secret
""")
        _try_auto_migrate(old, new)
        mode = oct(new.stat().st_mode)[-3:]
        assert mode == "600"

    def test_does_not_modify_old_config(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        original_content = """
model_list:
  - model_name: claude
    litellm_params:
      model: anthropic/claude-opus-4-6
      api_key: key
"""
        old, new = self._make_litellm_config(tmp_path, original_content)
        old_mtime = old.stat().st_mtime
        _try_auto_migrate(old, new)
        assert old.read_text() == original_content
        assert old.stat().st_mtime == old_mtime

    def test_returns_false_without_pyyaml(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, "model_list: []")
        with patch.dict(sys.modules, {"yaml": None}):
            result = _try_auto_migrate(old, new)
        assert result is False
        assert not new.exists()

    def test_returns_false_for_empty_model_list(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, "model_list: []")
        result = _try_auto_migrate(old, new)
        assert result is False

    def test_skips_entries_without_model(self, tmp_path):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, """
model_list:
  - model_name: broken
    litellm_params:
      api_key: key
  - model_name: valid
    litellm_params:
      model: anthropic/claude-opus-4-6
      api_key: key2
""")
        _try_auto_migrate(old, new)
        data = json.loads(new.read_text())
        assert len(data["models"]) == 1
        assert data["models"][0]["model"] == "claude-opus-4-6"

    def test_prints_needs_keys_warning(self, tmp_path, capsys):
        from core.llm.detection import _try_auto_migrate
        old, new = self._make_litellm_config(tmp_path, """
model_list:
  - model_name: claude
    litellm_params:
      model: anthropic/claude-opus-4-6
      api_key: os.environ/ANTHROPIC_API_KEY
""")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            _try_auto_migrate(old, new)
        captured = capsys.readouterr()
        assert "API keys" in captured.out


class TestGenerateSampleConfig:
    """Test sample config generation."""

    def test_includes_all_default_providers(self):
        from core.llm.detection import generate_sample_config
        sample = generate_sample_config()
        for provider in PROVIDER_DEFAULT_MODELS:
            assert f'"provider": "{provider}"' in sample

    def test_uses_default_model_names(self):
        from core.llm.detection import generate_sample_config
        sample = generate_sample_config()
        for model in PROVIDER_DEFAULT_MODELS.values():
            assert f'"model": "{model}"' in sample

    def test_no_api_key_in_json_body(self):
        from core.llm.detection import generate_sample_config
        sample = generate_sample_config()
        lines = [l for l in sample.splitlines() if not l.strip().startswith("//")]
        data = json.loads("\n".join(lines))
        for model in data["models"]:
            assert "api_key" not in model

    def test_includes_commented_key_example(self):
        from core.llm.detection import generate_sample_config
        sample = generate_sample_config()
        assert "// " in sample
        assert "api_key" in sample


class TestCompromisedLitellmDetection:
    """Test litellm compromise detection and hard stop."""

    @patch("core.llm.detection.Path.home")
    def test_182_8_causes_system_exit(self, mock_home, tmp_path):
        mock_home.return_value = tmp_path
        from core.llm.detection import _check_litellm_installed
        with patch("importlib.metadata.version", return_value="1.82.8"):
            with pytest.raises(SystemExit) as exc_info:
                _check_litellm_installed()
            assert "1.82.8" in str(exc_info.value)
            assert "24518" in str(exc_info.value)

    @patch("core.llm.detection.Path.home")
    def test_182_7_causes_system_exit(self, mock_home, tmp_path):
        mock_home.return_value = tmp_path
        from core.llm.detection import _check_litellm_installed
        with patch("importlib.metadata.version", return_value="1.82.7"):
            with pytest.raises(SystemExit) as exc_info:
                _check_litellm_installed()
            assert "1.82.7" in str(exc_info.value)

    @patch("core.llm.detection.Path.home")
    def test_safe_version_no_exit(self, mock_home, tmp_path, capsys):
        mock_home.return_value = tmp_path
        from core.llm.detection import _check_litellm_installed
        with patch("importlib.metadata.version", return_value="1.55.0"):
            _check_litellm_installed()
        captured = capsys.readouterr()
        assert "malicious" not in captured.out

    @patch("core.llm.detection.Path.home")
    def test_182_8_shows_shell_removal(self, mock_home, tmp_path, capsys):
        mock_home.return_value = tmp_path
        from core.llm.detection import _check_litellm_installed
        with patch("importlib.metadata.version", return_value="1.82.8"):
            with pytest.raises(SystemExit):
                _check_litellm_installed()
        captured = capsys.readouterr()
        assert "Do NOT use pip" in captured.out
        # Operator gets a guided two-step removal scoped to actual
        # site-packages locations rather than the previous
        # `find / ...` recommendation (whole-FS scan + path
        # substring match would delete unrelated files).
        assert "site.getsitepackages" in captured.out
        assert "rm -rf" in captured.out
        # Removal scope is the user's site-packages path, not `/`.
        assert "find /" not in captured.out

    @patch("core.llm.detection.Path.home")
    def test_182_7_shows_pip_removal(self, mock_home, tmp_path, capsys):
        mock_home.return_value = tmp_path
        from core.llm.detection import _check_litellm_installed
        with patch("importlib.metadata.version", return_value="1.82.7"):
            with pytest.raises(SystemExit):
                _check_litellm_installed()
        captured = capsys.readouterr()
        assert "pip uninstall litellm" in captured.out


@pytest.mark.skipif(not HAS_PYYAML, reason="PyYAML not installed")
class TestPreemptiveAutoMigration:
    """Test that litellm being installed triggers auto-migration."""

    def test_auto_migrates_when_litellm_installed(self, tmp_path, capsys):
        old_config = tmp_path / ".config" / "litellm" / "config.yaml"
        old_config.parent.mkdir(parents=True)
        old_config.write_text("""
model_list:
  - model_name: claude
    litellm_params:
      model: anthropic/claude-opus-4-6
      api_key: sk-ant-test
""")
        new_config = tmp_path / ".config" / "raptor" / "models.json"

        from core.llm.detection import _check_litellm_installed
        with patch("core.llm.detection.Path.home", return_value=tmp_path), \
             patch("importlib.metadata.version", return_value="1.55.0"):
            _check_litellm_installed()

        assert new_config.exists()
        data = json.loads(new_config.read_text())
        assert data["models"][0]["provider"] == "anthropic"

    def test_no_migration_when_new_config_exists(self, tmp_path):
        old_config = tmp_path / ".config" / "litellm" / "config.yaml"
        old_config.parent.mkdir(parents=True)
        old_config.write_text("model_list: [{model_name: x, litellm_params: {model: openai/gpt-5.2, api_key: k}}]")

        new_config = tmp_path / ".config" / "raptor" / "models.json"
        new_config.parent.mkdir(parents=True)
        new_config.write_text('{"models": []}')

        from core.llm.detection import _check_litellm_installed
        with patch("core.llm.detection.Path.home", return_value=tmp_path), \
             patch("importlib.metadata.version", return_value="1.55.0"):
            _check_litellm_installed()

        assert json.loads(new_config.read_text()) == {"models": []}


class TestConfigHasKeyedModelsSDKGating:
    """Test that _config_has_keyed_models checks SDK availability."""

    def test_returns_false_when_no_sdk(self, tmp_path):
        config = tmp_path / "models.json"
        config.write_text(json.dumps({"models": [
            {"provider": "anthropic", "model": "claude-opus-4-6", "api_key": "sk-ant-test"}
        ]}))
        from core.llm.detection import _config_has_keyed_models
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}), \
             patch("core.llm.detection.ANTHROPIC_SDK_AVAILABLE", False), \
             patch("core.llm.detection.OPENAI_SDK_AVAILABLE", False):
            assert _config_has_keyed_models() is False

    def test_returns_true_when_sdk_available(self, tmp_path):
        config = tmp_path / "models.json"
        config.write_text(json.dumps({"models": [
            {"provider": "anthropic", "model": "claude-opus-4-6", "api_key": "sk-ant-test"}
        ]}))
        from core.llm.detection import _config_has_keyed_models
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}), \
             patch("core.llm.detection.ANTHROPIC_SDK_AVAILABLE", True):
            assert _config_has_keyed_models() is True

    def test_ollama_requires_openai_sdk(self, tmp_path):
        config = tmp_path / "models.json"
        config.write_text(json.dumps({"models": [
            {"provider": "ollama", "model": "llama3", "api_key": "unused"}
        ]}))
        from core.llm.detection import _config_has_keyed_models
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}), \
             patch("core.llm.detection.OPENAI_SDK_AVAILABLE", False), \
             patch("core.llm.detection.ANTHROPIC_SDK_AVAILABLE", False):
            assert _config_has_keyed_models() is False


class TestWarnUnusableKeys:
    """Test warning when API keys are set but SDK is missing."""

    def test_warns_when_key_set_no_sdk(self):
        from core.llm.detection import _warn_unusable_keys
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}), \
             patch("core.llm.detection.ANTHROPIC_SDK_AVAILABLE", False), \
             patch("core.llm.detection.OPENAI_SDK_AVAILABLE", False), \
             patch("core.llm.detection.logger") as mock_logger:
            _warn_unusable_keys()
        mock_logger.warning.assert_called()
        warn_msg = mock_logger.warning.call_args[0][0]
        assert "ANTHROPIC_API_KEY" in warn_msg

    def test_no_warning_when_sdk_available(self):
        from core.llm.detection import _warn_unusable_keys
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}), \
             patch("core.llm.detection.ANTHROPIC_SDK_AVAILABLE", True), \
             patch("core.llm.detection.logger") as mock_logger:
            _warn_unusable_keys()
        mock_logger.warning.assert_not_called()

    def test_no_warning_when_no_key(self):
        from core.llm.detection import _warn_unusable_keys
        with patch.dict(os.environ, {}, clear=False), \
             patch("core.llm.detection.OPENAI_SDK_AVAILABLE", False), \
             patch("core.llm.detection.logger") as mock_logger:
            os.environ.pop("OPENAI_API_KEY", None)
            _warn_unusable_keys()
        mock_logger.warning.assert_not_called()


class TestFallbackModelsFromConfig:
    """Test that _get_default_fallback_models reads config file."""

    def test_config_fallback_role_used(self, tmp_path):
        """Models with role=fallback in config become fallback models."""
        config = tmp_path / "models.json"
        config.write_text(json.dumps({"models": [
            {"provider": "gemini", "model": "gemini-2.5-pro",
             "api_key": "test-key", "role": "analysis"},
            {"provider": "gemini", "model": "gemini-2.5-flash",
             "api_key": "test-key", "role": "fallback"},
        ]}))
        with patch.dict(os.environ, {"RAPTOR_CONFIG": str(config)}, clear=False):
            # Clear env vars so only config is used
            env = {k: v for k, v in os.environ.items()
                   if k not in ("GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MISTRAL_API_KEY")}
            with patch.dict(os.environ, env, clear=True):
                import core.llm.config as cfg
                cfg._thinking_model_checked = False
                cfg._cached_thinking_model = None
                fallbacks = _get_default_fallback_models()
        names = [f.model_name for f in fallbacks]
        assert "gemini-2.5-flash" in names
        # Primary should NOT be in fallbacks
        assert "gemini-2.5-pro" not in names

    def test_config_api_key_from_env(self, tmp_path):
        """Config entry without inline api_key resolves from env var."""
        config = tmp_path / "models.json"
        config.write_text(json.dumps({"models": [
            {"provider": "gemini", "model": "gemini-2.5-pro",
             "api_key": "test-key", "role": "analysis"},
            {"provider": "gemini", "model": "gemini-2.5-flash",
             "role": "fallback"},
        ]}))
        with patch.dict(os.environ, {
            "RAPTOR_CONFIG": str(config),
            "GEMINI_API_KEY": "env-key",
        }, clear=False):
            env_clean = {k: v for k, v in os.environ.items()
                         if k not in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MISTRAL_API_KEY")}
            with patch.dict(os.environ, env_clean, clear=True):
                import core.llm.config as cfg
                cfg._thinking_model_checked = False
                cfg._cached_thinking_model = None
                fallbacks = _get_default_fallback_models()
        flash = [f for f in fallbacks if f.model_name == "gemini-2.5-flash"]
        assert len(flash) == 1
        assert flash[0].api_key == "env-key"

    def test_config_timeout_honoured(self, tmp_path):
        """Config file timeout flows through to fallback ModelConfig."""
        entry = {"provider": "gemini", "model": "gemini-2.5-flash",
                 "api_key": "test-key", "timeout": 300}
        mc = _model_config_from_entry(entry)
        assert mc.timeout == 300
        assert mc.model_name == "gemini-2.5-flash"
        assert mc.api_key == "test-key"

    def test_env_var_fallback_when_no_config(self, tmp_path):
        """Without config file, env vars still produce fallbacks (backwards compat)."""
        config = tmp_path / "models.json"
        config.write_text(json.dumps({"models": []}))
        with patch.dict(os.environ, {
            "RAPTOR_CONFIG": str(config),
            "GEMINI_API_KEY": "env-key",
        }, clear=False):
            env_clean = {k: v for k, v in os.environ.items()
                         if k not in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MISTRAL_API_KEY")}
            with patch.dict(os.environ, env_clean, clear=True):
                import core.llm.config as cfg
                cfg._thinking_model_checked = False
                cfg._cached_thinking_model = None
                fallbacks = _get_default_fallback_models()
        names = [f.model_name for f in fallbacks]
        assert "gemini-2.5-pro" in names
        assert "gemini-2.5-flash" in names


class TestModelDataConsistency:
    """Verify model data tables are internally consistent."""

    def test_all_cost_models_have_limits(self):
        for model in MODEL_COSTS:
            assert model in MODEL_LIMITS, f"'{model}' in MODEL_COSTS but not MODEL_LIMITS"

    def test_all_limit_models_have_costs(self):
        for model in MODEL_LIMITS:
            assert model in MODEL_COSTS, f"'{model}' in MODEL_LIMITS but not MODEL_COSTS"

    def test_all_costs_have_input_and_output(self):
        for model, costs in MODEL_COSTS.items():
            assert "input" in costs, f"'{model}' missing 'input' cost"
            assert "output" in costs, f"'{model}' missing 'output' cost"

    def test_all_limits_have_context_and_output(self):
        for model, limits in MODEL_LIMITS.items():
            assert "max_context" in limits, f"'{model}' missing 'max_context'"
            assert "max_output" in limits, f"'{model}' missing 'max_output'"
