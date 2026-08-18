"""Test 10: Verify Ollama warning for exploit PoC generation limitations."""

import logging
import os
import sys
from pathlib import Path

import pytest

# Add parent directories to path for imports
# packages/llm_analysis/tests/test_ollama_warning.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.config import RaptorConfig
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


def _skip_unless_ollama_available():
    """Probe Ollama via loopback_safe_get, NOT plain requests.get.

    Plain requests honours the proxy env; on mandatory-proxy hosts
    whose NO_PROXY misses loopback, every suite run sent
    GET http://localhost:11434/api/tags THROUGH the egress proxy —
    recurring (denied) entries in the proxy log, and the probe could
    never succeed there even with Ollama up, so these tests silently
    always skipped. Same fix as core/llm/detection.py.
    """
    from core.llm.egress import loopback_safe_get
    try:
        response = loopback_safe_get(
            f"{RaptorConfig.OLLAMA_HOST}/api/tags", timeout=2,
        )
        if response.status_code != 200:
            pytest.skip("Ollama not available")
    except Exception:  # noqa: BLE001 — any probe failure means "not available"
        pytest.skip("Ollama not available")



@pytest.fixture(autouse=True)
def _attach_caplog_to_raptor_logger(caplog):
    """RaptorLogger sets propagate=False, so caplog (attached to root) misses
    its records. Attach caplog's handler directly to the 'raptor' logger for
    the duration of each test in this module."""
    raptor_logger = logging.getLogger("raptor")
    raptor_logger.addHandler(caplog.handler)
    try:
        yield
    finally:
        raptor_logger.removeHandler(caplog.handler)


class TestOllamaWarning:
    """Test 10: Verify warning appears when using Ollama for exploit generation."""

    def test_ollama_warning_on_init(self, caplog):
        """Test warning appears when LLMClient initialized with Ollama model."""
        _skip_unless_ollama_available()

        caplog.set_level(logging.WARNING)

        config = LLMConfig()
        config.primary_model = ModelConfig(
            provider="ollama",
            model_name="mistral",
            api_base=RaptorConfig.OLLAMA_HOST,
        )

        LLMClient(config)

        ollama_warnings = [
            record for record in caplog.records
            if record.levelname == "WARNING" and "ollama" in record.message.lower()
        ]
        assert ollama_warnings, "Expected an Ollama warning at LLMClient init"

    def test_ollama_warning_message_content(self, caplog):
        """Test warning message contains specific guidance."""
        _skip_unless_ollama_available()

        caplog.set_level(logging.WARNING)

        config = LLMConfig()
        config.primary_model = ModelConfig(
            provider="ollama",
            model_name="mistral",
            api_base=RaptorConfig.OLLAMA_HOST
        )

        LLMClient(config)

        # Find Ollama warning
        ollama_warnings = [
            record.message for record in caplog.records
            if record.levelname == "WARNING" and "ollama" in record.message.lower()
        ]

        if ollama_warnings:
            warning = ollama_warnings[0].lower()

            # Should mention local models
            assert "local" in warning or "ollama" in warning, \
                "Warning should mention local models or Ollama"

            # Should mention exploit/PoC limitations
            assert ("exploit" in warning or "poc" in warning), \
                "Warning should mention exploit or PoC limitations"

            # Should suggest using cloud models
            has_suggestion = any(
                keyword in warning
                for keyword in ["cloud", "api", "anthropic", "openai", "remote"]
            )
            assert has_suggestion, \
                "Warning should suggest using cloud/API models"

            print(f"\n✅ Warning content validated: {warning}")

    def test_no_warning_for_cloud_providers(self, caplog):
        """Test no warning for cloud providers (OpenAI, Anthropic, Gemini)."""
        # Test with OpenAI if available
        if not os.getenv("OPENAI_API_KEY"):
            pytest.skip("No OPENAI_API_KEY - skipping cloud provider test")

        caplog.set_level(logging.WARNING)

        config = LLMConfig()
        config.primary_model = ModelConfig(
            provider="openai",
            model_name="gpt-4o-mini"
        )

        LLMClient(config)

        # Check for Ollama warnings (should be none)
        ollama_warnings = [
            record.message for record in caplog.records
            if record.levelname == "WARNING"
            and "ollama" in record.message.lower()
            and "exploit" in record.message.lower()
        ]

        assert len(ollama_warnings) == 0, \
            "Should not warn about Ollama when using cloud providers"
        print("\n✅ No Ollama warning for cloud provider (correct)")

    def test_warning_appears_once(self, caplog):
        """Test warning appears only once per client initialization."""
        _skip_unless_ollama_available()

        caplog.set_level(logging.WARNING)

        config = LLMConfig()
        config.primary_model = ModelConfig(
            provider="ollama",
            model_name="mistral",
            api_base=RaptorConfig.OLLAMA_HOST,
        )

        LLMClient(config)

        ollama_warnings = [
            record for record in caplog.records
            if record.levelname == "WARNING" and "ollama" in record.message.lower()
        ]
        assert len(ollama_warnings) == 1, (
            f"Expected exactly one Ollama warning per client init, got {len(ollama_warnings)}"
        )

    def test_warning_format(self, caplog):
        """Test warning uses proper logging format."""
        _skip_unless_ollama_available()

        caplog.set_level(logging.WARNING)

        config = LLMConfig()
        config.primary_model = ModelConfig(
            provider="ollama",
            model_name="mistral",
            api_base=RaptorConfig.OLLAMA_HOST
        )

        LLMClient(config)

        # Find Ollama warning
        ollama_warnings = [
            record for record in caplog.records
            if record.levelname == "WARNING"
            and "ollama" in record.message.lower()
            and ("exploit" in record.message.lower() or "poc" in record.message.lower())
        ]

        if ollama_warnings:
            warning = ollama_warnings[0]

            # Check it's actually a WARNING level
            assert warning.levelname == "WARNING", "Should use WARNING level"

            # Check it has a message
            assert len(warning.message) > 0, "Warning should have content"

            # Check it's from the right logger
            assert "llm" in warning.name.lower() or "raptor" in warning.name.lower(), \
                f"Warning should come from LLM logger, got: {warning.name}"

            print(f"\n✅ Warning format correct: {warning.levelname} from {warning.name}")
