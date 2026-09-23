"""Ollama precision-caveat warnings — hermetic pins for all three sites.

The constructor warning and the two dispatch-lane warnings are emitted
from hand-built ModelConfigs with no live Ollama server involved, so
no test here probes one: a live-server skip gate made every pin in
this file CI-invisible — reverting the entire warning set passed the
suite (each test skipped). All assertions run unconditionally.
"""

import logging
import sys
from pathlib import Path
from typing import Any

import pytest

# core/llm/tests/test_ollama_warning.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.config import RaptorConfig
from core.llm.client import _OLLAMA_PRECISION_WARNING, LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse


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


def _ollama_config() -> LLMConfig:
    return LLMConfig(
        primary_model=ModelConfig(
            provider="ollama",
            model_name="mistral",
            api_base=RaptorConfig.OLLAMA_HOST,
        ),
        enable_caching=False,
        enable_fallback=False,
        max_retries=1,
    )


def _ollama_warnings(caplog) -> list[str]:
    return [
        record.message for record in caplog.records
        if record.levelname == "WARNING"
        and ("ollama" in record.message.lower()
             or "local model" in record.message.lower())
    ]


class _StubProvider:
    """Scripted provider — no network, numeric counters for deltas."""

    def __init__(self) -> None:
        self.total_cost = 0.0
        self.total_tokens = 0

    def generate(self, prompt: str, system_prompt: str | None = None,
                 **kw: Any) -> LLMResponse:
        return LLMResponse(
            content="ok", model="mistral", provider="ollama",
            tokens_used=1, cost=0.0, finish_reason="stop",
        )

    def generate_structured(
        self, prompt: str, schema: dict[str, Any],
        system_prompt: str | None = None, **kw: Any,
    ) -> tuple[dict[str, Any], str]:
        return {"x": "ok"}, "raw"


class TestOllamaWarning:
    """Warning appears when LLMClient is built with an Ollama primary."""

    def test_ollama_warning_on_init(self, caplog):
        caplog.set_level(logging.WARNING)
        LLMClient(_ollama_config())
        assert _ollama_warnings(caplog), (
            "Expected an Ollama warning at LLMClient init"
        )

    def test_ollama_warning_message_content(self, caplog):
        caplog.set_level(logging.WARNING)
        LLMClient(_ollama_config())

        warnings = _ollama_warnings(caplog)
        assert warnings, "Expected an Ollama warning at LLMClient init"
        warning = warnings[0].lower()

        # Should mention local models
        assert "local" in warning or "ollama" in warning

        # Should mention exploit/PoC limitations
        assert "exploit" in warning or "poc" in warning

        # Should point at the scorecard for a measured, per-model answer
        # rather than assuming reliability from provider name alone —
        # capability tracks model scale/quantization, not the Ollama
        # transport itself.
        assert any(k in warning for k in ("scorecard", "measured")), (
            "Warning should point to /scorecard for measured "
            "reliability data"
        )

    def test_no_warning_for_cloud_providers(self, caplog):
        caplog.set_level(logging.WARNING)
        LLMClient(LLMConfig(
            primary_model=ModelConfig(
                provider="openai", model_name="gpt-4o-mini", api_key="k",
            ),
            enable_caching=False,
        ))
        assert _ollama_warnings(caplog) == [], (
            "Should not warn about Ollama when using cloud providers"
        )

    def test_warning_appears_once(self, caplog):
        caplog.set_level(logging.WARNING)
        LLMClient(_ollama_config())
        assert len(_ollama_warnings(caplog)) == 1

    def test_warning_format(self, caplog):
        caplog.set_level(logging.WARNING)
        LLMClient(_ollama_config())
        records = [
            record for record in caplog.records
            if record.levelname == "WARNING"
            and "ollama" in record.message.lower()
        ]
        assert records, "Expected an Ollama warning at LLMClient init"
        warning = records[0]
        assert warning.levelname == "WARNING"
        assert len(warning.message) > 0
        assert (
            "llm" in warning.name.lower() or "raptor" in warning.name.lower()
        ), f"Warning should come from LLM logger, got: {warning.name}"


class TestOllamaFallbackLaneWarning:
    """The per-dispatch precision caveat fires on BOTH loops — the two
    sites share one constant so they cannot drift."""

    def test_constant_content(self):
        text = _OLLAMA_PRECISION_WARNING.lower()
        assert "local" in text
        assert "exploit" in text or "poc" in text
        assert "scorecard" in text

    @pytest.mark.parametrize("call", ["generate", "generate_structured"])
    def test_dispatch_lane_emits_caveat(self, caplog, call):
        caplog.set_level(logging.WARNING)
        client = LLMClient(_ollama_config())
        client._get_provider = (  # type: ignore[method-assign]
            lambda model_config: _StubProvider()
        )
        caplog.clear()  # drop the constructor-time warning
        if call == "generate":
            client.generate("test prompt")
        else:
            client.generate_structured(
                "test prompt",
                {"type": "object",
                 "properties": {"x": {"type": "string"}}},
            )
        emitted = [
            record.message for record in caplog.records
            if record.levelname == "WARNING"
        ]
        assert _OLLAMA_PRECISION_WARNING in emitted, (
            f"{call} must emit the shared precision caveat, got: {emitted}"
        )
