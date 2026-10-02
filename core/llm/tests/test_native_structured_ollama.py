"""Native constrained decoding for Ollama (#972).

An Ollama primary must get schema-valid JSON via the server's native
``format=<schema>`` constrained decoding — not the slow/fragile
tool-calling instructor path or prompt-and-pray. Also covers the
per-call ``timeout_s`` that this provider used to drop, and ``<think>``
stripping before the JSON parse.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

pytest.importorskip("openai")
pytest.importorskip("pydantic")

from core.llm.config import ModelConfig
from core.llm.providers import (
    LLMProvider,
    LLMResponse,
    OpenAICompatibleProvider,
    _dict_schema_to_pydantic,
    _strip_think_blocks,
)

_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["clear_fp", "needs_analysis"]},
        "prerequisites": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "prerequisites"],
}


def _provider(provider_name: str) -> OpenAICompatibleProvider:
    p = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
    LLMProvider.__init__(p, ModelConfig(
        provider=provider_name, model_name="test-model", api_key="k",
        cost_per_1k_tokens=0.0,
    ))
    p._instructor_lock = threading.Lock()
    p._instructor_consec_failures = 0
    p._tool_use_unsupported = False
    p.instructor_client = None
    return p


def _wire_recording_generate(
    provider: OpenAICompatibleProvider, content: str = None,
) -> list[dict[str, Any]]:
    """Record kwargs passed to generate(); return a valid-JSON response."""
    calls: list[dict[str, Any]] = []
    body = content if content is not None else (
        '{"verdict": "needs_analysis", "prerequisites": ["a", "b"]}'
    )

    def generate(prompt, system_prompt=None, **kwargs):
        calls.append(dict(kwargs))
        return LLMResponse(
            content=body, model="test-model", provider=provider.config.provider,
            tokens_used=5, cost=0.0, finish_reason="complete",
        )

    provider.generate = generate  # type: ignore[method-assign]
    return calls


class TestOllamaNativeFormat:
    def test_ollama_emits_format_extra_body_and_skips_instructor(self):
        provider = _provider("ollama")
        # instructor_client must stay untouched — a mock that explodes if called.
        class _Boom:
            def __getattr__(self, _):
                raise AssertionError("instructor must not be called on native path")
        provider.instructor_client = _Boom()
        calls = _wire_recording_generate(provider)

        out = provider.generate_structured("p", _SCHEMA)

        assert out.result["verdict"] == "needs_analysis"
        assert out.result["prerequisites"] == ["a", "b"]
        # Native format schema was passed through extra_body.
        assert "extra_body" in calls[0]
        assert "format" in calls[0]["extra_body"]
        assert calls[0]["extra_body"]["format"]["type"] == "object"

    def test_non_ollama_does_not_use_native_format(self):
        # Two-direction guard: an openai-compat provider keeps the
        # instructor-first path and never emits format.
        provider = _provider("openai")
        calls = _wire_recording_generate(provider)  # instructor_client=None → fallback

        out = provider.generate_structured("p", _SCHEMA)

        assert out.result["verdict"] == "needs_analysis"
        assert all("extra_body" not in c for c in calls)

    def test_native_path_falls_through_on_bad_json(self):
        # Native call returns junk → native parse raises → falls through to
        # the JSON fallback, which re-sends via generate() and succeeds.
        provider = _provider("ollama")
        bodies = iter([
            "not json at all",  # native attempt
            '{"verdict": "clear_fp", "prerequisites": []}',  # fallback attempt
        ])
        calls: list[dict[str, Any]] = []

        def generate(prompt, system_prompt=None, **kwargs):
            calls.append(dict(kwargs))
            return LLMResponse(
                content=next(bodies), model="test-model", provider="ollama",
                tokens_used=5, cost=0.0, finish_reason="complete",
            )

        provider.generate = generate  # type: ignore[method-assign]
        out = provider.generate_structured("p", _SCHEMA)

        assert out.result["verdict"] == "clear_fp"
        # First call was the native attempt (extra_body set), second the
        # fallback (no extra_body).
        assert "extra_body" in calls[0]
        assert "extra_body" not in calls[1]


class TestStripThinkBlocks:
    def test_removes_paired_block(self):
        text = '<think>reasoning here\nmore</think>\n{"x": 1}'
        assert _strip_think_blocks(text) == '{"x": 1}'

    def test_removes_lone_trailing_closer(self):
        text = 'the model reasoned about it</think>{"x": 1}'
        assert _strip_think_blocks(text) == '{"x": 1}'

    def test_leaves_clean_text_untouched(self):
        assert _strip_think_blocks('{"x": 1}') == '{"x": 1}'

    def test_think_wrapped_json_parses_via_build(self):
        # The exact failure shape from the live log: a reasoning model
        # wrapping the JSON in a think block.
        provider = _provider("ollama")
        pyd = _dict_schema_to_pydantic(_SCHEMA)
        resp = LLMResponse(
            content=(
                '<think>Let me check the taint flow...</think>\n'
                '{"verdict": "needs_analysis", "prerequisites": ["x"]}'
            ),
            model="test-model", provider="ollama", tokens_used=5,
            cost=0.0, finish_reason="complete",
        )
        out = provider._build_structured_response(resp, _SCHEMA, pyd)
        assert out.result["verdict"] == "needs_analysis"


class TestGenerateTimeoutForwarding:
    def test_generate_forwards_timeout_s_to_sdk(self):
        provider = _provider("ollama")
        recorded: dict[str, Any] = {}

        class _Msg:
            content = '{"x": 1}'
            reasoning_content = ""
            refusal = None
        class _Choice:
            message = _Msg()
            finish_reason = "stop"
        class _Resp:
            choices = [_Choice()]
            usage = None
        class _Completions:
            def create(self, **kwargs):
                recorded.update(kwargs)
                return _Resp()
        class _Chat:
            completions = _Completions()
        class _Client:
            chat = _Chat()

        provider.client = _Client()
        provider.generate("p", None, timeout_s=42.0,
                          extra_body={"format": {"type": "object"}})

        assert recorded.get("timeout") == 42.0
        assert recorded.get("extra_body") == {"format": {"type": "object"}}
