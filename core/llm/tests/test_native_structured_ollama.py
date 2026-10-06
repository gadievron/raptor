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
    def test_ollama_emits_response_format_and_think_false_and_skips_instructor(self):
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
        # Native path passes the OpenAI json_schema response_format...
        rf = calls[0]["response_format"]
        assert rf["type"] == "json_schema"
        assert rf["json_schema"]["schema"]["type"] == "object"
        # ...AND think:false (critical for reasoning models — otherwise they
        # think the budget away and return empty content).
        assert calls[0]["extra_body"] == {"think": False}

    def test_non_ollama_does_not_use_native_format(self):
        # Two-direction guard: an openai-compat provider keeps the
        # instructor-first path and never emits response_format/think.
        provider = _provider("openai")
        calls = _wire_recording_generate(provider)  # instructor_client=None → fallback

        out = provider.generate_structured("p", _SCHEMA)

        assert out.result["verdict"] == "needs_analysis"
        assert all("response_format" not in c for c in calls)
        assert all("extra_body" not in c for c in calls)

    def test_native_path_falls_through_on_validation_failure(self):
        # Native call returns valid JSON that doesn't match the schema →
        # Pydantic raises → falls through to JSON fallback.
        provider = _provider("ollama")
        bodies = iter([
            '{"wrong_field": true}',  # native: valid JSON, bad schema
            '{"verdict": "clear_fp", "prerequisites": []}',  # fallback
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
        assert "response_format" in calls[0]
        assert "response_format" not in calls[1]

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
        # First call was the native attempt (response_format set), second the
        # fallback (no response_format).
        assert "response_format" in calls[0]
        assert "response_format" not in calls[1]


class TestStripThinkBlocks:
    def test_removes_paired_block(self):
        text = '<think>reasoning here\nmore</think>\n{"x": 1}'
        assert _strip_think_blocks(text) == '{"x": 1}'

    def test_removes_lone_trailing_closer(self):
        text = 'the model reasoned about it</think>{"x": 1}'
        assert _strip_think_blocks(text) == '{"x": 1}'

    def test_removes_multiple_paired_blocks(self):
        text = '<think>a</think>middle<think>b</think>{"x": 1}'
        assert _strip_think_blocks(text) == 'middle{"x": 1}'

    def test_closer_inside_json_string_not_corrupted(self):
        text = '{"reasoning": "checked </think> and found it"}'
        assert _strip_think_blocks(text) == text

    def test_paired_block_inside_json_string_survives_via_build(self):
        # A JSON value containing <think>…</think> must not be corrupted.
        # _build_structured_response tries json.loads first; valid JSON
        # skips _strip_think_blocks entirely.
        provider = _provider("ollama")
        pyd = _dict_schema_to_pydantic(_SCHEMA)
        resp = LLMResponse(
            content='{"verdict": "needs_analysis", '
                    '"prerequisites": ["saw <think>x</think> in output"]}',
            model="test-model", provider="ollama", tokens_used=5,
            cost=0.0, finish_reason="complete",
        )
        out = provider._build_structured_response(resp, _SCHEMA, pyd)
        assert out.result["prerequisites"] == [
            "saw <think>x</think> in output",
        ]

    def test_think_tags_inside_json_survive_structured_fallback(self):
        # Regression: _structured_fallback calls generate(), which used to
        # strip think blocks unconditionally. That corrupted JSON values
        # containing <think>…</think> before the parse-first guard in
        # _build_structured_response could protect them.
        provider = _provider("openai")
        body = (
            '{"verdict": "needs_analysis", '
            '"prerequisites": ["saw <think>x</think> in output"]}'
        )
        calls = _wire_recording_generate(provider, content=body)

        out = provider.generate_structured("p", _SCHEMA)

        assert out.result["prerequisites"] == [
            "saw <think>x</think> in output",
        ]
        assert calls[0].get("_raw_think_blocks") is True

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
        provider.generate(
            "p", None, timeout_s=42.0,
            response_format={"type": "json_schema",
                             "json_schema": {"name": "v", "schema": {"type": "object"}}},
            extra_body={"think": False},
        )

        assert recorded.get("timeout") == 42.0
        assert recorded.get("extra_body") == {"think": False}
        assert recorded.get("response_format")["type"] == "json_schema"

    def test_none_timeout_not_forwarded(self):
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
        provider.generate("p", None, timeout_s=None)

        assert "timeout" not in recorded
