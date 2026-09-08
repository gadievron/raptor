"""Copilot CLI provider integration tests (no live model calls)."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from core.llm.config import ModelConfig
from core.llm.copilot_adapter import CopilotPromptResult
from core.llm.providers import (
    CopilotCLILLMProvider,
    StructuredResponse,
    create_provider,
)
from core.llm.tool_use.types import Message, TextBlock


@pytest.fixture(autouse=True)
def _clean_copilot_env(monkeypatch):
    for name in (
        "RAPTOR_COPILOT_MODEL_EXPLICIT",
        "RAPTOR_COPILOT_MAX_AI_CREDITS",
    ):
        monkeypatch.delenv(name, raising=False)


def _config(provider: str = "copilotcli") -> ModelConfig:
    return ModelConfig(
        provider=provider,
        model_name="gpt-5.6-sol",
        api_key=None,
        timeout=30,
        max_context=1_050_000,
        max_tokens=128_000,
    )


def _result(**overrides: Any) -> CopilotPromptResult:
    values = {
        "content": "answer",
        "model": "gpt-5.6-sol",
        "session_id": "session-1",
        "input_tokens": 100,
        "output_tokens": 20,
        "reasoning_tokens": 5,
        "cache_read_tokens": 10,
        "cache_write_tokens": 2,
        "estimated_cost_usd": 0.01,
        "duration_seconds": 0.5,
        "native_usage": {"premium_request_cost": 1},
        "attempted_models": ("gpt-5.6-sol",),
    }
    values.update(overrides)
    return CopilotPromptResult(**values)


def test_generate_returns_standard_response_and_tracks_usage(
    monkeypatch,
) -> None:
    import core.llm.copilot_adapter as adapter

    monkeypatch.setattr(
        adapter, "run_copilot_prompt", lambda config, prompt: _result(),
    )
    provider = CopilotCLILLMProvider(
        _config(), copilot_bin="/usr/bin/copilot",
    )

    response = provider.generate("prompt", system_prompt="system")

    assert response.content == "answer"
    assert response.provider == "copilotcli"
    assert response.tokens_used == 125
    assert response.input_tokens == 100
    assert response.output_tokens == 20
    assert response.thinking_tokens == 5
    assert response.cache_read_tokens == 10
    assert response.cache_write_tokens == 2
    assert response.cost == pytest.approx(0.01)
    assert response.resolved_model == "gpt-5.6-sol"
    assert response.native_usage == {"premium_request_cost": 1}
    assert response.attempted_models == ("gpt-5.6-sol",)
    assert provider.total_tokens == 125
    assert provider.total_input_tokens == 100
    assert provider.total_output_tokens == 20
    assert provider.total_thinking_tokens == 5
    assert provider.total_cache_read_tokens == 10
    assert provider.total_cache_write_tokens == 2
    assert provider.total_cost == pytest.approx(0.01)
    assert provider.call_count == 1
    assert provider.last_native_usage == {"premium_request_cost": 1}
    assert provider.last_attempted_models == ("gpt-5.6-sol",)


def test_generate_books_failed_call_usage_before_raising(monkeypatch) -> None:
    import core.llm.copilot_adapter as adapter

    monkeypatch.setattr(
        adapter,
        "run_copilot_prompt",
        lambda config, prompt: _result(error="permission denied"),
    )
    provider = CopilotCLILLMProvider(
        _config(), copilot_bin="/usr/bin/copilot",
    )

    with pytest.raises(RuntimeError, match="permission denied"):
        provider.generate("prompt")
    assert provider.call_count == 1
    assert provider.total_cost == pytest.approx(0.01)


def test_structured_response_uses_validated_json_fallback(
    monkeypatch,
) -> None:
    import core.llm.copilot_adapter as adapter
    import core.llm.providers as providers_mod

    captured: dict[str, Any] = {}

    class FakeValidated:
        def __init__(self, value):
            self.value = value

        @classmethod
        def model_validate(cls, value):
            assert isinstance(value.get("ok"), bool)
            return cls(value)

        def model_dump(self):
            return self.value

    def fake_run(config, prompt):
        captured["config"] = config
        captured["prompt"] = prompt
        return _result(content='{"ok": true}')

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    monkeypatch.setattr(
        providers_mod,
        "_dict_schema_to_pydantic",
        lambda schema: FakeValidated,
    )
    provider = CopilotCLILLMProvider(
        _config(), copilot_bin="/usr/bin/copilot",
    )
    response = provider.generate_structured(
        "prompt",
        {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
        },
        system_prompt="trusted",
    )

    assert response.result == {"ok": True}
    assert response.provider == "copilotcli"
    assert response.model == "gpt-5.6-sol"
    assert response.tokens_used == 125
    assert response.thinking_tokens == 5
    assert response.native_usage == {"premium_request_cost": 1}
    assert response.attempted_models == ("gpt-5.6-sol",)
    assert "Respond with JSON matching this schema" \
        in captured["config"].system_prompt
    assert provider.call_count == 1


def test_client_preserves_structured_fallback_metadata(tmp_path) -> None:
    from core.testing import install_provider, make_test_client

    class MetadataProvider:
        total_cost = 0.0
        total_tokens = 0
        total_input_tokens = 0
        total_output_tokens = 0
        total_thinking_tokens = 0
        total_cache_read_tokens = 0
        total_cache_write_tokens = 0

        def generate_structured(self, *args, **kwargs):
            self.total_cost += 0.25
            self.total_tokens += 150
            self.total_input_tokens += 100
            self.total_output_tokens += 20
            self.total_thinking_tokens += 30
            return StructuredResponse(
                result={"ok": True},
                raw='{"ok": true}',
                cost=0.25,
                tokens_used=150,
                model="gpt-5.3-codex",
                provider="copilotcli",
                input_tokens=100,
                output_tokens=20,
                thinking_tokens=30,
                native_usage={"premium_request_cost": 2},
                attempted_models=("gpt-5.6-sol", "gpt-5.3-codex"),
            )

    client = make_test_client(
        tmp_path,
        provider="copilotcli",
        enable_caching=True,
    )
    provider = MetadataProvider()
    install_provider(client, provider)
    schema = {
        "type": "object",
        "properties": {"ok": {"type": "boolean"}},
        "required": ["ok"],
    }

    response = client.generate_structured("prompt", schema)
    cached = client.generate_structured("prompt", schema)

    assert response.model == "gpt-5.3-codex"
    assert response.provider == "copilotcli"
    assert response.thinking_tokens == 30
    assert response.native_usage == {"premium_request_cost": 2}
    assert response.attempted_models == (
        "gpt-5.6-sol",
        "gpt-5.3-codex",
    )
    assert cached.cached is True
    assert cached.model == "gpt-5.3-codex"


def test_concurrent_structured_calls_keep_per_call_metadata(
    monkeypatch,
) -> None:
    import core.llm.copilot_adapter as adapter
    import core.llm.providers as providers_mod

    barrier = threading.Barrier(2)

    class FakeValidated:
        def __init__(self, value):
            self.value = value

        @classmethod
        def model_validate(cls, value):
            return cls(value)

        def model_dump(self):
            return self.value

    def fake_run(config, prompt):
        barrier.wait(timeout=5)
        suffix = prompt.rsplit("-", 1)[-1]
        return _result(
            content=f'{{"value": "{suffix}"}}',
            native_usage={"request": suffix},
            attempted_models=(f"model-{suffix}",),
        )

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    monkeypatch.setattr(
        providers_mod,
        "_dict_schema_to_pydantic",
        lambda schema: FakeValidated,
    )
    provider = CopilotCLILLMProvider(
        _config(),
        copilot_bin="/usr/bin/copilot",
    )
    schema = {
        "type": "object",
        "properties": {"value": {"type": "string"}},
        "required": ["value"],
    }

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(
            lambda prompt: provider.generate_structured(prompt, schema),
            ("prompt-one", "prompt-two"),
        ))

    by_value = {response.result["value"]: response for response in responses}
    assert by_value["one"].native_usage == {"request": "one"}
    assert by_value["one"].attempted_models == ("model-one",)
    assert by_value["two"].native_usage == {"request": "two"}
    assert by_value["two"].attempted_models == ("model-two",)


def test_automatic_fallback_and_explicit_model_state(monkeypatch) -> None:
    import core.llm.copilot_adapter as adapter

    seen = []

    def fake_run(config, prompt):
        seen.append(config)
        return _result()

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config(), copilot_bin="/usr/bin/copilot",
    )

    provider.generate("automatic")
    assert seen[-1].allow_model_fallback is True
    assert "gpt-5.3-codex" in seen[-1].fallback_models

    monkeypatch.setenv("RAPTOR_COPILOT_MODEL_EXPLICIT", "1")
    provider.generate("explicit")
    assert seen[-1].allow_model_fallback is False
    assert seen[-1].fallback_models == ()


def test_successful_fallback_model_is_pinned_for_later_calls(
    monkeypatch,
) -> None:
    import core.llm.copilot_adapter as adapter

    seen: list[tuple[str, tuple[str, ...]]] = []

    def fake_run(config, prompt):
        seen.append((config.model, config.fallback_models))
        return _result(model="gpt-5.3-codex")

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config(),
        copilot_bin="/usr/bin/copilot",
    )

    provider.generate("first")
    provider.generate("second")

    assert seen[0][0] == "gpt-5.6-sol"
    assert seen[0][1]
    assert seen[1] == ("gpt-5.3-codex", ())


def test_max_ai_credits_only_applied_when_explicit(monkeypatch) -> None:
    import core.llm.copilot_adapter as adapter

    seen = []

    def fake_run(config, prompt):
        seen.append(config)
        return _result()

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config(), copilot_bin="/usr/bin/copilot",
    )

    provider.generate("default")
    assert seen[-1].max_ai_credits is None

    monkeypatch.setenv("RAPTOR_COPILOT_MAX_AI_CREDITS", "7.5")
    provider.generate("env")
    assert seen[-1].max_ai_credits == pytest.approx(7.5)

    provider.generate("override", max_ai_credits=3.0)
    assert seen[-1].max_ai_credits == pytest.approx(3.0)


def test_sandbox_flag_is_forwarded(monkeypatch) -> None:
    import core.llm.copilot_adapter as adapter

    seen = []

    def fake_run(config, prompt):
        seen.append(config)
        return _result()

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config(), copilot_bin="/usr/bin/copilot",
    )

    provider.generate("sandboxed", sandbox=True)

    assert seen[-1].sandbox is True


def test_resumable_provider_passes_session_to_next_call(monkeypatch) -> None:
    import core.llm.copilot_adapter as adapter

    seen_sessions: list[str | None] = []
    seen_models: list[str] = []

    def fake_run(config, prompt):
        seen_sessions.append(config.session_id)
        seen_models.append(config.model)
        return _result(
            session_id="session-next",
            model="gpt-5.3-codex",
        )

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config("copilotcli-resumable"),
        copilot_bin="/usr/bin/copilot",
        resumable=True,
    )

    provider.generate("first")
    provider.generate("second")
    assert seen_sessions == [None, "session-next"]
    assert seen_models == ["gpt-5.6-sol", "gpt-5.3-codex"]


def test_resumable_provider_retries_rejected_session_fresh(
    monkeypatch,
) -> None:
    import core.llm.copilot_adapter as adapter

    seen: list[tuple[str, str | None]] = []

    def fake_run(config, prompt):
        seen.append((config.model, config.session_id))
        if config.session_id:
            return _result(
                model=config.model,
                session_id=None,
                error="session not found",
            )
        return _result(
            model=config.model,
            session_id="session-fresh",
        )

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config("copilotcli-resumable"),
        copilot_bin="/usr/bin/copilot",
        resumable=True,
    )
    provider._session_id = "session-stale"
    provider._session_model = "gpt-5.3-codex"

    response = provider.generate("retry")

    assert response.content == "answer"
    assert seen == [
        ("gpt-5.3-codex", "session-stale"),
        ("gpt-5.3-codex", None),
    ]
    assert provider._session_id == "session-fresh"
    assert provider._session_model == "gpt-5.3-codex"


def test_resumable_provider_serializes_concurrent_calls(monkeypatch) -> None:
    import core.llm.copilot_adapter as adapter

    guard = threading.Lock()
    active = 0
    max_active = 0

    def fake_run(config, prompt):
        nonlocal active, max_active
        with guard:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.05)
        with guard:
            active -= 1
        return _result(session_id="session-shared")

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config("copilotcli-resumable"),
        copilot_bin="/usr/bin/copilot",
        resumable=True,
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(provider.generate, ("one", "two")))

    assert max_active == 1


def test_stateless_provider_keeps_concurrent_calls_parallel(
    monkeypatch,
) -> None:
    import core.llm.copilot_adapter as adapter

    guard = threading.Lock()
    active = 0
    max_active = 0

    def fake_run(config, prompt):
        nonlocal active, max_active
        with guard:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.05)
        with guard:
            active -= 1
        return _result()

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config(),
        copilot_bin="/usr/bin/copilot",
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(provider.generate, ("one", "two")))

    assert max_active == 2


def test_resumable_tool_turn_sends_only_new_messages(monkeypatch) -> None:
    import core.llm.copilot_adapter as adapter

    prompts: list[str] = []
    sessions: list[str | None] = []

    def fake_run(config, prompt):
        prompts.append(prompt)
        sessions.append(config.session_id)
        return _result(content="ok", session_id="session-1")

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config("copilotcli-resumable"),
        copilot_bin="/usr/bin/copilot",
        resumable=True,
    )
    first = [Message(role="user", content=[TextBlock("first")])]
    provider.turn(first, [])
    second = [
        *first,
        Message(role="assistant", content=[TextBlock("ok")]),
        Message(role="user", content=[TextBlock("second")]),
    ]
    provider.turn(second, [])

    assert sessions == [None, "session-1"]
    assert "first" in prompts[0]
    assert "second" in prompts[1]
    assert "first" not in prompts[1]


def test_stale_resumable_tool_turn_retries_with_full_history(
    monkeypatch,
) -> None:
    import core.llm.copilot_adapter as adapter

    prompts: list[str] = []
    sessions: list[str | None] = []

    def fake_run(config, prompt):
        prompts.append(prompt)
        sessions.append(config.session_id)
        if len(prompts) == 2:
            return _result(
                content="",
                session_id=None,
                error="session not found",
            )
        return _result(content="ok", session_id="session-1")

    monkeypatch.setattr(adapter, "run_copilot_prompt", fake_run)
    provider = CopilotCLILLMProvider(
        _config("copilotcli-resumable"),
        copilot_bin="/usr/bin/copilot",
        resumable=True,
    )
    first = [Message(role="user", content=[TextBlock("first")])]
    provider.turn(first, [])
    second = [
        *first,
        Message(role="assistant", content=[TextBlock("ok")]),
        Message(role="user", content=[TextBlock("second")]),
    ]
    provider.turn(second, [])

    assert sessions == [None, "session-1", None]
    assert "first" not in prompts[1]
    assert "first" in prompts[2]
    assert "second" in prompts[2]


@pytest.mark.parametrize(
    "name",
    (
        "copilotcli",
        "copilot_cli",
        "copilot-cli",
        "copilotcli-resumable",
        "copilot_cli_resumable",
        "copilot-cli-resumable",
    ),
)
def test_factory_routes_copilot_aliases(monkeypatch, name: str) -> None:
    monkeypatch.setattr(
        "core.llm.copilot_adapter.resolve_copilot_cli",
        lambda explicit=None: "/usr/bin/copilot",
    )
    provider = create_provider(_config(name))
    assert isinstance(provider, CopilotCLILLMProvider)
    assert provider._resumable is name.replace("_", "-").endswith(
        "-resumable",
    )


def test_factory_rejects_non_selected_agent_cli(monkeypatch) -> None:
    monkeypatch.setenv("RAPTOR_AGENT_CLI", "copilot")

    with pytest.raises(RuntimeError, match="non-selected"):
        create_provider(ModelConfig(
            provider="claudecode",
            model_name="session-default",
        ))


def test_exported_from_core_llm_package() -> None:
    import core.llm

    assert core.llm.CopilotCLILLMProvider is CopilotCLILLMProvider
    assert "CopilotCLILLMProvider" in core.llm.__all__
    assert core.llm.CopilotPromptResult is CopilotPromptResult
    assert "CopilotDispatchConfig" in core.llm.__all__
    assert "CopilotPromptResult" in core.llm.__all__
    assert "configured_copilot_fallback_models" in core.llm.__all__
    assert "run_copilot_prompt" in core.llm.__all__
