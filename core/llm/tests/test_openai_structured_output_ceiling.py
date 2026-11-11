"""OpenAI structured generation honours the caller's output ceiling."""
from types import SimpleNamespace

import pytest

from core.llm.config import ModelConfig
from core.llm.providers import OpenAICompatibleProvider


@pytest.mark.parametrize("model,limit_key,other_key", [
    ("classic-stub", "max_tokens", "max_completion_tokens"),
    ("gpt-5-ceiling-stub", "max_completion_tokens", "max_tokens"),
])
@pytest.mark.parametrize("override,expected", [(1234, 1234), (None, 128000)],
                         ids=["lower-caller-ceiling", "configured-default"])
def test_instructor_uses_the_requested_output_ceiling(monkeypatch, model, limit_key,
                                                     other_key, override, expected):
    config = ModelConfig(provider="openai", model_name=model, api_key="inert",
                         max_tokens=128000)
    provider = OpenAICompatibleProvider(config)
    captured = []

    def scripted(**kwargs):
        captured.append(kwargs)
        result = kwargs["response_model"].model_validate({"x": "captured"})
        completion = SimpleNamespace(model=model, usage=SimpleNamespace(
            prompt_tokens=3, completion_tokens=2, completion_tokens_details=None,
            prompt_tokens_details=None))
        return result, completion

    provider.instructor_client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create_with_completion=scripted)))
    call_kwargs = {"temperature": 0.2, "_governed_single_attempt": True}
    if override is not None:
        call_kwargs["max_tokens"] = override
    result = provider.generate_structured("captured", {
        "type": "object", "properties": {"x": {"type": "string"}},
        "required": ["x"],
    }, **call_kwargs)

    assert result.result == {"x": "captured"}
    assert len(captured) == 1
    actual = captured[0]
    assert actual[limit_key] == expected
    assert other_key not in actual
    assert actual["model"] == model
    assert actual["messages"] == [{"role": "user", "content": "captured"}]
    assert actual["max_retries"] == 1
    if limit_key == "max_completion_tokens":
        assert "temperature" not in actual
    else:
        assert actual["temperature"] == 0.2
    assert config.max_tokens == 128000
