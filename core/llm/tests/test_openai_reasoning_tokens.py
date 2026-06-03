"""Unit tests for the OpenAI reasoning-model token/temperature contract.

gpt-5.x and the o1/o3/o4 families reject the legacy ``max_tokens`` param
(require ``max_completion_tokens``) and only accept the default
``temperature``. These tests pin the classifier + kwargs builder so the
provider never regresses to sending the wrong params (which 400s every
gpt-5.x call). See core/llm/providers.py.
"""
import os
import sys

sys.path.insert(0, os.environ.get("RAPTOR_DIR", os.getcwd()))

from core.llm.providers import (  # noqa: E402
    _is_openai_reasoning_model,
    _openai_sampling_kwargs,
)


def test_reasoning_models_detected():
    for m in ("gpt-5", "gpt-5.4", "gpt-5.5", "gpt-5.5-pro",
              "openai/gpt-5.5", "o1", "o3-mini", "o4-mini"):
        assert _is_openai_reasoning_model(m), m


def test_classic_models_not_detected():
    for m in ("gpt-4.1", "gpt-4o", "gpt-4o-mini", "gpt-4-turbo",
              "claude-opus-4-8", "qwen3", "", None):
        assert not _is_openai_reasoning_model(m), m


def test_reasoning_kwargs_use_max_completion_tokens_and_drop_temperature():
    kw = _openai_sampling_kwargs("gpt-5.5", 1234, temperature=0.7)
    assert kw == {"max_completion_tokens": 1234}
    assert "max_tokens" not in kw
    assert "temperature" not in kw


def test_classic_kwargs_keep_legacy_params():
    kw = _openai_sampling_kwargs("gpt-4o", 1234, temperature=0.7)
    assert kw == {"max_tokens": 1234, "temperature": 0.7}


def test_classic_kwargs_omit_temperature_when_none():
    kw = _openai_sampling_kwargs("gpt-4o", 999, temperature=None)
    assert kw == {"max_tokens": 999}


if __name__ == "__main__":
    test_reasoning_models_detected()
    test_classic_models_not_detected()
    test_reasoning_kwargs_use_max_completion_tokens_and_drop_temperature()
    test_classic_kwargs_keep_legacy_params()
    test_classic_kwargs_omit_temperature_when_none()
    print("all reasoning-token tests passed")
