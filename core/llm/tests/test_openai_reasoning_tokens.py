"""Unit tests for the OpenAI reasoning-model token/temperature contract.

gpt-5.x and the o1/o3/o4 families reject the legacy ``max_tokens`` param
(require ``max_completion_tokens``) and only accept the default
``temperature``. These tests pin the classifier + kwargs builder so the
provider never regresses to sending the wrong params (which 400s every
gpt-5.x call). See core/llm/providers.py.
"""
import sys
from pathlib import Path

# core/llm/tests/test_openai_reasoning_tokens.py -> parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

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


def test_future_reasoning_models_detected_by_version():
    # gpt-6+/o5+ don't exist yet but must be treated as reasoning when they
    # ship — detection is version-gated, not a literal name list.
    for m in ("gpt-6", "gpt-6-mini", "gpt-10", "openai/gpt-6",
              "o5", "o5-pro", "o6-mini"):
        assert _is_openai_reasoning_model(m), m


def test_non_reasoning_o_prefix_names_not_detected():
    # Names that merely start with 'o' but aren't o-series reasoning models.
    for m in ("olmo", "olmo-2", "orca-2", "openchat"):
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
    test_future_reasoning_models_detected_by_version()
    test_non_reasoning_o_prefix_names_not_detected()
    test_reasoning_kwargs_use_max_completion_tokens_and_drop_temperature()
    test_classic_kwargs_keep_legacy_params()
    test_classic_kwargs_omit_temperature_when_none()
    print("all reasoning-token tests passed")
