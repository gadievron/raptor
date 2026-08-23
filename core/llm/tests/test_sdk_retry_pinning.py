"""SDK-internal retries are pinned off — RAPTOR's loops are the
single retry authority.

The anthropic/openai SDKs default to ``max_retries=2`` inside the
client. RAPTOR wraps every call in its own retry loop
(``LLMClient.generate`` / ``generate_structured``, the provider
``turn()`` transient-error loops), so the SDK default stacks
multiplicatively: a provider loop of 4 attempts each carrying 3 SDK
attempts is 12 upstream calls per logical call, each burning a full
read timeout during an upstream brownout. Every SDK client RAPTOR
constructs must therefore pin ``max_retries=0``.

Call paths that use the SDK client outside a RAPTOR retry loop and
their failure semantics:

* ``turn_stream()`` — no RAPTOR retry, but no production consumer
  enables loop streaming; a first-attempt transient error surfaces
  to callers that already classify provider errors.
* instructor reask — validation-driven re-asks; transport failures
  propagate to the ``generate_structured`` retry loop.
"""

from __future__ import annotations

import pytest

from core.llm.config import ModelConfig


class TestDirectSdkClients:
    def test_anthropic_direct_client_pins_zero_sdk_retries(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("anthropic")
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        from core.llm.providers import AnthropicProvider
        provider = AnthropicProvider(ModelConfig(
            provider="anthropic", model_name="claude-opus-4-6",
            api_key="test-key", timeout=1,
        ))
        assert provider.client.max_retries == 0

    def test_openai_direct_client_pins_zero_sdk_retries(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("openai")
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        from core.llm.providers import OpenAICompatibleProvider
        provider = OpenAICompatibleProvider(ModelConfig(
            provider="openai", model_name="gpt-test",
            api_key="test-key", timeout=1,
        ))
        assert provider.client.max_retries == 0


class TestDispatcherFactoryClients:
    """The dispatcher factories build the same SDK clients over the
    UDS transport — the stacking is identical (each SDK-internal
    retry rides the dispatcher's full upstream read timeout)."""

    def test_make_anthropic_client_pins_zero_sdk_retries(
        self, tmp_path,
    ) -> None:
        pytest.importorskip("anthropic")
        from core.llm.dispatcher.client import make_anthropic_client
        client = make_anthropic_client(
            socket_path=str(tmp_path / "sock"), token="test-token",
        )
        assert client.max_retries == 0

    def test_make_bedrock_client_pins_zero_sdk_retries(
        self, tmp_path,
    ) -> None:
        pytest.importorskip("anthropic")
        from core.llm.dispatcher.client import make_bedrock_client
        for api in ("mantle", "runtime"):
            client = make_bedrock_client(
                api=api, socket_path=str(tmp_path / "sock"),
                token="test-token",
            )
            assert client.max_retries == 0

    def test_make_openai_client_pins_zero_sdk_retries(
        self, tmp_path,
    ) -> None:
        pytest.importorskip("openai")
        from core.llm.dispatcher.client import make_openai_client
        client = make_openai_client(
            socket_path=str(tmp_path / "sock"), token="test-token",
        )
        assert client.max_retries == 0
