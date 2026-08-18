"""``make_gemini_base_url`` must honour a per-model timeout.

The Anthropic/OpenAI/Bedrock factories all accept and forward
``timeout=`` to the underlying httpx client, but the Gemini factory
built its client without one — dispatcher-routed Gemini calls were
pinned to the 60s httpx default regardless of ``config.timeout``
(thinking calls routinely exceed 60s).
"""

from __future__ import annotations

from core.llm.dispatcher.client import make_gemini_base_url


def test_timeout_flows_to_httpx_client():
    base_url, http = make_gemini_base_url(
        socket_path="/tmp/nonexistent-test.sock",
        token="test-token",
        timeout=300.0,
    )
    try:
        assert base_url == "http://_/gemini"
        assert http.timeout.read == 300.0
    finally:
        http.close()


def test_default_timeout_unchanged():
    _, http = make_gemini_base_url(
        socket_path="/tmp/nonexistent-test.sock",
        token="test-token",
    )
    try:
        assert http.timeout.read == 60.0
    finally:
        http.close()
