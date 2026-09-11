"""``core.llm.detection._host_is_local`` — loopback classification.

The classifier decides whether an OLLAMA host may appear unredacted in
logs, and it is invoked from INSIDE exception handlers (the Ollama
connection-error path), so it must never raise: a malformed
``OLLAMA_HOST`` would otherwise crash ``detect_llm_availability`` from
within its own error handling. Malformed values classify as NOT local
(redact — the safe direction).
"""

from __future__ import annotations

import pytest

from core.llm.detection import _host_is_local


class TestHostIsLocal:

    @pytest.mark.parametrize("raw", [
        "http://127.0.0.1:11434",
        "http://localhost:11434",
        "127.0.0.1:11434",
        "localhost",
        "http://[::1]:11434",
        "::1",
        "0.0.0.0:11434",
        "http://127.0.0.53:11434",   # full 127.0.0.0/8 range
    ])
    def test_valid_loopback_forms_classify_local(self, raw: str) -> None:
        assert _host_is_local(raw) is True

    @pytest.mark.parametrize("raw", [
        "http://ollama.internal.example:11434",
        "10.0.0.5:11434",
        "localhost.attacker.example",
        "127.0.0.1.evil",
    ])
    def test_remote_forms_classify_not_local(self, raw: str) -> None:
        assert _host_is_local(raw) is False

    @pytest.mark.parametrize("raw", [
        "http://[::1:11434",     # unbalanced IPv6 bracket — urlparse
                                 # raises "Invalid IPv6 URL" on it
        "http://[garbage:80",
        "[::1:11434",
    ])
    def test_malformed_value_is_not_local_and_never_raises(
        self, raw: str,
    ) -> None:
        # Fail safe: unparseable input must classify as NOT local
        # (gets redacted), never propagate an exception into the
        # caller's except-handler.
        assert _host_is_local(raw) is False
