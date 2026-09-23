"""TCP loopback plane: pre-auth header deadline + connection cap.

The loopback listener has no peer-UID gate — any local UID connects —
and token validation happens only after headers parse. Tokenless
slow-header clients previously got the relay deadline (3600 s) as the
per-recv bound for the pre-auth header read, and ThreadingMixIn
spawned an uncapped daemon thread per accepted connection: an
unprivileged local user (or an in-sandbox process reaching a bridged
loopback) could wedge the credential dispatcher — and every LLM call
in the run — without ever presenting a token.
"""

from __future__ import annotations

import socket
import time

import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.server import LLMDispatcher


@pytest.fixture
def fake_creds() -> CredentialStore:
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "real-secret-anthropic-key-NOT-LEAKED",
        "openai": None,
        "gemini": None,
    }
    return creds


def _dispatcher(fake_creds, tmp_path) -> LLMDispatcher:
    return LLMDispatcher(
        run_id="tcp-hardening",
        creds=fake_creds,
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600,
        token_budget=100,
    )


def test_tokenless_slow_header_connection_is_closed(
    monkeypatch, fake_creds, tmp_path,
) -> None:
    """A connection that never completes its header block is closed at
    the pre-auth deadline — not held for the 3600 s relay deadline."""
    monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_PREAUTH_DEADLINE_S", "1")
    d = _dispatcher(fake_creds, tmp_path)
    try:
        port = d.enable_loopback_listener()
        conn = socket.create_connection(("127.0.0.1", port), timeout=10)
        try:
            conn.settimeout(8)
            start = time.monotonic()
            data = conn.recv(1)  # blocks until the server closes
            elapsed = time.monotonic() - start
            assert data == b"", "server must close the idle connection"
            assert elapsed < 6, (
                f"pre-auth close took {elapsed:.1f}s — deadline not applied"
            )
        finally:
            conn.close()
    finally:
        d.shutdown()


def test_partial_request_line_is_closed(
    monkeypatch, fake_creds, tmp_path,
) -> None:
    """Half a request line (classic slowloris) hits the same deadline."""
    monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_PREAUTH_DEADLINE_S", "1")
    d = _dispatcher(fake_creds, tmp_path)
    try:
        port = d.enable_loopback_listener()
        conn = socket.create_connection(("127.0.0.1", port), timeout=10)
        try:
            conn.sendall(b"POST /anthropic/v1/mes")  # never finishes
            conn.settimeout(8)
            data = conn.recv(4096)
            # Either an error response or a bare close — never a hang.
            assert data == b"" or b"HTTP/" in data
        finally:
            conn.close()
    finally:
        d.shutdown()


def test_tcp_connection_cap_refuses_over_cap(
    monkeypatch, fake_creds, tmp_path,
) -> None:
    """Connections beyond the cap are refused (closed) pre-thread; the
    in-cap connections stay open within the pre-auth window."""
    monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_TCP_MAX_CONNECTIONS", "4")
    d = _dispatcher(fake_creds, tmp_path)
    held: list[socket.socket] = []
    try:
        port = d.enable_loopback_listener()
        for _ in range(4):
            held.append(
                socket.create_connection(("127.0.0.1", port), timeout=5))
        # Give the accept loop a beat to hand all four to handlers.
        time.sleep(0.2)
        extra = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            extra.settimeout(5)
            assert extra.recv(1) == b"", (
                "over-cap connection must be refused, not queued"
            )
        finally:
            extra.close()
    finally:
        for conn in held:
            conn.close()
        d.shutdown()
