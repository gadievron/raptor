"""Upstream-relay bounds — cumulative byte cap and total deadline.

Pre-fix the relay loop drained ``iter_raw()`` to EOF with only
per-read timeouts: a fire-hosing upstream streamed unbounded bytes
through the handler thread, and a drip-feeding upstream held the
thread and connection slot indefinitely. Hermetic — captive loopback
upstream, no LLM, no network.
"""

from __future__ import annotations

import http.server
import json
import os
import threading
import time

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import (
    _TOKEN_HEADER,
    LLMDispatcher,
    RelayLimitExceeded,
)


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "fake-anthropic-key",
        "openai": None,
        "gemini": None,
    }
    return creds


class _Upstream:
    """Captive provider stub. ``mode``:

    * ``"firehose"``     — 64 KiB JSON body, sent at once.
    * ``"sse_firehose"`` — 64 KiB of well-formed SSE events, at once.
    * ``"drip"``         — one small chunk every 0.3s for ~6s.
    """

    def __init__(self, mode: str):
        outer = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                if outer.mode in ("firehose", "sse_firehose"):
                    if outer.mode == "firehose":
                        payload = b"x" * (64 * 1024)
                        ctype = "application/json"
                    else:
                        event = (
                            b'data: {"type":"content_block_delta",'
                            b'"delta":{"type":"text_delta",'
                            b'"text":"xxxx"}}\n\n'
                        )
                        payload = event * 800  # ~64 KiB of valid SSE
                        ctype = "text/event-stream"
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    # Flushed pieces so the relay observes multiple
                    # chunks: some body bytes reach the client BEFORE
                    # the byte cap aborts the stream.
                    try:
                        for i in range(0, len(payload), 2048):
                            self.wfile.write(payload[i:i + 2048])
                            self.wfile.flush()
                            time.sleep(0.005)
                    except OSError:
                        pass
                    return
                # drip
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(20 * 64))
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b"d" * 64)
                        self.wfile.flush()
                        time.sleep(0.3)
                except OSError:
                    return

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        self.mode = mode
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


def _make_dispatcher(fake_creds, tmp_path, upstream):
    d = LLMDispatcher(
        run_id="relay-limits", creds=fake_creds,
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600, token_budget=100,
    )
    original = d._rules["anthropic"]
    d._rules["anthropic"] = ProviderRule(
        name=original.name,
        upstream_base_url=upstream.base_url,
        inject_headers=original.inject_headers,
        strip_request_headers=original.strip_request_headers,
    )
    return d


def _worker_token(d: LLMDispatcher) -> str:
    _, fd = d.allocate_worker(label="test-worker")
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    return token


def _post(d: LLMDispatcher, token: str) -> bytes:
    """POST through the dispatcher; return whatever body bytes arrive
    before the relay ends (normally or aborted)."""
    transport = httpx.HTTPTransport(uds=str(d.socket_path))
    received = b""
    try:
        with httpx.Client(transport=transport, timeout=30.0) as client:
            with client.stream(
                "POST", "http://_/anthropic/v1/messages",
                headers={_TOKEN_HEADER: token},
                content=json.dumps({"model": "m", "messages": []}),
            ) as resp:
                for chunk in resp.iter_raw():
                    received += chunk
    except httpx.HTTPError:
        # An aborted relay tears the connection mid-body.
        pass
    return received


def _wait_relay_abort(d: LLMDispatcher, timeout: float = 5.0) -> bool:
    """True when a request.error audit row names RelayLimitExceeded."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            text = d._audit_path.read_text()
        except OSError:
            text = ""
        if RelayLimitExceeded.__name__ in text:
            return True
        time.sleep(0.05)
    return False


class TestRelayLimits:

    def test_byte_cap_aborts_firehose_upstream(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv(
            "RAPTOR_LLM_DISPATCHER_RELAY_MAX_BYTES", "4096",
        )
        upstream = _Upstream("firehose")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            received = _post(d, token)
            # The relay stopped within a chunk of the cap instead of
            # forwarding all 64 KiB.
            assert len(received) < 64 * 1024
            assert _wait_relay_abort(d)
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_cap_abort_mid_sse_emits_terminal_error_event(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """Cap-abort after a 200 + partial SSE body must NOT write a
        second HTTP message into the open body (pre-fix an
        ``HTTP/1.0 502`` landed there and SSE consumers parsed it as
        event data — silent truncation dressed as success). The
        stream must end with a well-formed terminal SSE error event
        naming the abort reason, then close."""
        monkeypatch.setenv(
            "RAPTOR_LLM_DISPATCHER_RELAY_MAX_BYTES", "4096",
        )
        upstream = _Upstream("sse_firehose")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            received = _post(d, token)
            # The 200 + partial body had been sent before the abort.
            assert received
            assert b"HTTP/1.0" not in received
            assert b"HTTP/1.1" not in received
            # Terminal typed error event, at the tail of the stream.
            assert b"event: error" in received[-512:]
            assert b"relay cap" in received[-512:]
            assert received.endswith(b"\n\n")
            # Audit row still records the abort.
            assert _wait_relay_abort(d)
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_cap_abort_mid_json_closes_without_http_error_message(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """Non-SSE mid-body abort: nothing more is written — no
        second HTTP message, no SSE frame — so the consumer sees a
        short body / dropped connection (a transport error), never a
        truncated-but-apparently-successful payload."""
        monkeypatch.setenv(
            "RAPTOR_LLM_DISPATCHER_RELAY_MAX_BYTES", "4096",
        )
        upstream = _Upstream("firehose")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            received = _post(d, token)
            assert received
            assert b"HTTP/1.0" not in received
            assert b"event: error" not in received
            assert set(received) == {ord("x")}  # body bytes only
            assert _wait_relay_abort(d)
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_total_deadline_aborts_drip_upstream(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv(
            "RAPTOR_LLM_DISPATCHER_RELAY_DEADLINE_S", "1",
        )
        upstream = _Upstream("drip")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            start = time.monotonic()
            _post(d, token)
            elapsed = time.monotonic() - start
            # Pre-fix the relay followed the drip to its end (~6s);
            # the 1s total deadline must cut it well short.
            assert elapsed < 4.0
            assert _wait_relay_abort(d)
        finally:
            upstream.shutdown()
            d.shutdown()
