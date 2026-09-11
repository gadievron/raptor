"""Handler-plane hardening — status-line safety, peer-UID width,
client-leg socket timeout.

Hermetic — captive loopback upstream, fake sockets, no LLM.
"""

from __future__ import annotations

import http.server
import json
import struct
import sys
import threading
import time

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import LLMDispatcher, _peer_uid

_PRICED_MODEL = "claude-opus-4-8"


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "fake-anthropic-key",
        "openai": None,
        "gemini": None,
    }
    return creds


class TestStatusLineSafety:
    """_send_simple must never place caller-composed text in the HTTP
    status line — the detail rides only in the JSON body."""

    def _reject_with_model(self, fake_creds, tmp_path, model: str):
        d = LLMDispatcher(
            run_id="statusline", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=100,
        )
        try:
            token, _info = d.allocate_child(
                "cc-line", budget_usd=1.0, models=[_PRICED_MODEL],
            )
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            with httpx.Client(transport=transport, timeout=10.0) as client:
                return client.post(
                    "http://_/anthropic/v1/messages",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    content=json.dumps({
                        "model": model, "max_tokens": 10, "messages": [],
                    }).encode(),
                )
        finally:
            d.shutdown()

    def test_crlf_and_nonlatin1_model_gets_clean_403(
        self, fake_creds, tmp_path,
    ):
        # The allowlist-reject reason embeds the request body's model
        # verbatim. A CR/LF + non-latin1 model must yield a clean 403
        # with the DEFAULT phrase (pre-fix: UnicodeEncodeError killed
        # the request with no response, and raw CR/LF split the
        # status line — response splitting toward the sender).
        model = 'bad\r\nX-Injected: 1\r\n\r\nHTTP/1.0 200 OK 中文'
        resp = self._reject_with_model(fake_creds, tmp_path, model)
        assert resp.status_code == 403
        assert resp.reason_phrase == "Forbidden"
        assert "x-injected" not in {k.lower() for k in resp.headers}
        # The detail (including the hostile model) rides in the JSON
        # body, where encoding escapes it.
        assert "not in allowlist" in resp.json()["error"]

    def test_plain_reject_reason_still_in_body(self, fake_creds, tmp_path):
        # Opposite direction: ordinary rejections keep their
        # actionable detail in the body.
        resp = self._reject_with_model(fake_creds, tmp_path, "other-model")
        assert resp.status_code == 403
        assert "other-model" in resp.json()["error"]


@pytest.mark.skipif(sys.platform != "linux", reason="SO_PEERCRED is Linux-only")
class TestPeerUidUnsigned:
    """struct ucred is pid_t/uid_t/gid_t — uid/gid UNSIGNED. uids >=
    2^31 (nobody=4294967294 on some distros, container idmap offsets)
    must round-trip, or every peer on such a host is rejected."""

    class _FakeConn:
        def __init__(self, payload: bytes):
            self._payload = payload

        def getsockopt(self, _level, _opt, buflen):
            return self._payload[:buflen]

    def test_high_uid_unpacks_unsigned(self):
        conn = self._FakeConn(struct.pack("iII", 1234, 4294967294, 1000))
        assert _peer_uid(conn) == 4294967294

    def test_ordinary_uid_unchanged(self):
        conn = self._FakeConn(struct.pack("iII", 1234, 1000, 1000))
        assert _peer_uid(conn) == 1000


class _SlowDrainUpstream:
    """SSE upstream that fire-hoses several MiB immediately — enough
    to overrun the UDS socket buffers so the dispatcher's client-leg
    write blocks when the client stops reading."""

    def __init__(self):
        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                start = (
                    b'event: message_start\n'
                    b'data: {"type":"message_start","message":{"model":"'
                    + _PRICED_MODEL.encode() +
                    b'","usage":{"input_tokens":1000,"output_tokens":1}}}\n\n'
                )
                filler = (
                    b'event: content_block_delta\n'
                    b'data: {"type":"content_block_delta","delta":'
                    b'{"type":"text_delta","text":"xxxxxxxx"}}\n\n'
                ) * 40_000  # ~4.5 MiB
                payload = start + filler
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except OSError:
                    pass

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        self.base_url = (
            f"http://127.0.0.1:{self._server.server_address[1]}"
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


class TestClientLegWriteTimeout:
    """A stalled reader must abort the relay like RelayLimitExceeded —
    aborted usage booked, reservation released — instead of pinning
    the handler thread, its upstream pool connection, and the child
    token's reservation for as long as the client holds the socket."""

    def test_stalled_reader_aborts_books_and_releases(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        # The client-leg socket timeout is bound to the relay
        # total-deadline knob (read per connection).
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_RELAY_DEADLINE_S", "1")
        upstream = _SlowDrainUpstream()
        d = LLMDispatcher(
            run_id="stalled-reader", creds=fake_creds,
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
        try:
            token, _info = d.allocate_child("cc-stall", budget_usd=50.0)
            rec = d._tokens[token]
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            aborted_while_open = False
            with httpx.Client(transport=transport, timeout=30.0) as client:  # noqa: SIM117
                with client.stream(
                    "POST", "http://_/anthropic/v1/messages",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    content=json.dumps({
                        "model": _PRICED_MODEL, "max_tokens": 100,
                        "messages": [],
                    }).encode(),
                ):
                    # Read NOTHING: socket buffers fill, the
                    # dispatcher's wfile.write blocks, and the socket
                    # timeout must fire WHILE this connection is
                    # still open — pre-fix the handler thread stayed
                    # parked in send until the client went away.
                    deadline = time.time() + 8.0
                    while time.time() < deadline:
                        text = ""
                        try:
                            text = (tmp_path / "audit.jsonl").read_text()
                        except OSError:
                            pass
                        if '"request.error"' in text:
                            aborted_while_open = True
                            break
                        time.sleep(0.1)
            assert aborted_while_open, (
                "relay did not abort while the stalled reader held "
                "the connection open"
            )
            # Aborted usage was booked (message_start input tokens at
            # minimum) and the reservation fully released.
            deadline = time.time() + 5.0
            while time.time() < deadline and rec.reserved_usd > 0.0:
                time.sleep(0.05)
            assert rec.reserved_usd == 0.0
            assert rec.spent_usd > 0.0
        finally:
            upstream.shutdown()
            d.shutdown()
