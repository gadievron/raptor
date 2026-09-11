"""Spend-scanner integrity — classification, truncation recovery,
identity encoding.

The usage scanner prices scoped-child spend from the bytes the
dispatcher relays, and the relayed body embeds MODEL-AUTHORED text —
so nothing about how the scanner reads a response may be steerable by
body content. These tests pin the three evasion shapes: content-
substring SSE/JSON misclassification, an oversize body whose full
parse is impossible, and a compressed body the scanner cannot read.
Hermetic — captive loopback upstream, no LLM, no network.
"""

from __future__ import annotations

import http.server
import json
import logging
import threading

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import LLMDispatcher, _UsageScanner

# A model with a real entry in the pricing table (needed for booking).
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


def _json_body(
    content_text: str,
    input_tokens: int = 5000,
    output_tokens: int = 2000,
) -> bytes:
    """A non-streamed Anthropic Messages JSON body whose content text
    is attacker-shaped (round-tripped through json.dumps exactly as a
    real response would escape it) and whose usage rides at the end."""
    return json.dumps({
        "id": "msg_test",
        "type": "message",
        "model": _PRICED_MODEL,
        "content": [{"type": "text", "text": content_text}],
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
    }).encode()


class TestScannerClassification:
    """SSE-vs-JSON must come from Content-Type, not body content."""

    def test_json_with_data_substring_books_usage_via_header(self):
        # Model output containing 'data:' — the prompt-injection shape
        # that flipped the pre-fix substring classifier into the SSE
        # branch and booked $0.
        s = _UsageScanner()
        s.set_content_type("application/json")
        s.feed(_json_body("data: look, an SSE-looking string"))
        usage = s.extract()
        assert usage["input_tokens"] == 5000
        assert usage["output_tokens"] == 2000
        assert usage["model"] == _PRICED_MODEL

    def test_json_with_data_substring_books_usage_without_header(self):
        # Header absent: the fallback is LINE-anchored — a 'data:'
        # inside a JSON string value never starts a line (JSON string
        # encoding escapes newlines), so the body still parses as JSON.
        s = _UsageScanner()
        s.feed(_json_body("data: mid-line\nevent: also mid-line"))
        usage = s.extract()
        assert usage["input_tokens"] == 5000
        assert usage["output_tokens"] == 2000

    def test_sse_classified_by_header(self):
        s = _UsageScanner()
        s.set_content_type("text/event-stream; charset=utf-8")
        s.feed(
            b'event: message_start\n'
            b'data: {"type":"message_start","message":{"model":"'
            + _PRICED_MODEL.encode()
            + b'","usage":{"input_tokens":1000,"output_tokens":1}}}\n\n'
            b'event: message_delta\n'
            b'data: {"type":"message_delta","usage":'
            b'{"output_tokens":500}}\n\n'
        )
        usage = s.extract()
        assert usage["input_tokens"] == 1000
        assert usage["output_tokens"] == 500

    def test_sse_without_header_still_classified(self):
        # Opposite direction of the fallback: a real SSE body with no
        # Content-Type is still recognised (its field names DO start
        # lines) — the fix must not lose usage on header-less streams.
        s = _UsageScanner()
        s.feed(
            b'data: {"type":"message_start","message":{"model":"'
            + _PRICED_MODEL.encode()
            + b'","usage":{"input_tokens":700,"output_tokens":1}}}\n\n'
        )
        usage = s.extract()
        assert usage["input_tokens"] == 700

    def test_header_wins_over_body_shape(self):
        # An SSE Content-Type with a JSON-shaped body must take the
        # SSE branch (no data: lines → no usage) — the header is
        # authoritative in both directions, so a body can never
        # steer itself into the other parser.
        s = _UsageScanner()
        s.set_content_type("text/event-stream")
        s.feed(_json_body("plain"))
        usage = s.extract()
        assert usage["input_tokens"] == 0
        assert usage["output_tokens"] == 0


class TestTruncatedBodyRecovery:
    """Oversize non-SSE bodies must book from the retained tail, and
    failures must be loud — never a silent $0."""

    def _feed_chunked(self, s: _UsageScanner, body: bytes) -> None:
        for i in range(0, len(body), 64 * 1024):
            s.feed(body[i:i + 64 * 1024])

    def test_oversize_json_books_from_tail(self):
        s = _UsageScanner()
        s.set_content_type("application/json")
        body = _json_body(
            "a" * (600 * 1024), input_tokens=100, output_tokens=150_000,
        )
        assert len(body) > _UsageScanner._HEAD_CAP + _UsageScanner._TAIL_CAP
        self._feed_chunked(s, body)
        assert s.truncated
        usage = s.extract()
        assert usage["input_tokens"] == 100
        assert usage["output_tokens"] == 150_000
        # Model recovered from the head window (it rides early).
        assert usage["model"] == _PRICED_MODEL

    def test_oversize_json_with_nested_usage_object(self):
        # The trailing usage block may itself nest an object
        # (server_tool_use) — the brace scan must span it.
        s = _UsageScanner()
        s.set_content_type("application/json")
        body = json.dumps({
            "id": "msg_test",
            "model": _PRICED_MODEL,
            "content": [{"type": "text", "text": "b" * (600 * 1024)}],
            "usage": {
                "input_tokens": 42,
                "server_tool_use": {"web_search_requests": 2},
                "output_tokens": 7,
            },
        }).encode()
        self._feed_chunked(s, body)
        assert s.truncated
        usage = s.extract()
        assert usage["input_tokens"] == 42
        assert usage["output_tokens"] == 7

    def test_usage_inside_string_content_is_not_forged(self):
        # Attacker text carrying a usage-shaped decoy rides inside a
        # JSON string, so its quotes arrive ESCAPED — the tail
        # recovery must not read it. Body deliberately has its REAL
        # usage truncated away (content continues past the tail cap
        # after the decoy... here: no real usage at all).
        s = _UsageScanner()
        s.set_content_type("application/json")
        decoy = '"usage": {"input_tokens": 1, "output_tokens": 1}'
        # Decoy at the END of the content so it survives inside the
        # retained tail window, where the recovery scan runs.
        body = json.dumps({
            "id": "msg_test",
            "content": [{"type": "text", "text": "c" * (600 * 1024) + decoy}],
        }).encode()
        self._feed_chunked(s, body)
        assert s.truncated
        usage = s.extract()
        assert usage["input_tokens"] == 0
        assert usage["output_tokens"] == 0

    def test_unrecovered_truncation_warns_and_flags_audit(
        self, fake_creds, tmp_path, caplog,
    ):
        # When even the tail recovery fails, the $0 booking must be
        # LOUD: a WARNING naming the token and an audit-row flag.
        d = LLMDispatcher(
            run_id="unscanned", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=100,
        )
        try:
            token, info = d.allocate_child("cc-x", budget_usd=1.0)
            rec = d._tokens[token]
            s = _UsageScanner()
            s.set_content_type("application/json")
            self._feed_chunked(s, b"x" * (600 * 1024))  # not even JSON
            with caplog.at_level(logging.WARNING):
                d._book_child_usage(rec, s, aborted=False)
            assert any(
                "unscanned_response" in m and info["token_id"] in m
                for m in caplog.messages
            )
            rows = [
                json.loads(line)
                for line in (tmp_path / "audit.jsonl").read_text().splitlines()
            ]
            spend_rows = [r for r in rows if r["event"] == "child_token.spend"]
            assert spend_rows and spend_rows[-1]["unscanned_response"] is True
        finally:
            d.shutdown()

    def test_scanned_response_does_not_flag_audit(
        self, fake_creds, tmp_path, caplog,
    ):
        # Opposite direction: a normally-scanned response books its
        # cost with unscanned_response=False and no warning.
        d = LLMDispatcher(
            run_id="scanned", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=100,
        )
        try:
            token, _info = d.allocate_child("cc-y", budget_usd=1.0)
            rec = d._tokens[token]
            s = _UsageScanner()
            s.set_content_type("application/json")
            s.feed(_json_body("plain", input_tokens=10, output_tokens=5))
            with caplog.at_level(logging.WARNING):
                d._book_child_usage(rec, s, aborted=False)
            assert not any("unscanned_response" in m for m in caplog.messages)
            rows = [
                json.loads(line)
                for line in (tmp_path / "audit.jsonl").read_text().splitlines()
            ]
            spend_rows = [r for r in rows if r["event"] == "child_token.spend"]
            assert spend_rows and spend_rows[-1]["unscanned_response"] is False
            assert rec.spent_usd > 0
        finally:
            d.shutdown()


class _EchoUpstream:
    """Captive provider stub recording request headers verbatim."""

    def __init__(self):
        self.requests: list[dict] = []
        outer = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                # raw header pairs, duplicates preserved
                outer.requests.append({
                    "header_items": list(self.headers.items()),
                })
                resp = json.dumps({
                    "id": "msg_test",
                    "model": _PRICED_MODEL,
                    "content": [{"type": "text", "text": "hi"}],
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


def _make_dispatcher(fake_creds, tmp_path, upstream) -> LLMDispatcher:
    d = LLMDispatcher(
        run_id="scan-integrity", creds=fake_creds,
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


class TestIdentityEncodingForced:
    """Child-token requests must reach the upstream with exactly ONE
    accept-encoding header, value identity — regardless of the case
    the client spelled its own accept-encoding with (undici sends
    lowercase; dict-assigning only the canonical spelling shipped
    both and the upstream honoured gzip, blinding the scanner)."""

    @pytest.mark.parametrize("client_header", [
        "accept-encoding", "Accept-Encoding", "ACCEPT-ENCODING",
    ])
    def test_client_accept_encoding_replaced(
        self, fake_creds, tmp_path, client_header,
    ):
        upstream = _EchoUpstream()
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, _info = d.allocate_child("cc-enc", budget_usd=1.0)
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            with httpx.Client(transport=transport, timeout=10.0) as client:
                resp = client.post(
                    "http://_/anthropic/v1/messages",
                    headers=[
                        ("Authorization", f"Bearer {token}"),
                        ("Content-Type", "application/json"),
                        (client_header, "gzip, deflate, br"),
                    ],
                    content=json.dumps({
                        "model": _PRICED_MODEL, "max_tokens": 50,
                        "messages": [],
                    }).encode(),
                )
            assert resp.status_code == 200
            values = [
                v for k, v in upstream.requests[0]["header_items"]
                if k.lower() == "accept-encoding"
            ]
            assert values == ["identity"]
        finally:
            upstream.shutdown()
            d.shutdown()
