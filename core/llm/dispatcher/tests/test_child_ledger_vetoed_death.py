"""Child-token ledger behaviour on a vetoed mid-response death.

The spend-aware worker gate refuses to re-send a generation whose
response head arrived before the wire died. On a scoped child token
the same failure has a LEDGER side: the dispatcher books the aborted
attempt's upstream-reported usage (a failed call still spent real
money) and must release the per-request budget reservation exactly
once. This pins the interaction end to end on the real dispatcher:
the worker-side hook records the response-started stamp (the veto's
evidence), the upstream handles exactly one request, the spend is
booked exactly once, and no reservation lingers to starve later
admissions.

Hermetic — captive loopback upstream, no LLM, no network egress.
"""

from __future__ import annotations

import http.server
import json
import os
import threading
import time

import httpx
import pytest

import core.llm.dispatcher.client as dispatcher_client
from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.client import (
    _note_attempt_state,
    _reset_attempt_state,
    mint_child_token,
    take_upstream_response_started,
)
from core.llm.dispatcher.server import LLMDispatcher

# Must have a pricing-table entry: an unpriced model books $0 and the
# test would pass vacuously.
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


@pytest.fixture(autouse=True)
def _clean_attempt_state():
    dispatcher_client._attempt_state.response_started = False
    yield
    dispatcher_client._attempt_state.response_started = False


class _AbortSSEUpstream:
    """SSE upstream that sends ``message_start`` (with usage) then
    dies — a mid-response death AFTER billable work landed upstream.
    The declared Content-Length exceeds what is sent, so the client
    sees a wire-level incomplete body, not a clean end of stream."""

    def __init__(self) -> None:
        outer = self
        self.requests = 0

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):
                outer.requests += 1
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                start = (
                    b'event: message_start\n'
                    b'data: {"type":"message_start","message":{"model":"'
                    + _PRICED_MODEL.encode() +
                    b'","usage":{"input_tokens":1000,"output_tokens":1}}}'
                    b'\n\n'
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header(
                    "Content-Length", str(len(start) + 4096),
                )
                self.end_headers()
                self.wfile.write(start)
                self.wfile.flush()
                self.connection.close()

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        self.base_url = (
            "http://127.0.0.1:%d" % self._server.server_address[1]
        )
        threading.Thread(
            target=self._server.serve_forever, daemon=True,
        ).start()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _make_dispatcher(fake_creds, tmp_path, base_url: str) -> LLMDispatcher:
    d = LLMDispatcher(
        run_id="child-ledger", creds=fake_creds,
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600, token_budget=100,
    )
    original = d._rules["anthropic"]
    d._rules["anthropic"] = ProviderRule(
        name=original.name,
        upstream_base_url=base_url,
        inject_headers=original.inject_headers,
        strip_request_headers=original.strip_request_headers,
    )
    return d


def _worker_token(d: LLMDispatcher) -> str:
    _, fd = d.allocate_worker(label="ledger-worker")
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    return token


class TestChildLedgerOnVetoedDeath:

    def test_one_booking_and_reservation_released(
        self, fake_creds, tmp_path,
    ):
        upstream = _AbortSSEUpstream()
        d = _make_dispatcher(fake_creds, tmp_path, upstream.base_url)
        try:
            worker = _worker_token(d)
            minted = mint_child_token(
                budget_usd=1.0, models=[_PRICED_MODEL], ttl_s=120,
                label="ledger-child",
                socket_path=str(d.socket_path), token=worker,
            )
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            with httpx.Client(
                transport=transport, timeout=30.0,
                event_hooks={
                    "request": [_reset_attempt_state],
                    "response": [_note_attempt_state],
                },
            ) as c:
                with pytest.raises(httpx.HTTPError):
                    c.post(
                        "http://_/anthropic/v1/messages",
                        headers={
                            "Authorization": f"Bearer {minted['token']}",
                        },
                        content=json.dumps({
                            "model": _PRICED_MODEL,
                            "messages": [], "max_tokens": 10,
                        }),
                    )
            # Worker-side veto evidence: the relayed 200 head WAS
            # stamped response-started before the wire died.
            assert take_upstream_response_started() is True
            # The abort booking + reservation release run on the
            # handler thread after the client-side error — poll to
            # the settled state.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                spend = d.child_spend(minted["token_id"])
                with d._tokens_lock:
                    rec = d._child_by_id_locked(minted["token_id"])
                    reserved = rec.reserved_usd
                if spend["requests_made"] >= 1 and reserved == 0.0:
                    break
                time.sleep(0.05)
            # Ledger honesty: exactly one request, the aborted
            # attempt's usage booked once (message_start input tokens
            # are the floor of what the upstream reported), and the
            # admission reservation fully released.
            assert spend["requests_made"] == 1, spend
            assert spend["spent_usd"] > 0, spend
            assert reserved == 0.0, reserved
            # No second upstream request, no second booking.
            assert upstream.requests == 1
            spend2 = d.child_spend(minted["token_id"])
            assert spend2["spent_usd"] == spend["spent_usd"]
        finally:
            upstream.shutdown()
            d.shutdown()
