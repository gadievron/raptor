"""Dispatcher seam for the confined usage scan — admission gate and
booking loudness.

The jail's own machinery (worker lifecycle, re-validation, tier
ladder) is pinned in ``test_usage_scan_jail.py``; these tests pin the
three places ``server.py`` consumes it:

- Scoped-token admission fails closed PRE-upstream when the jail
  reports unavailable (fail-closed arm): 503 stamped with the
  pre-response upstream-state header, a ``usage_scan.unavailable``
  audit row, and the upstream never contacted — while worker-token
  relays on the same dispatcher are unaffected (they book no spend
  and carry no scanner).
- A ``scan_failed`` verdict books $0 LOUDLY: a WARNING naming the
  token plus ``scan_failed: true`` on the ``child_token.spend`` audit
  row.
- Normal bookings stamp the serving ``usage_scan_tier`` on the spend
  row (machine consumers can see which floor priced a run).

Hermetic — captive loopback upstream, stubbed jail where a failure
shape is scripted, real jail where the happy path is asserted.
"""

from __future__ import annotations

import http.server
import json
import logging
import os
import threading

import httpx
import pytest

from core.llm.dispatcher import server as server_mod
from core.llm.dispatcher import usage_scan_jail
from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import (
    _UPSTREAM_STATE_HEADER,
    _UPSTREAM_STATE_PRE,
    LLMDispatcher,
    _UsageScanner,
)

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


class _EchoUpstream:
    """Captive provider stub counting the requests that reach it."""

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
        run_id="scan-seam", creds=fake_creds,
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


def _audit_rows(tmp_path) -> "list[dict]":
    return [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
    ]


class _UnavailableJail:
    """Fail-closed-arm stand-in: capable kernel, worker unspawnable."""

    def ensure_available(self) -> str:
        raise usage_scan_jail.UsageScanJailUnavailable(
            "usage-scan worker spawn failed: scripted")

    def scan(self, *_a: object, **_k: object) -> dict:
        raise AssertionError("scan() must not be reached past a 503")


class _ScanFailedJail:
    """A jail whose worker died on this response's bytes."""

    def ensure_available(self) -> str:
        return usage_scan_jail.TIER_JAIL_LANDLOCK

    def scan(self, *_a: object, **_k: object) -> dict:
        return {
            "model": None,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_creation_tokens": 0,
            "scan_failed": True,
            "usage_scan_tier": usage_scan_jail.TIER_JAIL_LANDLOCK,
        }


def _post(d: LLMDispatcher, token: str) -> httpx.Response:
    transport = httpx.HTTPTransport(uds=str(d.socket_path))
    with httpx.Client(transport=transport, timeout=10.0) as client:
        return client.post(
            "http://_/anthropic/v1/messages",
            headers=[
                ("Authorization", f"Bearer {token}"),
                ("Content-Type", "application/json"),
            ],
            content=json.dumps({
                "model": _PRICED_MODEL, "max_tokens": 50,
                "messages": [],
            }).encode(),
        )


class TestAdmissionGate:

    def test_scoped_token_refused_pre_upstream_when_jail_unavailable(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        # server.py binds the getter by name at import — patch ITS
        # reference, not the jail module's.
        monkeypatch.setattr(server_mod, "get_usage_scan_jail",
                            _UnavailableJail)
        upstream = _EchoUpstream()
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token, info = d.allocate_child("cc-gate", budget_usd=1.0)
            resp = _post(d, token)
            assert resp.status_code == 503
            # Pre-response stamp: no upstream byte was seen, worker
            # retry policy stays in force.
            assert resp.headers[_UPSTREAM_STATE_HEADER] == (
                _UPSTREAM_STATE_PRE)
            assert upstream.requests == []  # never contacted
            rows = [r for r in _audit_rows(tmp_path)
                    if r["event"] == "usage_scan.unavailable"]
            assert rows and rows[-1]["status"] == "reject"
            assert rows[-1]["token_id"] == info["token_id"]
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_worker_token_relays_when_jail_unavailable(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        # Worker tokens book no spend and construct no scanner — the
        # jail gate must not touch them.
        monkeypatch.setattr(server_mod, "get_usage_scan_jail",
                            _UnavailableJail)
        upstream = _EchoUpstream()
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            _sock_path, token_fd = d.allocate_worker("worker-gate")
            token = os.read(token_fd, 256).decode("ascii")
            os.close(token_fd)
            resp = _post(d, token)
            assert resp.status_code == 200
            assert len(upstream.requests) == 1
        finally:
            upstream.shutdown()
            d.shutdown()


class TestBookingLoudness:

    def test_scan_failed_books_zero_with_warning_and_audit_flag(
        self, fake_creds, tmp_path, monkeypatch, caplog,
    ):
        monkeypatch.setattr(server_mod, "get_usage_scan_jail",
                            _ScanFailedJail)
        d = LLMDispatcher(
            run_id="scan-failed", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=100,
        )
        try:
            token, info = d.allocate_child("cc-fail", budget_usd=1.0)
            rec = d._tokens[token]
            s = _UsageScanner()
            s.set_content_type("application/json")
            s.feed(b'{"model":"' + _PRICED_MODEL.encode()
                   + b'","usage":{"input_tokens":10,"output_tokens":5}}')
            with caplog.at_level(logging.WARNING):
                d._book_child_usage(rec, s, aborted=False)
            assert rec.spent_usd == 0
            assert any(
                "scan_failed" in m and info["token_id"] in m
                for m in caplog.messages
            )
            spend = [r for r in _audit_rows(tmp_path)
                     if r["event"] == "child_token.spend"]
            assert spend and spend[-1]["scan_failed"] is True
            assert spend[-1]["cost_usd"] == 0
            assert spend[-1]["usage_scan_tier"] == (
                usage_scan_jail.TIER_JAIL_LANDLOCK)
        finally:
            d.shutdown()

    def test_normal_booking_stamps_tier_and_no_failure_flags(
        self, fake_creds, tmp_path, caplog,
    ):
        # Real jail singleton end-to-end: buffer → jailed scan → book.
        d = LLMDispatcher(
            run_id="scan-ok", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=100,
        )
        try:
            token, _info = d.allocate_child("cc-ok", budget_usd=1.0)
            rec = d._tokens[token]
            s = _UsageScanner()
            s.set_content_type("application/json")
            s.feed(json.dumps({
                "id": "msg_test", "model": _PRICED_MODEL,
                "content": [{"type": "text", "text": "hi"}],
                "usage": {"input_tokens": 1000, "output_tokens": 500},
            }).encode())
            with caplog.at_level(logging.WARNING):
                d._book_child_usage(rec, s, aborted=False)
            assert rec.spent_usd > 0
            assert not any("scan_failed" in m for m in caplog.messages)
            spend = [r for r in _audit_rows(tmp_path)
                     if r["event"] == "child_token.spend"]
            assert spend and spend[-1]["scan_failed"] is False
            assert spend[-1]["usage_scan_tier"] in (
                usage_scan_jail.TIER_JAIL_LANDLOCK,
                usage_scan_jail.TIER_JAIL_NO_LANDLOCK,
                usage_scan_jail.TIER_IN_PROCESS,
            )
        finally:
            d.shutdown()
