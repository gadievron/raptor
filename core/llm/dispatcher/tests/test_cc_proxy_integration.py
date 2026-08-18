"""Integration smoke: a REAL ``claude`` CLI child in credential-proxy
posture against a fake upstream.

Skipped when the ``claude`` binary is absent. Hermetic even when it
runs: the dispatcher's Bedrock leg is pointed (via the endpoint
override) at a captive Mantle-shaped SSE server inside the test — no
provider traffic, no real credentials, no cost — and the child's
proxy env is additionally blackholed so any non-loopback attempt
fails instantly instead of leaving the test's hermetic envelope.

Proves the CLI-side contract end-to-end on a Bedrock-mode install:
the CLI reads the gateway env family (``ANTHROPIC_BEDROCK_MANTLE_
BASE_URL`` + ``CLAUDE_CODE_SKIP_MANTLE_AUTH``), authenticates with
the scoped bearer token on the dispatcher's TCP plane, the control-
plane probe gets the canned answer, the Mantle leg attaches the
parent-held credential, the SSE body streams back, and usage is
booked on the token.
"""

from __future__ import annotations

import http.server
import json
import shutil
import subprocess
import threading
import time

import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.server import LLMDispatcher

_CLAUDE = shutil.which("claude")

pytestmark = pytest.mark.skipif(
    _CLAUDE is None, reason="claude CLI not installed",
)

_SMOKE_MODEL = "anthropic.claude-opus-4-8"


def _sse_reply(text: str) -> bytes:
    events = [
        ("message_start", {
            "type": "message_start",
            "message": {
                "id": "msg_smoke", "type": "message", "role": "assistant",
                "model": _SMOKE_MODEL, "content": [],
                "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 25, "output_tokens": 1},
            },
        }),
        ("content_block_start", {
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""},
        }),
        ("content_block_delta", {
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": text},
        }),
        ("content_block_stop", {
            "type": "content_block_stop", "index": 0,
        }),
        ("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": 12},
        }),
        ("message_stop", {"type": "message_stop"}),
    ]
    out = b""
    for name, payload in events:
        out += (
            f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode()
        )
    return out


class _FakeMantle:
    """Captive Mantle-shaped upstream (``/anthropic/v1/messages``):
    SSE for stream:true bodies, plain JSON otherwise."""

    def __init__(self):
        outer = self
        self.messages_hits = 0
        self.captured_headers: list[dict] = []

        class _H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                if "/v1/messages" not in self.path:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                outer.messages_hits += 1
                outer.captured_headers.append(dict(self.headers.items()))
                try:
                    streaming = bool(json.loads(body).get("stream"))
                except (json.JSONDecodeError, ValueError):
                    streaming = False
                if streaming:
                    payload = _sse_reply("PROOF-SMOKE-OK")
                    ctype = "text/event-stream"
                else:
                    payload = json.dumps({
                        "id": "msg_smoke", "type": "message",
                        "role": "assistant", "model": _SMOKE_MODEL,
                        "content": [
                            {"type": "text", "text": "PROOF-SMOKE-OK"},
                        ],
                        "stop_reason": "end_turn",
                        "usage": {
                            "input_tokens": 25, "output_tokens": 12,
                        },
                    }).encode()
                    ctype = "application/json"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _H,
        )
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(
            target=self._server.serve_forever, daemon=True,
        ).start()

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


def _fake_bedrock_creds(endpoint: str) -> CredentialStore:
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": None,
        # Bearer mode: no botocore needed; the parent-held credential
        # the dispatcher must attach (and the child must never see).
        "aws_bearer_token": "parent-held-bedrock-bearer-NOT-IN-CHILD",
    }
    creds._aws_region = "us-east-1"
    creds._aws_endpoint = endpoint
    creds._aws_profile = None
    creds._aws_signer_cache = {}
    creds._aws_signer_lock = threading.Lock()
    creds._aws_model_overrides = {}
    creds._aws_bearer_exp = None
    return creds


@pytest.mark.timeout(240)
def test_real_claude_cli_round_trip_through_credential_proxy(
    tmp_path, monkeypatch,
):
    fake = _FakeMantle()
    d = LLMDispatcher(
        run_id="cc-smoke", creds=_fake_bedrock_creds(fake.base_url),
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=600, token_budget=100,
    )
    try:
        port = d.enable_loopback_listener()
        token, info = d.allocate_child(
            "cc-smoke", budget_usd=1.0, ttl_s=600,
        )
        # Force the Bedrock-mode branch with a known priced model,
        # regardless of the host's own install shape.
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("ANTHROPIC_MODEL", _SMOKE_MODEL)
        monkeypatch.setenv("ANTHROPIC_SMALL_FAST_MODEL", _SMOKE_MODEL)

        from core.llm.cc_adapter import (
            CCDispatchConfig,
            build_cc_command,
            cc_subprocess_env,
        )
        env = cc_subprocess_env(
            credential_mode="proxy",
            proxy_base_url=f"http://127.0.0.1:{port}",
            proxy_auth_token=token,
        )
        # The env-construction invariant, re-checked on the exact dict
        # the real child receives.
        assert not any(
            k.startswith("AWS_") or k == "ANTHROPIC_API_KEY"
            for k in env
        )
        assert "parent-held-bedrock-bearer-NOT-IN-CHILD" not in json.dumps(env)
        # Hermeticity hardening: blackhole every non-loopback route so
        # a CLI feature that tries to phone home fails instantly
        # instead of reaching the network from the test.
        for var in ("HTTPS_PROXY", "https_proxy",
                    "HTTP_PROXY", "http_proxy"):
            env[var] = "http://127.0.0.1:9"

        cmd = build_cc_command(CCDispatchConfig(
            claude_bin=_CLAUDE,
            tools="",
            budget_usd="2.00",
            capture_json_envelope=True,
            model=_SMOKE_MODEL,
        ))
        proc = subprocess.run(
            cmd, input="Reply with one word.", text=True,
            capture_output=True, timeout=180, env=env,
            cwd=str(tmp_path),
        )
        # The CLI completed a round trip THROUGH the dispatcher: the
        # fake upstream saw its messages call(s) and the reply text
        # made it back into the CLI's output envelope.
        assert fake.messages_hits >= 1, (
            f"claude never reached the dispatcher: rc={proc.returncode} "
            f"stderr={proc.stderr[-500:]!r}"
        )
        assert proc.returncode == 0, (
            f"rc={proc.returncode} stderr={proc.stderr[-500:]!r} "
            f"stdout={proc.stdout[-500:]!r}"
        )
        assert "PROOF-SMOKE-OK" in proc.stdout
        # The parent-held credential rode the upstream leg only.
        sent = {k.lower(): v for k, v in fake.captured_headers[0].items()}
        assert sent.get("authorization") == (
            "Bearer parent-held-bedrock-bearer-NOT-IN-CHILD"
        )
        assert token not in json.dumps(fake.captured_headers)
        # Usage booked on the scoped token from the relayed bytes.
        deadline = time.time() + 3
        spend = {}
        while time.time() < deadline:
            spend = d.child_spend(info["token_id"]) or {}
            if spend.get("spent_usd"):
                break
            time.sleep(0.05)
        assert spend.get("spent_usd", 0) > 0
        assert spend.get("requests_made", 0) >= 1
    finally:
        fake.shutdown()
        d.shutdown()
