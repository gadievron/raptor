"""Security + E2E tests for ``core/llm/dispatcher``.

The five security layers each get a dedicated test. The E2E section
spins up the dispatcher, points it at a captive ``httpx.MockTransport``
upstream, drives a real ``httpx`` client through the UDS, and asserts
on what the dispatcher forwarded to the upstream — including that
the worker's dummy auth header was stripped and the parent's real
key was injected.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import sys
import threading
import time

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.server import (
    LLMDispatcher,
    _TOKEN_HEADER,
    _peer_uid,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "real-secret-anthropic-key-NOT-LEAKED",
        "openai": None,
        "gemini": None,
    }
    return creds


@pytest.fixture
def dispatcher(fake_creds, tmp_path):
    """Run-scoped dispatcher with a fake credential store and audit
    log inside ``tmp_path``."""
    audit = tmp_path / "audit.jsonl"
    d = LLMDispatcher(
        run_id="test",
        audit_path=audit,
        token_ttl_s=3600,
        token_budget=100,
        creds=fake_creds,
    )
    yield d
    d.shutdown()


def _read_audit(d: LLMDispatcher) -> list[dict]:
    if not d._audit_path or not d._audit_path.exists():
        return []
    return [json.loads(line) for line in d._audit_path.read_text().splitlines()]


def _wait_for_audit_event(d: LLMDispatcher, event: str, timeout: float = 2.0) -> dict | None:
    """The dispatcher writes the audit line AFTER the response is
    flushed to the client. The httpx call can therefore return
    before the audit line lands. Poll briefly to absorb that lag."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for ev in _read_audit(d):
            if ev["event"] == event:
                return ev
        time.sleep(0.02)
    return None


# ---------------------------------------------------------------------------
# L1 — filesystem isolation
# ---------------------------------------------------------------------------


class TestLayer1FilesystemIsolation:

    def test_socket_dir_is_0700(self, dispatcher):
        mode = stat.S_IMODE(dispatcher._sock_dir.stat().st_mode)
        assert mode == 0o700

    def test_socket_file_is_0600_or_more_restrictive(self, dispatcher):
        # World-readable would let same-UID processes connect via path
        # alone — the dir 0700 is the actual gate, but the socket
        # mode is belt-and-braces. Anything 0600 or stricter is fine.
        mode = stat.S_IMODE(dispatcher.socket_path.stat().st_mode)
        # Must not be group- or world-readable
        assert mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH) == 0

    def test_socket_dir_is_inside_a_per_run_tempdir(self, dispatcher):
        assert dispatcher._sock_dir.name.startswith("raptor-llm-test-")

    def test_shutdown_removes_socket_dir(self, fake_creds):
        d = LLMDispatcher(run_id="ephemeral", creds=fake_creds, token_ttl_s=60)
        sock_dir = d._sock_dir
        d.shutdown()
        assert not sock_dir.exists()


# ---------------------------------------------------------------------------
# L2 — peer-UID verification
# ---------------------------------------------------------------------------


class TestLayer2PeerUidVerification:

    def test_peer_uid_lookup_returns_self_uid(self, dispatcher):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.connect(str(dispatcher.socket_path))
            # Server does the lookup on its accepted side — but we
            # can also probe our own side as sanity. Same process,
            # same UID, so this is just confirming the mechanism
            # works on the test platform.
            uid_self = _peer_uid(c)
            # On Linux/macOS the lookup should succeed; on other
            # platforms it returns None (and the dispatcher would
            # reject the connection, not what's tested here).
            if sys.platform in ("linux", "darwin"):
                assert uid_self == os.getuid()


# ---------------------------------------------------------------------------
# L3 — token authentication
# ---------------------------------------------------------------------------


class TestLayer3TokenAuth:

    def _post(self, dispatcher, headers: dict[str, str]) -> httpx.Response:
        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=10.0) as c:
            return c.post(
                "http://_/anthropic/v1/messages",
                content=b'{"x":1}',
                headers=headers,
            )

    def test_request_without_token_is_rejected(self, dispatcher):
        r = self._post(dispatcher, headers={})
        assert r.status_code == 401
        assert "missing token" in r.text

    def test_request_with_unknown_token_is_rejected(self, dispatcher):
        r = self._post(dispatcher, headers={_TOKEN_HEADER: "totally-invented-token"})
        assert r.status_code == 401
        assert "unknown token" in r.text

    def test_request_with_valid_token_passes_token_check(self, dispatcher):
        """A valid token must get past the gate. We don't assert on
        the response body or status because the upstream is the real
        anthropic.com here (CI may or may not have network) — only
        that the response is NOT one of the gate's rejection shapes."""
        socket_path, fd = dispatcher.allocate_worker(label="test-l3")
        token = os.read(fd, 64).decode().strip()
        os.close(fd)
        r = self._post(dispatcher, headers={_TOKEN_HEADER: token})
        # Body must NOT contain any of our gate's rejection messages.
        # Decode best-effort — upstream may return gzipped body.
        body_lower = ""
        try:
            body_lower = r.text.lower()
        except Exception:
            pass
        for bad in ("missing token", "unknown token", "token expired",
                    "token revoked", "token exhausted"):
            assert bad not in body_lower, f"gate rejected a valid token: {body_lower!r}"


# ---------------------------------------------------------------------------
# L4 — token lifecycle (single-use, budget, TTL)
# ---------------------------------------------------------------------------


class TestLayer4TokenLifecycle:

    def test_token_budget_exhaustion(self, fake_creds, tmp_path):
        # Budget enforcement is gate logic — must not depend on the
        # real anthropic.com upstream (CI may have no network).
        # Point the anthropic rule at a captive in-process server so
        # the first two requests resolve quickly and we observe the
        # gate's third-request rejection deterministically.
        upstream = _CaptiveUpstream()
        d = LLMDispatcher(
            run_id="budget", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=2,
        )
        from core.llm.dispatcher.auth import ProviderRule
        original = d._rules["anthropic"]
        d._rules["anthropic"] = ProviderRule(
            name=original.name,
            upstream_base_url=upstream.base_url,
            inject_headers=original.inject_headers,
            strip_request_headers=original.strip_request_headers,
        )
        try:
            socket_path, fd = d.allocate_worker(label="budget-test")
            token = os.read(fd, 64).decode().strip()
            os.close(fd)
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            with httpx.Client(transport=transport, timeout=5.0) as c:
                # First two consume budget. Both pass token check.
                for _ in range(2):
                    r = c.post("http://_/anthropic/v1/messages",
                               content=b"{}",
                               headers={_TOKEN_HEADER: token})
                    assert "missing token" not in r.text
                    assert "unknown token" not in r.text
                    assert "exhausted" not in r.text
                # Third must be rejected with budget exhausted.
                r = c.post("http://_/anthropic/v1/messages",
                           content=b"{}",
                           headers={_TOKEN_HEADER: token})
                assert r.status_code == 401
                assert "exhausted" in r.text
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_token_expiry(self, fake_creds, tmp_path):
        d = LLMDispatcher(
            run_id="expiry", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=0,  # immediate expiry
            token_budget=100,
        )
        try:
            socket_path, fd = d.allocate_worker(label="expiry-test")
            token = os.read(fd, 64).decode().strip()
            os.close(fd)
            time.sleep(0.05)
            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            with httpx.Client(transport=transport, timeout=5.0) as c:
                r = c.post("http://_/anthropic/v1/messages",
                           content=b"{}",
                           headers={_TOKEN_HEADER: token})
                assert r.status_code == 401
                assert "expired" in r.text
        finally:
            d.shutdown()

    def test_revoked_token_is_rejected(self, dispatcher):
        socket_path, fd = dispatcher.allocate_worker(label="revoke")
        token = os.read(fd, 64).decode().strip()
        os.close(fd)
        # Manually flip status — what happens on connection close
        # in production.
        with dispatcher._tokens_lock:
            dispatcher._tokens[token].status = "revoked"
        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=5.0) as c:
            r = c.post("http://_/anthropic/v1/messages",
                       content=b"{}",
                       headers={_TOKEN_HEADER: token})
            assert r.status_code == 401
            assert "revoked" in r.text


# ---------------------------------------------------------------------------
# L5 — audit log
# ---------------------------------------------------------------------------


class TestLayer5AuditLog:

    def test_server_start_is_logged(self, dispatcher):
        events = _read_audit(dispatcher)
        assert any(e["event"] == "server.start" for e in events)

    def test_token_issue_is_logged(self, dispatcher):
        socket_path, fd = dispatcher.allocate_worker(label="audit-test")
        os.close(fd)
        events = _read_audit(dispatcher)
        issued = [e for e in events if e["event"] == "token.issue"]
        assert len(issued) >= 1
        assert issued[-1]["worker_label"] == "audit-test"
        # Token id is the 12-char prefix, not the full secret.
        assert len(issued[-1]["token_id"]) == 12

    def test_token_reject_is_logged(self, dispatcher):
        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=5.0) as c:
            c.post("http://_/anthropic/v1/messages",
                   content=b"{}",
                   headers={_TOKEN_HEADER: "wrong-token"})
        events = _read_audit(dispatcher)
        rejects = [e for e in events if e["event"] == "token.reject"]
        assert len(rejects) >= 1
        assert rejects[-1]["status"] == "reject"
        assert rejects[-1]["reason"] == "unknown token"

    def test_audit_does_not_log_token_value(self, dispatcher):
        socket_path, fd = dispatcher.allocate_worker(label="leak-check")
        token = os.read(fd, 64).decode().strip()
        os.close(fd)
        events = _read_audit(dispatcher)
        for e in events:
            for value in e.values():
                if isinstance(value, str):
                    assert token not in value, f"full token leaked into audit: {e}"


# ---------------------------------------------------------------------------
# E2E — captive upstream + real httpx client through UDS
# ---------------------------------------------------------------------------


class _CaptiveUpstream:
    """Tiny HTTP server in a thread that records exactly one request
    and replies with a fixed JSON body. The dispatcher's
    ``upstream_base_url`` is rewritten to point here for the duration
    of the test, so we observe the real bytes the dispatcher would
    send to the actual provider."""

    def __init__(self):
        import http.server

        self.captured: dict = {}
        self_outer = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                return

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                self_outer.captured["method"] = self.command
                self_outer.captured["path"] = self.path
                self_outer.captured["headers"] = {k: v for k, v in self.headers.items()}
                self_outer.captured["body"] = body
                resp = b'{"id":"msg_test","content":"hello"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        self.host, self.port = self._server.server_address
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


class TestE2ECredentialIsolation:
    """Drive a real httpx client through the UDS, with the
    dispatcher's upstream rewritten to a captive HTTP server, and
    assert (a) the request reaches the upstream, (b) the worker's
    dummy auth header is stripped, (c) the parent's real key is
    injected, (d) the response streams back unchanged."""

    def _setup(self, fake_creds, tmp_path):
        upstream = _CaptiveUpstream()
        d = LLMDispatcher(
            run_id="e2e", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=100,
        )
        # Rewrite the rule to point at our captive server. The rule
        # is a frozen dataclass, so swap the whole entry.
        from core.llm.dispatcher.auth import ProviderRule
        original = d._rules["anthropic"]
        d._rules["anthropic"] = ProviderRule(
            name=original.name,
            upstream_base_url=upstream.base_url,
            inject_headers=original.inject_headers,
            strip_request_headers=original.strip_request_headers,
        )
        return d, upstream

    def test_e2e_credentials_injected_dummy_stripped(self, fake_creds, tmp_path):
        d, upstream = self._setup(fake_creds, tmp_path)
        try:
            _, fd = d.allocate_worker(label="e2e")
            token = os.read(fd, 64).decode().strip()
            os.close(fd)

            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            with httpx.Client(transport=transport, timeout=10.0) as client:
                resp = client.post(
                    "http://_/anthropic/v1/messages",
                    headers={
                        _TOKEN_HEADER: token,
                        # Worker's SDK passes ``api_key='dummy-not-used'``
                        # which becomes this header. Dispatcher must
                        # strip it before forwarding upstream.
                        "x-api-key": "dummy-not-used",
                        "Content-Type": "application/json",
                    },
                    content=b'{"model":"claude-3-haiku","messages":[]}',
                )

            # ---- response streamed back unchanged ----
            assert resp.status_code == 200
            assert resp.json()["id"] == "msg_test"

            # ---- dispatcher hit the right upstream path ----
            assert upstream.captured["method"] == "POST"
            assert upstream.captured["path"] == "/v1/messages"

            # ---- credential isolation invariants ----
            sent_headers = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            # 1. Dummy key must NOT have flowed upstream
            assert sent_headers.get("x-api-key") != "dummy-not-used"
            # 2. Real key MUST have been injected
            assert sent_headers.get("x-api-key") == "real-secret-anthropic-key-NOT-LEAKED"
            # 3. Anthropic-version header injected by the rule
            assert sent_headers.get("anthropic-version") == "2023-06-01"
            # 4. Token header MUST NOT have been forwarded upstream
            assert "x-raptor-token" not in sent_headers

            # ---- request body passed through unchanged ----
            assert upstream.captured["body"] == b'{"model":"claude-3-haiku","messages":[]}'
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_e2e_audit_records_dispatch_without_body(self, fake_creds, tmp_path):
        d, upstream = self._setup(fake_creds, tmp_path)
        try:
            _, fd = d.allocate_worker(label="audit-e2e")
            token = os.read(fd, 64).decode().strip()
            os.close(fd)

            transport = httpx.HTTPTransport(uds=str(d.socket_path))
            with httpx.Client(transport=transport, timeout=10.0) as c:
                c.post(
                    "http://_/anthropic/v1/messages",
                    headers={_TOKEN_HEADER: token},
                    content=b'{"prompt":"sensitive-content-must-not-be-logged"}',
                )

            ev = _wait_for_audit_event(d, "request.dispatch")
            assert ev is not None, "request.dispatch did not appear in audit log"
            assert ev["worker_label"] == "audit-e2e"
            assert ev["status"] == "ok"
            # Body content must NOT be in the audit log.
            for value in ev.values():
                if isinstance(value, str):
                    assert "sensitive-content-must-not-be-logged" not in value
        finally:
            upstream.shutdown()
            d.shutdown()


# ---------------------------------------------------------------------------
# Spawn helper — token via inherited FD, NOT via env or argv
# ---------------------------------------------------------------------------


class TestRealAnthropicSDKThroughDispatcher:
    """The strongest in-process E2E: a real ``anthropic.Anthropic``
    SDK client built via ``make_anthropic_client`` makes a request,
    the dispatcher forwards to a captive HTTP server, the response
    flows back through the SDK's deserialiser. Proves that the
    base_url + dummy api_key + UDS transport combination is one the
    stock SDK actually accepts."""

    def _setup(self, fake_creds, tmp_path):
        upstream = _CaptiveUpstream()
        d = LLMDispatcher(
            run_id="sdk-e2e", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600, token_budget=100,
        )
        from core.llm.dispatcher.auth import ProviderRule
        original = d._rules["anthropic"]
        d._rules["anthropic"] = ProviderRule(
            name=original.name,
            upstream_base_url=upstream.base_url,
            inject_headers=original.inject_headers,
            strip_request_headers=original.strip_request_headers,
        )
        return d, upstream

    def test_real_anthropic_sdk_call_succeeds(self, fake_creds, tmp_path):
        """Build the client via ``make_anthropic_client`` (the actual
        worker-side helper), call ``messages.create``, assert the SDK
        parsed the response and the dispatcher injected real creds."""
        anthropic = pytest.importorskip("anthropic")
        from core.llm.dispatcher.client import make_anthropic_client

        d, upstream = self._setup(fake_creds, tmp_path)
        # Override _CaptiveUpstream's response to a valid Anthropic
        # messages payload so the SDK's deserialiser doesn't choke.
        anthropic_response_body = json.dumps({
            "id": "msg_e2e_test",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-haiku-20240307",
            "content": [{"type": "text", "text": "hello from dispatcher"}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 5, "output_tokens": 4},
        }).encode("utf-8")
        # Replace the captive handler's response. Done after the
        # fixture is built so the dispatcher is wired correctly.
        upstream._server.RequestHandlerClass.do_POST = (
            self._make_post_handler(upstream, anthropic_response_body)
        )

        try:
            socket_path, fd = d.allocate_worker(label="sdk-e2e")
            token = os.read(fd, 64).decode().strip()
            os.close(fd)

            client = make_anthropic_client(
                socket_path=str(d.socket_path),
                token=token,
            )
            try:
                msg = client.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=64,
                    messages=[{"role": "user", "content": "ping"}],
                )
            finally:
                client.close()

            # ---- SDK parsed the response correctly ----
            assert msg.id == "msg_e2e_test"
            assert msg.content[0].text == "hello from dispatcher"

            # ---- credential isolation invariants on the upstream ----
            sent_headers = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent_headers.get("x-api-key") == "real-secret-anthropic-key-NOT-LEAKED"
            # SDK sends api_key='dummy-not-used' as x-api-key; dispatcher must strip
            assert sent_headers.get("x-api-key") != "dummy-not-used"
            # Capability token must NOT have flowed upstream
            assert "x-raptor-token" not in sent_headers
            # Anthropic version header injected by the rule
            assert sent_headers.get("anthropic-version") == "2023-06-01"

            # ---- request body is the SDK's actual JSON ----
            req_body = json.loads(upstream.captured["body"])
            assert req_body["model"] == "claude-3-haiku-20240307"
            assert req_body["messages"][0]["content"] == "ping"
        finally:
            upstream.shutdown()
            d.shutdown()

    def _make_post_handler(self, upstream, response_body):
        """Closure that captures one request and replies with
        ``response_body``. Used to swap in payload-shape responses
        per-test without rebuilding the captive server class."""
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            upstream.captured["method"] = self.command
            upstream.captured["path"] = self.path
            upstream.captured["headers"] = {k: v for k, v in self.headers.items()}
            upstream.captured["body"] = body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
        return do_POST


class TestSubprocessE2E:
    """The fullest end-to-end: spawn a real subprocess via
    ``spawn_worker``, have it import the stock anthropic SDK, make a
    call, return the response. Subprocess gets NO API keys in env —
    if anything reaches the captive upstream with the real key in
    place, the dispatcher's whole chain works."""

    def test_subprocess_uses_dispatcher_with_no_keys_in_env(
        self, fake_creds, tmp_path
    ):
        anthropic = pytest.importorskip("anthropic")
        from core.llm.dispatcher.spawn import spawn_worker

        upstream = _CaptiveUpstream()
        # Same payload-shape swap as above so the SDK parses successfully.
        anthropic_response_body = json.dumps({
            "id": "msg_subproc",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-haiku-20240307",
            "content": [{"type": "text", "text": "subprocess hello"}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 5, "output_tokens": 3},
        }).encode("utf-8")

        def do_POST(handler):  # noqa: N802
            length = int(handler.headers.get("Content-Length", "0"))
            body = handler.rfile.read(length) if length else b""
            upstream.captured["method"] = handler.command
            upstream.captured["path"] = handler.path
            upstream.captured["headers"] = {k: v for k, v in handler.headers.items()}
            upstream.captured["body"] = body
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(anthropic_response_body)))
            handler.end_headers()
            handler.wfile.write(anthropic_response_body)

        upstream._server.RequestHandlerClass.do_POST = do_POST

        d = LLMDispatcher(
            run_id="subproc-e2e", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=60, token_budget=10,
        )
        from core.llm.dispatcher.auth import ProviderRule
        original = d._rules["anthropic"]
        d._rules["anthropic"] = ProviderRule(
            name=original.name,
            upstream_base_url=upstream.base_url,
            inject_headers=original.inject_headers,
            strip_request_headers=original.strip_request_headers,
        )

        try:
            # Worker script: read token, build anthropic client via
            # the official helper, call messages.create, assert no
            # API keys are in env, write SDK response to stdout.
            worker_src = tmp_path / "worker.py"
            worker_src.write_text(
                "import json, os, sys\n"
                "# Confirm the worker has NO API keys in env — that's\n"
                "# the whole point of credential isolation.\n"
                "for k in os.environ:\n"
                "    if 'API_KEY' in k or 'API_TOKEN' in k:\n"
                "        sys.exit(f'leaked key in env: {k}')\n"
                "from core.llm.dispatcher.client import make_anthropic_client\n"
                "client = make_anthropic_client()\n"
                "msg = client.messages.create(\n"
                "    model='claude-3-haiku-20240307',\n"
                "    max_tokens=64,\n"
                "    messages=[{'role': 'user', 'content': 'subproc ping'}],\n"
                ")\n"
                "client.close()\n"
                "sys.stdout.write(json.dumps({'id': msg.id, 'text': msg.content[0].text}))\n",
                encoding="utf-8",
            )
            import subprocess
            proc = spawn_worker(
                d,
                cmd=[sys.executable, str(worker_src)],
                label="subproc-e2e",
                # Crucially: NO LLM_API_KEY_VARS in env. PYTHONPATH so
                # the worker can import core.llm.dispatcher.client.
                env={
                    "PATH": os.environ.get("PATH", ""),
                    # Repo root: this file is at
                    # ``core/llm/dispatcher/tests/test_dispatcher.py`` so
                    # five ``dirname`` calls reach the repo root. Setting
                    # PYTHONPATH to ``core/`` (one fewer dirname) would
                    # cause the worker's ``import json`` to resolve to
                    # ``core/json/`` instead of stdlib.
                    "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.dirname(
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    ))),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # 30s, not 15s: this 1-deep Python subprocess (worker.py
            # imports anthropic + core.llm) takes ~10-12s in isolation
            # but can exceed 15s on a contended xdist runner. 30s
            # matches the timeout used by the grandchild-relay sibling
            # in core/llm/tests/test_dispatcher_integration.py.
            stdout, stderr = proc.communicate(timeout=30)
            assert proc.returncode == 0, (
                f"worker failed: rc={proc.returncode} "
                f"stdout={stdout.decode()!r} stderr={stderr.decode()!r}"
            )

            # ---- response made it back through dispatcher → SDK → stdout ----
            payload = json.loads(stdout.decode())
            assert payload["id"] == "msg_subproc"
            assert payload["text"] == "subprocess hello"

            # ---- the dispatcher injected the real key on the upstream ----
            sent_headers = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent_headers.get("x-api-key") == "real-secret-anthropic-key-NOT-LEAKED"
            assert "x-raptor-token" not in sent_headers

            # ---- request body shape matches what the SDK in the subprocess sent ----
            req = json.loads(upstream.captured["body"])
            assert req["model"] == "claude-3-haiku-20240307"
            assert req["messages"][0]["content"] == "subproc ping"
        finally:
            upstream.shutdown()
            d.shutdown()


class TestSpawnHelperTokenIsolation:

    def test_token_arrives_via_inherited_fd_not_env(self, fake_creds, tmp_path):
        from core.llm.dispatcher.spawn import spawn_worker

        d = LLMDispatcher(
            run_id="spawn", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=60, token_budget=10,
        )
        try:
            # Worker script reads token from FD, prints both the
            # token and the entire env (lowercased keys) so we can
            # assert the env never contains the token value.
            worker_src = (tmp_path / "worker.py")
            worker_src.write_text(
                "import os, sys\n"
                "fd = int(os.environ['RAPTOR_LLM_TOKEN_FD'])\n"
                "tok = os.read(fd, 64).decode().strip()\n"
                "os.close(fd)\n"
                "envdump = ';'.join(f'{k}={v}' for k, v in os.environ.items())\n"
                "sys.stdout.write(f'TOKEN={tok}\\nENV={envdump}\\n')\n",
                encoding="utf-8",
            )
            import subprocess
            proc = spawn_worker(
                d,
                cmd=[sys.executable, str(worker_src)],
                label="spawn-test",
                env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": os.environ.get("PYTHONPATH", "")},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(timeout=10)
            assert proc.returncode == 0, f"worker failed: {stderr.decode()}"
            output = stdout.decode()
            assert "TOKEN=" in output
            token_line = next(l for l in output.splitlines() if l.startswith("TOKEN="))
            env_line = next(l for l in output.splitlines() if l.startswith("ENV="))
            token_value = token_line[len("TOKEN="):]
            env_value = env_line[len("ENV="):]
            # The token value must not appear in env — that's the
            # whole point of FD-passing. RAPTOR_LLM_TOKEN_FD (the
            # FD number) is fine to be in env; the token VALUE is not.
            assert "RAPTOR_LLM_TOKEN_FD=" in env_value
            assert token_value not in env_value, (
                "token value leaked into worker's env — FD-passing failed"
            )
            assert len(token_value) >= 32   # url-safe 32 bytes -> 43 chars
        finally:
            d.shutdown()
