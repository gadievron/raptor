"""Bedrock dispatcher tests — Mantle Anthropic-Messages auth-forward.

The dispatcher's bedrock rule forwards a worker's Anthropic-shape
``/v1/messages`` request to AWS Bedrock Mantle's
``/anthropic/v1/messages`` endpoint, attaching either the static bearer
token (``AWS_BEARER_TOKEN_BEDROCK``) or a SigV4 signature with the
parent's AWS credentials.  No body transformation: the worker speaks
plain Anthropic Messages, the dispatcher just signs and forwards.

These tests drive a real ``httpx`` client (and the real Anthropic SDK)
through the UDS, point the bedrock rule at a captive local upstream,
and assert on what the dispatcher forwarded: path prefixed correctly,
body verbatim, and the right auth header for each mode.

``botocore`` is an optional, parent-only dependency.  The SigV4
signing tests skip when it's absent; the unconfigured-503, bearer-
auth, and env-hygiene tests run unconditionally so CI (which has no
botocore) still exercises the graceful-degradation path and the
credential-scrub guarantee.
"""

from __future__ import annotations

import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from core.llm.dispatcher.auth import (
    CredentialStore,
    build_rules,
)
from core.llm.dispatcher.server import LLMDispatcher, _TOKEN_HEADER

try:
    import botocore  # noqa: F401

    _HAS_BOTOCORE = True
except ImportError:
    _HAS_BOTOCORE = False

needs_botocore = pytest.mark.skipif(
    not _HAS_BOTOCORE,
    reason="botocore not installed (optional parent-only dependency)",
)

# Fixture AWS creds — never real. SigV4 over these proves the parent's
# credentials (not the worker's) signed the request.
_FAKE_AK = "AKIAIOSFODNN7EXAMPLE"
_FAKE_SK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
_REGION = "us-east-1"
# Mantle accepts bare model IDs — no date suffix, no ``-v1:0`` version,
# no regional prefix.  (Per AWS docs:
# ``client.messages.create(model="anthropic.claude-opus-4-8", ...)``.)
_MODEL = "anthropic.claude-opus-4-8"

_MESSAGES_RESPONSE = {
    "id": "msg_bedrock_test",
    "type": "message",
    "role": "assistant",
    "model": _MODEL,
    "content": [{"type": "text", "text": "pong"}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 3, "output_tokens": 1},
}


# ---------------------------------------------------------------------------
# Captive upstream — stands in for bedrock-mantle.<region>.api.aws
# ---------------------------------------------------------------------------


class _CaptureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: A002 — silence stderr spam
        return

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        self.server.captured = {  # type: ignore[attr-defined]
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body,
        }
        resp = json.dumps(_MESSAGES_RESPONSE).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


@pytest.fixture
def upstream():
    """A captive HTTP server the bedrock rule forwards to. Yields
    ``(endpoint_url, get_captured)``."""
    server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    server.captured = None  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", lambda: server.captured  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()


def _bedrock_store(endpoint: str) -> CredentialStore:
    store = CredentialStore()
    store.set_aws(
        access_key=_FAKE_AK,
        secret_key=_FAKE_SK,
        region=_REGION,
        endpoint=endpoint,
    )
    return store


def _post_bedrock(
    dispatcher: LLMDispatcher,
    body: dict,
    *,
    path: str = "/bedrock/v1/messages",
) -> httpx.Response:
    """Post an Anthropic Messages request to the dispatcher's bedrock
    prefix.  Worker sends standard Anthropic shape; dispatcher forwards
    to Mantle (``/anthropic/v1/messages``) with AWS auth attached."""
    socket_path, fd = dispatcher.allocate_worker(label="bedrock-test")
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
    with httpx.Client(transport=transport, timeout=10.0) as c:
        return c.post(
            f"http://_{path}",
            headers={
                _TOKEN_HEADER: token,
                "Content-Type": "application/json",
                # Worker SDK leftover the dispatcher must NOT forward:
                "x-api-key": "dummy-not-used",
            },
            content=json.dumps(body).encode("utf-8"),
        )


# ---------------------------------------------------------------------------
# Runtime (InvokeModel) path — explicit ``/bedrock/runtime/...``
# ---------------------------------------------------------------------------


_RUNTIME_INVOKE_RESPONSE = {
    "id": "msg_bedrock_invoke",
    "type": "message",
    "role": "assistant",
    "model": _MODEL,
    "content": [{"type": "text", "text": "pong"}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 3, "output_tokens": 1},
}


def test_runtime_bearer_invoke_path(upstream, tmp_path):
    """Worker addresses ``/bedrock/runtime/v1/messages``; dispatcher
    rewrites to ``/model/<id>/invoke``, fills in ``anthropic_version``,
    and forwards with bearer auth.  The model field is MOVED into the
    URL path (no longer in the body)."""
    endpoint, captured = upstream
    store = CredentialStore()
    store.set_aws(
        bearer_token="ABSK-runtime", region=_REGION, endpoint=endpoint,
    )
    d = LLMDispatcher(
        run_id="bedrock-runtime-bearer",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d,
            {
                "model": _MODEL,
                "max_tokens": 8,
                "messages": [{"role": "user", "content": "ping"}],
            },
            path="/bedrock/runtime/v1/messages",
        )
        assert resp.status_code == 200
    finally:
        d.shutdown()

    req = captured()
    assert req is not None
    # InvokeModel URL pattern: /model/<urlencoded-id>/invoke
    assert req["path"] == f"/model/{_MODEL}/invoke"
    sent = json.loads(req["body"])
    assert "model" not in sent  # moved into URL
    assert sent["anthropic_version"] == "bedrock-2023-05-31"
    assert sent["max_tokens"] == 8
    hdrs = req["headers"]
    assert hdrs["authorization"] == "Bearer ABSK-runtime"
    assert "x-amz-date" not in hdrs  # bearer auth, not SigV4


@needs_botocore
def test_runtime_sigv4_invoke_path(upstream, tmp_path):
    """Same runtime path with SigV4 auth instead of bearer."""
    endpoint, captured = upstream
    d = LLMDispatcher(
        run_id="bedrock-runtime-sigv4",
        audit_path=tmp_path / "audit.jsonl",
        creds=_bedrock_store(endpoint),
    )
    try:
        resp = _post_bedrock(
            d,
            {
                "model": _MODEL,
                "max_tokens": 8,
                "messages": [{"role": "user", "content": "ping"}],
            },
            path="/bedrock/runtime/v1/messages",
        )
        assert resp.status_code == 200
    finally:
        d.shutdown()
    req = captured()
    assert req["path"] == f"/model/{_MODEL}/invoke"
    hdrs = req["headers"]
    assert hdrs["authorization"].startswith("AWS4-HMAC-SHA256 ")
    auth = hdrs["authorization"]
    assert f"Credential={_FAKE_AK}/" in auth
    assert f"/{_REGION}/bedrock/aws4_request" in auth


def test_runtime_rejects_streaming(upstream, tmp_path):
    """InvokeModel doesn't have a JSON-line streaming protocol (the
    streaming sibling is ``InvokeModelWithResponseStream`` with a
    different response framing).  The dispatcher rejects with a clean
    400 + actionable error message rather than forwarding."""
    endpoint, _ = upstream
    store = CredentialStore()
    store.set_aws(
        bearer_token="ABSK-stream", region=_REGION, endpoint=endpoint,
    )
    d = LLMDispatcher(
        run_id="bedrock-runtime-stream-reject",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d,
            {
                "model": _MODEL,
                "max_tokens": 8,
                "stream": True,
                "messages": [{"role": "user", "content": "ping"}],
            },
            path="/bedrock/runtime/v1/messages",
        )
        assert resp.status_code == 400
        # Operator guidance: use Mantle for streaming.
        assert "RAPTOR_BEDROCK_API=mantle" in resp.json()["error"]
    finally:
        d.shutdown()


def test_runtime_targets_bedrock_runtime_host(tmp_path, monkeypatch):
    """The runtime path's endpoint URL is the legacy bedrock-runtime
    host, NOT bedrock-mantle.  Verified by intercepting
    ``aws_bedrock_endpoint("runtime")`` — proves API selection drives
    host selection at the store layer, not just at the rule layer."""
    store = CredentialStore()
    store.set_aws(bearer_token="ABSK", region="us-east-1")
    mantle_url = store.aws_bedrock_endpoint("mantle")
    runtime_url = store.aws_bedrock_endpoint("runtime")
    assert mantle_url == "https://bedrock-mantle.us-east-1.api.aws"
    assert runtime_url == "https://bedrock-runtime.us-east-1.amazonaws.com"
    # Default (no api) → mantle, matching the operator-default contract.
    assert store.aws_bedrock_endpoint() == mantle_url


# ---------------------------------------------------------------------------
# Mantle path — signing + path-prefix forwarding (need botocore)
# ---------------------------------------------------------------------------


@needs_botocore
def test_messages_sigv4_forward(upstream, tmp_path):
    """A SigV4-signed Messages request: model + messages forwarded
    verbatim, path prefixed with ``/anthropic`` (``/v1/messages`` →
    ``/anthropic/v1/messages``), SigV4 headers correctly attached,
    worker's stale x-api-key header dropped.  ``anthropic_version``
    is injected (see ``test_anthropic_version_*``)."""
    endpoint, captured = upstream
    d = LLMDispatcher(
        run_id="bedrock-sig",
        audit_path=tmp_path / "audit.jsonl",
        creds=_bedrock_store(endpoint),
    )
    try:
        resp = _post_bedrock(
            d,
            {
                "model": _MODEL,
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "ping"}],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["content"][0]["text"] == "pong"
    finally:
        d.shutdown()

    req = captured()
    assert req is not None, "upstream never received the forwarded request"

    # Path forwarded with /anthropic prefix — Mantle, not InvokeModel.
    assert req["path"] == "/anthropic/v1/messages"

    # Body forwarded — model stays in body, anthropic_version filled
    # in (Mantle requires it), original Anthropic shape preserved.
    sent = json.loads(req["body"])
    assert sent["model"] == _MODEL
    assert sent["anthropic_version"] == "bedrock-2023-05-31"
    assert sent["max_tokens"] == 16
    assert sent["messages"] == [{"role": "user", "content": "ping"}]

    # Headers: worker's stale x-api-key gone; SigV4 present.
    hdrs = req["headers"]
    assert "x-api-key" not in hdrs
    assert hdrs.get("authorization", "").startswith("AWS4-HMAC-SHA256 ")
    assert "x-amz-date" in hdrs
    assert hdrs.get("content-type") == "application/json"

    auth = hdrs["authorization"]
    assert f"Credential={_FAKE_AK}/" in auth
    assert f"/{_REGION}/bedrock/aws4_request" in auth
    sig = re.search(r"Signature=([0-9a-f]{64})\b", auth)
    assert sig, f"no 64-hex signature in {auth!r}"


@needs_botocore
def test_messages_signature_matches_wire_request(
    upstream, tmp_path, monkeypatch,
):
    """Cryptographic verification: freeze botocore's clock, capture the
    EXACT path/host/headers/body the dispatcher transmitted,
    independently re-sign that wire request, and assert the recomputed
    SigV4 ``Authorization`` is byte-identical.  AWS verifies a request
    by performing this same recomputation, so a match proves the
    signature is valid for what actually went on the wire — and would
    FAIL if httpx altered the path encoding between signing and sending."""
    import datetime as _dt

    import botocore.auth as _ba
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    fixed = _dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=_dt.timezone.utc)
    monkeypatch.setattr(_ba, "get_current_datetime", lambda: fixed)

    endpoint, captured = upstream
    d = LLMDispatcher(
        run_id="bedrock-verify",
        audit_path=tmp_path / "audit.jsonl",
        creds=_bedrock_store(endpoint),
    )
    try:
        resp = _post_bedrock(
            d,
            {
                "model": _MODEL,
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "ping"}],
            },
        )
        assert resp.status_code == 200
    finally:
        d.shutdown()

    req = captured()
    assert req is not None
    host = endpoint.split("://", 1)[1]
    wire_url = f"http://{host}{req['path']}"
    check = AWSRequest(
        method="POST", url=wire_url, data=req["body"],
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    SigV4Auth(
        Credentials(_FAKE_AK, _FAKE_SK), "bedrock", _REGION,
    ).add_auth(check)
    assert check.headers["X-Amz-Date"] == req["headers"]["x-amz-date"]
    assert check.headers["Authorization"] == req["headers"]["authorization"]


def test_anthropic_sdk_roundtrip(upstream, tmp_path):
    """The strongest CI-friendly E2E: the real Anthropic SDK, pointed at
    ``/bedrock`` via :func:`make_bedrock_client`, gets a parsed Message
    back via the dispatcher's bearer-auth path.  No botocore needed
    (bearer mode short-circuits SigV4)."""
    pytest.importorskip("anthropic")
    from core.llm.dispatcher.client import make_bedrock_client

    endpoint, _ = upstream
    store = CredentialStore()
    store.set_aws(
        bearer_token="ABSK-roundtrip", region=_REGION, endpoint=endpoint,
    )
    d = LLMDispatcher(
        run_id="bedrock-sdk",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        socket_path, fd = d.allocate_worker(label="bedrock-sdk")
        token = os.read(fd, 64).decode().strip()
        os.close(fd)
        client = make_bedrock_client(
            socket_path=str(d.socket_path), token=token,
        )
        result = client.messages.create(
            model=_MODEL,
            max_tokens=16,
            messages=[{"role": "user", "content": "ping"}],
        )
        assert result.content[0].text == "pong"
        assert result.stop_reason == "end_turn"
    finally:
        d.shutdown()


def test_streaming_messages_passes_through(upstream, tmp_path):
    """``stream=true`` is forwarded verbatim — Mantle supports SSE
    natively via the standard Anthropic streaming protocol.  The
    dispatcher does not transform/reject; it just forwards the body
    flag through."""
    endpoint, captured = upstream
    store = CredentialStore()
    store.set_aws(
        bearer_token="ABSK-stream", region=_REGION, endpoint=endpoint,
    )
    d = LLMDispatcher(
        run_id="bedrock-stream",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d,
            {
                "model": _MODEL,
                "max_tokens": 8,
                "stream": True,
                "messages": [{"role": "user", "content": "ping"}],
            },
        )
        # The captive upstream returns JSON (not SSE), so the dispatcher
        # gets 200 — the important assertion is that the dispatcher
        # didn't REJECT streaming with a 400 like the old InvokeModel
        # path did.
        assert resp.status_code == 200
    finally:
        d.shutdown()
    sent = json.loads(captured()["body"])
    assert sent["stream"] is True   # forwarded verbatim


def test_count_tokens_path_forwarded(upstream, tmp_path):
    """The dispatcher forwards arbitrary paths under ``/bedrock/`` with
    the ``/anthropic`` prefix — not just ``/v1/messages``.
    ``/v1/messages/count_tokens`` is the obvious second one (used by
    SDKs for context budgeting)."""
    endpoint, captured = upstream
    store = CredentialStore()
    store.set_aws(
        bearer_token="ABSK-models", region=_REGION, endpoint=endpoint,
    )
    d = LLMDispatcher(
        run_id="bedrock-count",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d, {}, path="/bedrock/v1/messages/count_tokens",
        )
        assert resp.status_code == 200
    finally:
        d.shutdown()
    assert captured()["path"] == "/anthropic/v1/messages/count_tokens"


# ---------------------------------------------------------------------------
# Bedrock API-key / bearer-token auth (no botocore — CI-safe)
# ---------------------------------------------------------------------------


def test_anthropic_version_injected_when_missing(upstream, tmp_path):
    """Mantle inherits Bedrock InvokeModel's ``anthropic_version``
    requirement (``"bedrock-2023-05-31"``).  The Anthropic SDK doesn't
    add the field (the public API doesn't need it), so the dispatcher
    injects it on the way to Mantle when the worker omitted it."""
    endpoint, captured = upstream
    store = CredentialStore()
    store.set_aws(
        bearer_token="ABSK-aver", region=_REGION, endpoint=endpoint,
    )
    d = LLMDispatcher(
        run_id="bedrock-aver",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d, {"model": _MODEL, "max_tokens": 8, "messages": []}
        )
        assert resp.status_code == 200
    finally:
        d.shutdown()
    sent = json.loads(captured()["body"])
    assert sent["anthropic_version"] == "bedrock-2023-05-31"


def test_anthropic_version_operator_value_preserved(upstream, tmp_path):
    """An operator who deliberately set a different ``anthropic_version``
    (e.g. a future-dated schema version) should see their value
    forwarded — the dispatcher only fills the slot when missing."""
    endpoint, captured = upstream
    store = CredentialStore()
    store.set_aws(
        bearer_token="ABSK-aver", region=_REGION, endpoint=endpoint,
    )
    d = LLMDispatcher(
        run_id="bedrock-aver-pre",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d,
            {
                "model": _MODEL,
                "max_tokens": 8,
                "messages": [],
                "anthropic_version": "bedrock-2099-12-31",
            },
        )
        assert resp.status_code == 200
    finally:
        d.shutdown()
    sent = json.loads(captured()["body"])
    assert sent["anthropic_version"] == "bedrock-2099-12-31"


def test_messages_bearer_auth(upstream, tmp_path):
    """Bedrock API-key path: a static ``Authorization: Bearer`` header,
    no SigV4, no botocore — body and path forwarded verbatim.  Mirrors
    what the AWS SDKs send when ``AWS_BEARER_TOKEN_BEDROCK`` is set."""
    endpoint, captured = upstream
    store = CredentialStore()
    store.set_aws(
        bearer_token="ABSK-test-token-xyz",
        region=_REGION, endpoint=endpoint,
    )
    d = LLMDispatcher(
        run_id="bedrock-bearer",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d,
            {
                "model": _MODEL,
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "ping"}],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["content"][0]["text"] == "pong"
    finally:
        d.shutdown()

    req = captured()
    assert req["path"] == "/anthropic/v1/messages"
    hdrs = req["headers"]
    assert hdrs.get("authorization") == "Bearer ABSK-test-token-xyz"
    assert "x-amz-date" not in hdrs  # bearer auth, not SigV4
    assert hdrs.get("content-type") == "application/json"
    # Body forwarded — model stays in body, Anthropic shape preserved,
    # ``anthropic_version`` injected by the dispatcher.
    sent = json.loads(req["body"])
    assert sent["model"] == _MODEL
    assert sent["anthropic_version"] == "bedrock-2023-05-31"


def test_bedrock_bearer_precedence_over_sigv4(upstream, tmp_path):
    """When both a bearer token and SigV4 keys are present, bearer wins
    (matching the AWS SDKs) — proven by the absence of a SigV4 date and
    the presence of the Bearer header. Needs no botocore precisely
    because the bearer branch short-circuits before aws_signer()."""
    endpoint, captured = upstream
    store = CredentialStore()
    store.set_aws(
        access_key=_FAKE_AK, secret_key=_FAKE_SK,
        bearer_token="ABSK-wins", region=_REGION, endpoint=endpoint,
    )
    d = LLMDispatcher(
        run_id="bedrock-precedence",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d, {"model": _MODEL, "max_tokens": 8, "messages": []}
        )
        assert resp.status_code == 200
    finally:
        d.shutdown()

    hdrs = captured()["headers"]
    assert hdrs.get("authorization") == "Bearer ABSK-wins"
    assert "x-amz-date" not in hdrs


def test_bedrock_bearer_without_region_503(tmp_path, monkeypatch):
    """A bearer token with no resolvable region can't build the regional
    host → unconfigured → 503. SigV4 fallback forced off so the result is
    deterministic regardless of ambient AWS creds/botocore."""
    store = CredentialStore()
    store.set_aws(bearer_token="ABSK-x")
    store._aws_region = None
    monkeypatch.setattr(store, "aws_signer", lambda: None)
    assert build_rules(store)["bedrock"].is_configured() is False

    d = LLMDispatcher(
        run_id="bedrock-noregion",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d, {"model": _MODEL, "max_tokens": 8, "messages": []}
        )
        assert resp.status_code == 503
    finally:
        d.shutdown()


# ---------------------------------------------------------------------------
# Graceful degradation + env hygiene (run WITHOUT botocore — CI-safe)
# ---------------------------------------------------------------------------


def test_bedrock_unconfigured_returns_503(tmp_path, monkeypatch):
    """No usable AWS signer (botocore missing / no creds) → 503, the same
    UX as any unconfigured provider. Forced deterministically so the test
    is independent of the ambient AWS credential chain."""
    store = CredentialStore()
    monkeypatch.setattr(store, "aws_signer", lambda: None)
    assert build_rules(store)["bedrock"].is_configured() is False

    d = LLMDispatcher(
        run_id="bedrock-503",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d, {"model": _MODEL, "max_tokens": 8, "messages": []}
        )
        assert resp.status_code == 503
        assert "bedrock" in resp.json()["error"]
    finally:
        d.shutdown()


def test_bedrock_signing_failure_returns_502(tmp_path, monkeypatch):
    """A signing failure that is NOT a BedrockTransformError — e.g. a
    botocore credential refresh raising inside SigV4Auth.add_auth when an
    SSO/IMDS token expires mid-run — is mapped to a clean 502 + audit row,
    not an exception that escapes the handler thread and drops the worker's
    connection. Runs without botocore: the signer is faked configured and
    the transform is forced to raise."""
    import core.llm.dispatcher.auth as auth_mod

    store = CredentialStore()
    # Configured (so we get past the 503 gate) ...
    monkeypatch.setattr(
        store, "aws_signer",
        lambda: ("creds", _REGION, "https://x.invalid"),
    )
    # ... but signing blows up the way a credential refresh would.
    def _boom(*a, **k):
        raise RuntimeError("simulated credential refresh failure")

    monkeypatch.setattr(
        auth_mod, "_build_signed_mantle_request", _boom,
    )

    d = LLMDispatcher(
        run_id="bedrock-502",
        audit_path=tmp_path / "audit.jsonl",
        creds=store,
    )
    try:
        resp = _post_bedrock(
            d, {"model": _MODEL, "max_tokens": 8, "messages": []}
        )
        assert resp.status_code == 502
        assert "signing failed" in resp.json()["error"]
    finally:
        d.shutdown()

    audit = (tmp_path / "audit.jsonl").read_text()
    assert "provider.transform_error" in audit

def test_aws_secrets_popped_from_env(monkeypatch):
    """AWS secret env vars are read-and-erased at CredentialStore
    construction — so they're gone from os.environ before any worker is
    spawned (the same isolation the other provider keys get)."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _FAKE_AK)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _FAKE_SK)
    monkeypatch.setenv("AWS_SESSION_TOKEN", "session-token-xyz")
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "ABSK-bearer-secret")
    monkeypatch.setenv("AWS_REGION", _REGION)

    store = CredentialStore()

    # Secrets erased from the live environment...
    assert "AWS_ACCESS_KEY_ID" not in os.environ
    assert "AWS_SECRET_ACCESS_KEY" not in os.environ
    assert "AWS_SESSION_TOKEN" not in os.environ
    assert "AWS_BEARER_TOKEN_BEDROCK" not in os.environ
    # ...but captured in the parent's store.
    assert store.get("aws_access_key_id") == _FAKE_AK
    assert store.get("aws_secret_access_key") == _FAKE_SK
    assert store.get("aws_session_token") == "session-token-xyz"
    assert store.get("aws_bearer_token") == "ABSK-bearer-secret"
    # Region is not a secret and stays readable.
    assert store._aws_region == _REGION
    assert os.environ.get("AWS_REGION") == _REGION
