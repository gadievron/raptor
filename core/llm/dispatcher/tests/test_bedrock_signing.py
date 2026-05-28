"""Bedrock SigV4 signing-proxy tests for ``core/llm/dispatcher``.

The dispatcher rewrites a worker's stock-Anthropic ``/v1/messages``
request into a Bedrock ``InvokeModel`` call and SigV4-signs it with the
parent's AWS credentials (the worker holds none). These tests drive a
real ``httpx`` client (and the real Anthropic SDK) through the UDS, point
the bedrock rule at a captive local upstream, and assert on what the
dispatcher forwarded: the body/path transform and a well-formed SigV4
``Authorization`` header.

``botocore`` is an optional, parent-only dependency. The signing tests
skip when it's absent; the unconfigured-503 and env-hygiene tests run
unconditionally so CI (which has no botocore) still exercises the
graceful-degradation path and the credential-scrub guarantee.
"""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from core.llm.dispatcher.auth import (
    BedrockTransformError,
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
# A realistic Bedrock model id — the colon must survive into the path as
# %3A (matching boto3's own URL-encoding of modelId).
_MODEL = "anthropic.claude-3-5-sonnet-20241022-v2:0"

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
# Captive upstream — stands in for bedrock-runtime.<region>.amazonaws.com
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


def _post_bedrock(dispatcher: LLMDispatcher, body: dict) -> httpx.Response:
    socket_path, fd = dispatcher.allocate_worker(label="bedrock-test")
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
    with httpx.Client(transport=transport, timeout=10.0) as c:
        return c.post(
            "http://_/bedrock/v1/messages",
            headers={
                _TOKEN_HEADER: token,
                "Content-Type": "application/json",
                # Worker SDK leftovers the dispatcher must NOT forward:
                "x-api-key": "dummy-not-used",
                "anthropic-version": "2023-06-01",
            },
            content=json.dumps(body).encode("utf-8"),
        )


# ---------------------------------------------------------------------------
# Signing + transform (need botocore)
# ---------------------------------------------------------------------------


@needs_botocore
def test_bedrock_transform_and_sigv4(upstream, tmp_path):
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

    # Path: model moved out of the body into /model/<encoded-id>/invoke.
    assert req["path"] == f"/model/{urllib.parse.quote(_MODEL, safe='')}/invoke"

    # Body: model removed, anthropic_version added, payload preserved.
    sent = json.loads(req["body"])
    assert "model" not in sent
    assert sent["anthropic_version"] == "bedrock-2023-05-31"
    assert sent["max_tokens"] == 16
    assert sent["messages"] == [{"role": "user", "content": "ping"}]

    # Headers: worker's anthropic auth gone; SigV4 present; the signed
    # content-type/accept were actually transmitted on the wire (not just
    # declared in SignedHeaders — a dispatcher that signed then dropped
    # them would otherwise slip through).
    hdrs = req["headers"]
    assert "x-api-key" not in hdrs
    assert "anthropic-version" not in hdrs
    assert "x-amz-date" in hdrs
    assert hdrs.get("content-type") == "application/json"
    assert hdrs.get("accept") == "application/json"

    auth = hdrs["authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 ")
    assert f"Credential={_FAKE_AK}/" in auth
    assert f"/{_REGION}/bedrock/aws4_request" in auth
    sig = re.search(r"Signature=([0-9a-f]{64})\b", auth)
    assert sig, f"no 64-hex signature in {auth!r}"
    signed = re.search(r"SignedHeaders=([^,]+)", auth).group(1).split(";")
    # Match boto3's bedrock-runtime InvokeModel signed-header set exactly.
    # host is signed but never forged by us — httpx's URL-derived Host
    # must equal what SigV4 signed.
    assert set(signed) == {"accept", "content-type", "host", "x-amz-date"}


@needs_botocore
def test_bedrock_signature_matches_wire_request(upstream, tmp_path, monkeypatch):
    """Cryptographic verification, not just structural: freeze botocore's
    clock, capture the EXACT method/path/host/headers/body the dispatcher
    transmitted, independently re-sign that wire request, and assert the
    recomputed SigV4 ``Authorization`` is byte-identical. AWS verifies a
    request by performing this same recomputation, so a match proves the
    signature is valid for what actually went on the wire — and would
    FAIL if httpx altered the path encoding between signing and sending
    (the sign-here / send-there split's main risk)."""
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
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    SigV4Auth(Credentials(_FAKE_AK, _FAKE_SK), "bedrock", _REGION).add_auth(check)
    assert check.headers["X-Amz-Date"] == req["headers"]["x-amz-date"]
    assert check.headers["Authorization"] == req["headers"]["authorization"]


@needs_botocore
def test_bedrock_sdk_roundtrip(upstream, tmp_path):
    """The strongest E2E: the real Anthropic SDK, pointed at /bedrock via
    make_bedrock_client, gets a parsed Message back."""
    anthropic = pytest.importorskip("anthropic")  # noqa: F841
    from core.llm.dispatcher.client import make_bedrock_client

    endpoint, _ = upstream
    d = LLMDispatcher(
        run_id="bedrock-sdk",
        audit_path=tmp_path / "audit.jsonl",
        creds=_bedrock_store(endpoint),
    )
    try:
        socket_path, fd = d.allocate_worker(label="bedrock-sdk")
        token = os.read(fd, 64).decode().strip()
        os.close(fd)
        client = make_bedrock_client(socket_path=str(d.socket_path), token=token)
        msg = client.messages.create(
            model=_MODEL,
            max_tokens=16,
            messages=[{"role": "user", "content": "ping"}],
        )
        assert msg.content[0].text == "pong"
        assert msg.role == "assistant"
    finally:
        d.shutdown()


@needs_botocore
def test_bedrock_streaming_rejected(upstream):
    endpoint, _ = upstream
    rule = build_rules(_bedrock_store(endpoint))["bedrock"]
    body = json.dumps(
        {"model": _MODEL, "max_tokens": 8, "stream": True, "messages": []}
    ).encode()
    with pytest.raises(BedrockTransformError) as ei:
        rule.prepare_request("POST", "/v1/messages", {}, body)
    assert ei.value.status == 400
    assert "stream" in ei.value.message.lower()


@needs_botocore
def test_bedrock_missing_model_rejected(upstream):
    endpoint, _ = upstream
    rule = build_rules(_bedrock_store(endpoint))["bedrock"]
    body = json.dumps({"max_tokens": 8, "messages": []}).encode()
    with pytest.raises(BedrockTransformError) as ei:
        rule.prepare_request("POST", "/v1/messages", {}, body)
    assert ei.value.status == 400
    assert "model" in ei.value.message.lower()


@needs_botocore
def test_bedrock_invalid_json_rejected(upstream):
    endpoint, _ = upstream
    rule = build_rules(_bedrock_store(endpoint))["bedrock"]
    with pytest.raises(BedrockTransformError) as ei:
        rule.prepare_request("POST", "/v1/messages", {}, b"{not json")
    assert ei.value.status == 400


# ---------------------------------------------------------------------------
# Bedrock API-key / bearer-token auth (no botocore — CI-safe)
# ---------------------------------------------------------------------------


def test_bedrock_bearer_token_auth(upstream, tmp_path):
    """Bedrock API-key path: a static ``Authorization: Bearer`` header,
    no SigV4 (no ``x-amz-date``), no botocore — but the same body/path
    transform as the SigV4 path. Mirrors what the AWS SDKs send when
    ``AWS_BEARER_TOKEN_BEDROCK`` is set."""
    endpoint, captured = upstream
    store = CredentialStore()
    store.set_aws(bearer_token="ABSK-test-token-xyz", region=_REGION, endpoint=endpoint)
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
    assert req["path"] == f"/model/{urllib.parse.quote(_MODEL, safe='')}/invoke"
    hdrs = req["headers"]
    assert hdrs.get("authorization") == "Bearer ABSK-test-token-xyz"
    assert "x-amz-date" not in hdrs  # bearer auth, not SigV4
    assert hdrs.get("content-type") == "application/json"
    assert hdrs.get("accept") == "application/json"
    sent = json.loads(req["body"])
    assert "model" not in sent
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

    monkeypatch.setattr(auth_mod, "_build_signed_bedrock_request", _boom)

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
