"""Child-plane path confinement: a scoped child token reaches ONLY
the Messages endpoints.

The attack: the
child-plane authorization checked provider prefix, POST, model-in-body,
and budget — never the upstream PATH. A prompt-injected CC child drove
the operator's real x-api-key against ``/v1/messages/batches``
(deferred-cost: no usage frame streams back, so the ledger booked $0
while real provider spend accrued), ``/v1/files`` (cross-run data
persistence in the operator's account), and
``/v1/organizations/api_keys``.

Post-fix contract: child tokens may reach exactly ``/v1/messages`` and
``/v1/messages/count_tokens`` (query strings allowed); every other
upstream path is refused 403 before the forward leg, so nothing
reaches the provider and nothing is reserved or spent. The deferred-
cost batch lane is closed by construction — batches are denied, so no
usage-frame-less spend can book $0.
"""

from __future__ import annotations

import json

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import LLMDispatcher

_PRICED_MODEL = "claude-opus-4-8"


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
    from core.llm.dispatcher.tests.test_child_tokens import _Upstream

    upstream = _Upstream("json")
    d = LLMDispatcher(
        run_id="child-paths", creds=fake_creds,
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
        yield d, upstream
    finally:
        d.shutdown()
        upstream.shutdown()


def _child_client(d: LLMDispatcher) -> httpx.Client:
    transport = httpx.HTTPTransport(uds=str(d.child_socket_path))
    return httpx.Client(transport=transport, timeout=10.0)


def _post(client, token, path, payload=None):
    return client.post(
        f"http://_{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        content=json.dumps(payload if payload is not None else {
            "model": _PRICED_MODEL, "max_tokens": 16, "messages": [],
        }).encode(),
    )


# Probe set: every payload satisfies the
# model-in-body gate the old enforcement stopped at.
_FORBIDDEN_PATHS = [
    ("/anthropic/v1/messages/batches",
     {"model": _PRICED_MODEL,
      "requests": [{"custom_id": "x", "params": {}}]}),
    ("/anthropic/v1/files?beta=true",
     {"model": _PRICED_MODEL, "purpose": "user_data"}),
    ("/anthropic/v1/organizations/api_keys",
     {"model": _PRICED_MODEL}),
    # Prefix/suffix probes around the allowlisted endpoint.
    ("/anthropic/v1/messages/batches/b_123", {"model": _PRICED_MODEL}),
    ("/anthropic/v1/messagesx", {"model": _PRICED_MODEL}),
    ("/anthropic/v1", {"model": _PRICED_MODEL}),
    # The Bedrock runtime surface stays out (proxy children are
    # Mantle-forced); mantle-shaped probes off the Messages endpoints
    # stay out too.
    ("/anthropic/runtime/v1/messages", {"model": _PRICED_MODEL}),
    ("/anthropic/mantle/v1/files", {"model": _PRICED_MODEL}),
]


class TestChildPathAllowlist:
    def test_non_messages_paths_refused_and_never_forwarded(
            self, dispatcher):
        d, upstream = dispatcher
        token, info = d.allocate_child(
            "probe-child", budget_usd=1.0, models=[_PRICED_MODEL],
            ttl_s=600,
        )
        with _child_client(d) as client:
            for path, payload in _FORBIDDEN_PATHS:
                resp = _post(client, token, path, payload)
                assert resp.status_code == 403, (
                    f"{path} → {resp.status_code}: {resp.text}"
                )
                assert "upstream path" in resp.text
        # Nothing reached the provider; nothing was booked.
        assert upstream.requests == []
        spend = d.child_spend(info["token_id"]) or {}
        assert not spend.get("spent_usd")

    def test_messages_path_still_allowed(self, dispatcher):
        d, upstream = dispatcher
        token, _info = d.allocate_child(
            "cc-child", budget_usd=1.0, models=[_PRICED_MODEL],
            ttl_s=600,
        )
        with _child_client(d) as client:
            resp = _post(client, token, "/anthropic/v1/messages")
            assert resp.status_code == 200, resp.text
            # Query strings on the allowlisted path survive.
            resp2 = _post(
                client, token, "/anthropic/v1/messages?beta=true",
            )
            assert resp2.status_code == 200, resp2.text
        assert len(upstream.requests) == 2

    def test_count_tokens_path_still_allowed(self, dispatcher):
        d, upstream = dispatcher
        token, _info = d.allocate_child(
            "cc-child", budget_usd=1.0, models=[_PRICED_MODEL],
            ttl_s=600,
        )
        with _child_client(d) as client:
            resp = _post(
                client, token, "/anthropic/v1/messages/count_tokens",
            )
        assert resp.status_code == 200, resp.text
        assert upstream.requests[0]["path"].startswith(
            "/v1/messages/count_tokens",
        )

    def test_worker_tokens_unaffected(self, dispatcher):
        # The path pin scopes CHILD tokens; full-power worker tokens
        # keep their existing surface (they never ride the child
        # plane's containment story).
        import os as _os

        d, upstream = dispatcher
        _, fd = d.allocate_worker(label="test-worker")
        worker_token = _os.read(fd, 64).decode().strip()
        _os.close(fd)
        transport = httpx.HTTPTransport(uds=str(d.socket_path))
        with httpx.Client(transport=transport, timeout=10.0) as client:
            resp = _post(
                client, worker_token, "/anthropic/v1/messages/batches",
                {"model": _PRICED_MODEL, "requests": []},
            )
        assert resp.status_code == 200, resp.text


class TestAllowlistComposesWithCostFreeExemption:
    """The path allowlist and the cost-free count_tokens exemption both
    key on the upstream path; these pins prove the composition holds
    in both directions: the exemption still works for admitted paths,
    and it is unreachable for everything the allowlist refuses."""

    def test_count_tokens_admitted_and_exempt_priced_path_reserves(
            self, dispatcher):
        d, _upstream = dispatcher
        token, _info = d.allocate_child(
            "cc-child", budget_usd=1.0, models=[_PRICED_MODEL],
            ttl_s=600,
        )
        rec = d._tokens[token]
        body = json.dumps({
            "model": _PRICED_MODEL, "messages": [],
        }).encode()
        # Admitted cost-free endpoint: allowed with NOTHING reserved.
        deny, reserved = d._authorize_child_request(
            rec, "anthropic", "POST", body,
            "/v1/messages/count_tokens",
        )
        assert deny is None
        assert reserved == 0.0
        d._release_child_reservation(rec, reserved)
        # Admitted priced endpoint: allowed with a real reservation
        # (bounded max_tokens keeps the ceiling inside the budget).
        priced_body = json.dumps({
            "model": _PRICED_MODEL, "max_tokens": 100, "messages": [],
        }).encode()
        deny, reserved = d._authorize_child_request(
            rec, "anthropic", "POST", priced_body, "/v1/messages",
        )
        assert deny is None
        assert reserved > 0.0
        d._release_child_reservation(rec, reserved)

    def test_count_tokens_exemption_survives_small_budget(
            self, dispatcher):
        # The exemption's purpose: a budget smaller than the priced
        # full-window ceiling must still admit count_tokens (no
        # max_tokens in the body → ceiling fallback would 402 it).
        d, _upstream = dispatcher
        token, _info = d.allocate_child(
            "cc-child", budget_usd=0.01, models=[_PRICED_MODEL],
            ttl_s=600,
        )
        rec = d._tokens[token]
        body = json.dumps({
            "model": _PRICED_MODEL, "messages": [],
        }).encode()
        deny, reserved = d._authorize_child_request(
            rec, "anthropic", "POST", body,
            "/v1/messages/count_tokens",
        )
        assert deny is None and reserved == 0.0
        d._release_child_reservation(rec, reserved)
        deny, _ = d._authorize_child_request(
            rec, "anthropic", "POST", body, "/v1/messages",
        )
        assert deny is not None and deny[0] == 402

    def test_cost_free_looking_path_outside_allowlist_still_403(
            self, dispatcher):
        # The exemption composes BEHIND the allowlist: a path that
        # merely ENDS with /count_tokens must be refused before any
        # reservation logic, never forwarded reservation-free.
        d, upstream = dispatcher
        token, info = d.allocate_child(
            "probe-child", budget_usd=1.0, models=[_PRICED_MODEL],
            ttl_s=600,
        )
        with _child_client(d) as client:
            resp = _post(
                client, token, "/anthropic/v1/foo/count_tokens",
            )
        assert resp.status_code == 403, resp.text
        assert "upstream path" in resp.text
        assert upstream.requests == []
        spend = d.child_spend(info["token_id"]) or {}
        assert not spend.get("spent_usd")

    def test_fragment_target_rejected_400_before_both_checks(
            self, dispatcher):
        # RFC 7230 fragment rejection (the composed queue's gate)
        # fires pre-routing; the masquerade path never reaches the
        # allowlist or the exemption. Raw socket — HTTP clients strip
        # fragments client-side and would hide the shape.
        import socket as _socket

        d, upstream = dispatcher
        token, _info = d.allocate_child(
            "probe-child", budget_usd=1.0, models=[_PRICED_MODEL],
            ttl_s=600,
        )
        payload = json.dumps({
            "model": _PRICED_MODEL, "messages": [],
        }).encode()
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.connect(str(d.child_socket_path))
        req = (
            f"POST /anthropic/v1/messages#/count_tokens HTTP/1.1\r\n"
            f"Host: d\r\nAuthorization: Bearer {token}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode() + payload
        s.sendall(req)
        s.settimeout(10)
        head = s.recv(4096).split(b"\r\n", 1)[0]
        s.close()
        assert b"400" in head, head
        assert upstream.requests == []
