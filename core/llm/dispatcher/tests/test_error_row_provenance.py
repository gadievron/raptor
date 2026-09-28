"""In-flight provenance on the relay's failure-path audit rows.

Pre-fix ``request.error`` rows were flat — event/status/reason only —
so trail readers could not separate "relay belatedly noticing a worker
that had already left" (long in-flight, response never started) from a
genuine mid-response loss. The rows now carry ``response_started``
(had the worker-facing response begun — the same condition that
selects the mid-stream abort path over the stamped 502) and
``elapsed_s`` (monotonic seconds since the upstream send began), as
EXTRA KEYS ONLY: the classic row shape is unchanged for existing
consumers, which filter parsed rows by the ``event`` field.

Hermetic — captive loopback upstream, no LLM, no network.
"""

from __future__ import annotations

import json
import os
import time

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import (
    _TOKEN_HEADER,
    LLMDispatcher,
)
from core.llm.tests.mock_upstream import MockUpstream


@pytest.fixture
def fake_creds() -> CredentialStore:
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "fake-anthropic-key",
        "openai": None,
        "gemini": None,
    }
    return creds


def _make_dispatcher(
    fake_creds: CredentialStore, tmp_path, upstream: MockUpstream,
) -> LLMDispatcher:
    d = LLMDispatcher(
        run_id="error-provenance", creds=fake_creds,
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


def _post(d: LLMDispatcher, token: str) -> httpx.Response:
    transport = httpx.HTTPTransport(uds=str(d.socket_path))
    with httpx.Client(transport=transport, timeout=30.0) as client:
        return client.post(
            "http://_/anthropic/v1/messages",
            headers={_TOKEN_HEADER: token},
            content=json.dumps({"model": "m", "messages": []}),
        )


def _post_streaming(d: LLMDispatcher, token: str) -> bytes:
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
        pass
    return received


def _audit_events(d: LLMDispatcher, event: str) -> list[dict]:
    try:
        lines = d._audit_path.read_text().splitlines()
    except OSError:
        return []
    rows = [json.loads(line) for line in lines if line.strip()]
    return [r for r in rows if r.get("event") == event]


def _wait_audit(
    d: LLMDispatcher, event: str, timeout: float = 5.0,
) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = _audit_events(d, event)
        if rows:
            return rows
        time.sleep(0.05)
    return []


def _assert_classic_shape(row: dict) -> None:
    """The pre-existing row contract consumers rely on: the classic
    keys are present and typed as before — extras ride alongside."""
    assert isinstance(row["ts"], float)
    assert isinstance(row["event"], str)
    assert isinstance(row["status"], str)
    assert isinstance(row["reason"], str)


class TestErrorRowProvenance:

    def test_pre_response_failure_marks_response_not_started(
        self, fake_creds, tmp_path,
    ):
        """An upstream that dies before any response byte (fresh
        connections included, so the one stale retry is exhausted)
        yields a request.error row with response_started=False and a
        plausible in-flight duration."""
        upstream = MockUpstream("no-response-close")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            assert _post(d, token).status_code == 502
            rows = _wait_audit(d, "request.error")
            assert rows
            row = rows[0]
            _assert_classic_shape(row)
            assert row["response_started"] is False
            # Loopback death is quick; anything under the client's
            # 30s budget is plausible, negative or absent is not.
            assert isinstance(row["elapsed_s"], float)
            assert 0.0 <= row["elapsed_s"] < 30.0
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_mid_response_failure_marks_response_started(
        self, fake_creds, tmp_path,
    ):
        """A death after the response head + partial body was relayed
        yields response_started=True — the genuine mid-response-loss
        shape, distinguishable from the belated-orphan one."""
        upstream = MockUpstream("rst-mid-response")
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            _post_streaming(d, token)
            rows = _wait_audit(d, "request.error")
            assert rows
            row = rows[0]
            _assert_classic_shape(row)
            assert row["response_started"] is True
            assert isinstance(row["elapsed_s"], float)
            assert 0.0 <= row["elapsed_s"] < 30.0
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_retry_row_carries_the_same_provenance_fields(
        self, fake_creds, tmp_path,
    ):
        """request.retry shares the writer and the shape: a stale-reuse
        retry is pre-response by construction and fires within the
        retry ceiling of the send."""
        upstream = MockUpstream("half-open", idle_s=0.4)
        d = _make_dispatcher(fake_creds, tmp_path, upstream)
        try:
            token = _worker_token(d)
            assert _post(d, token).status_code == 200
            time.sleep(0.9)  # idle the pooled connection past teardown
            assert _post(d, token).status_code == 200
            rows = _wait_audit(d, "request.retry")
            assert rows
            row = rows[0]
            _assert_classic_shape(row)
            assert row["response_started"] is False
            assert isinstance(row["elapsed_s"], float)
            # Retry eligibility is gated on the stale-retry ceiling
            # (2s default) — the recorded duration must sit inside it.
            assert 0.0 <= row["elapsed_s"] <= 2.0
        finally:
            upstream.shutdown()
            d.shutdown()
