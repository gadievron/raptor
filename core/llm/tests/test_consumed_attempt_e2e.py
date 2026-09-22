"""Spend-aware retry gate, end-to-end through the real dispatcher.

Full worker stack: ``LLMClient`` retry loop → ``AnthropicProvider`` →
real Anthropic SDK → dispatcher UDS httpx client (attempt-state hooks)
→ real ``LLMDispatcher`` → captive keep-alive upstream
(``mock_upstream``). Pins the series' contract at the wire:

* mid-response death (upstream processed and billed, then the wire
  died) → the worker does NOT re-send: upstream handles the request
  exactly once and the failure surfaces the distinct error class;
* pre-response death → the worker's retry budget is preserved;
* ``RAPTOR_LLM_RETRY_CONSUMED=1`` → the operator's paid re-sends
  actually happen.

Hermetic — captive loopback upstream, no LLM, no network egress.
"""

from __future__ import annotations

import json
import os
import time

import pytest

anthropic = pytest.importorskip("anthropic")

import core.llm.dispatcher.client as dispatcher_client  # noqa: E402
from core.llm.client import LLMClient, MidResponseDeathError  # noqa: E402
from core.llm.config import LLMConfig, ModelConfig  # noqa: E402
from core.llm.dispatcher.auth import (  # noqa: E402
    CredentialStore,
    ProviderRule,
)
from core.llm.dispatcher.server import LLMDispatcher  # noqa: E402
from core.llm.tests.mock_upstream import MockUpstream  # noqa: E402

# Deliberately NOT marked ``integration``: that marker means live
# network and is deselected by default, while everything here is a
# captive loopback upstream behind a real dispatcher UDS — hermetic
# and fast enough for the default tier, where the series' strongest
# pin belongs.


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "fake-anthropic-key",
        "openai": None,
        "gemini": None,
    }
    return creds


@pytest.fixture
def _no_sleep(monkeypatch):
    import core.llm.client as client_mod
    monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)


def _wire(fake_creds, tmp_path, upstream, monkeypatch) -> LLMDispatcher:
    """Dispatcher fronting *upstream*, with THIS process set up as its
    worker (socket env + cached token, as spawn_worker would)."""
    d = LLMDispatcher(
        run_id="consumed-e2e", creds=fake_creds,
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
    _, fd = d.allocate_worker(label="consumed-e2e-worker")
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", str(d.socket_path))
    monkeypatch.setattr(dispatcher_client, "_cached_token", token)
    return d


def _llm_client(max_retries: int) -> LLMClient:
    primary = ModelConfig(
        provider="anthropic", model_name="claude-test",
        api_key="unused-on-dispatcher-path", timeout=15,
    )
    return LLMClient(LLMConfig(
        primary_model=primary, fallback_models=[],
        enable_caching=False, max_retries=max_retries,
        enable_fallback=False,
    ))


def _audit_events(d: LLMDispatcher, event: str) -> list[dict]:
    try:
        lines = d._audit_path.read_text().splitlines()
    except OSError:
        return []
    rows = [json.loads(line) for line in lines if line.strip()]
    return [r for r in rows if r.get("event") == event]


def _wait_processed(upstream: MockUpstream, n: int, timeout: float = 5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if upstream.counters()["requests_processed"] >= n:
            return
        time.sleep(0.05)


class TestConsumedAttemptE2E:

    def test_mid_response_death_upstream_processes_exactly_once(
        self, fake_creds, tmp_path, monkeypatch, _no_sleep, caplog,
    ):
        """The measured defect, closed: a generation that dies
        mid-response through the whole real stack is bought once, not
        once per retry attempt."""
        upstream = MockUpstream("rst-mid-response")
        d = _wire(fake_creds, tmp_path, upstream, monkeypatch)
        try:
            client = _llm_client(max_retries=3)
            with caplog.at_level("WARNING", logger="core.llm.client"):
                with pytest.raises(RuntimeError) as excinfo:
                    client.generate("hello")
            # Upstream handled the request EXACTLY once — the retry
            # loop did not re-send the consumed generation.
            assert upstream.counters()["requests_processed"] == 1
            assert isinstance(
                excinfo.value.__cause__, MidResponseDeathError,
            )
            assert any(
                "NOT re-sending" in r.message for r in caplog.records
            )
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_pre_response_death_keeps_worker_retry(
        self, fake_creds, tmp_path, monkeypatch, _no_sleep,
    ):
        """An upstream that dies before any response byte keeps the
        pre-existing recovery path: the dispatcher answers 502
        (stamped pre-response) and the worker spends its full retry
        budget — one request.error audit row per worker attempt."""
        upstream = MockUpstream("no-response-close")
        d = _wire(fake_creds, tmp_path, upstream, monkeypatch)
        try:
            client = _llm_client(max_retries=2)
            with pytest.raises(RuntimeError):
                client.generate("hello")
            assert len(_audit_events(d, "request.error")) == 2
            # Each worker attempt reached the upstream (this mock
            # reads every request before dying — including the
            # dispatcher's own bounded fresh-connection retry, so
            # strictly more sends than worker attempts).
            assert upstream.counters()["requests_processed"] >= 2
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_escape_hatch_resends_through_the_real_stack(
        self, fake_creds, tmp_path, monkeypatch, _no_sleep, caplog,
    ):
        """RAPTOR_LLM_RETRY_CONSUMED=1: the operator's chosen re-buys
        really happen — upstream processes once per worker attempt,
        each named a re-purchase."""
        monkeypatch.setenv("RAPTOR_LLM_RETRY_CONSUMED", "1")
        upstream = MockUpstream("rst-mid-response")
        d = _wire(fake_creds, tmp_path, upstream, monkeypatch)
        try:
            client = _llm_client(max_retries=2)
            with caplog.at_level("WARNING", logger="core.llm.client"):
                with pytest.raises(RuntimeError):
                    client.generate("hello")
            _wait_processed(upstream, 2)
            assert upstream.counters()["requests_processed"] == 2
            assert sum(
                "re-buys the generation" in r.message
                for r in caplog.records
            ) == 2
        finally:
            upstream.shutdown()
            d.shutdown()
