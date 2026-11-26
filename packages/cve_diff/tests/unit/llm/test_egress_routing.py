"""Egress chokepoint routing for cve-diff's provider construction.

``_provider_for_model`` builds providers directly via
``create_provider`` (never ``LLMClient``), which pre-fix meant the
in-process LLM egress chokepoint (``core.llm.egress``) never fired for
cve-diff — its SDK calls went direct, with no hostname allowlist and
no audit surface. The direct-SDK lane must now enable the chokepoint,
registering the package's own fixed fetch hosts alongside the model
endpoint; the dispatcher route and the claudecode fallback stay
mutation-free.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

import cve_diff.llm.client as client_mod
from core.testing.llm_env import reset_llm_egress_state


@pytest.fixture(autouse=True)
def _clean_egress_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset ``core.llm.egress`` flags + scrub proxy env around each test."""
    yield from reset_llm_egress_state(monkeypatch)


@pytest.fixture(autouse=True)
def _direct_sdk_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic auth resolution: direct-SDK lane for Anthropic
    models (API key present, no dispatcher socket), strict mode off."""
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_EGRESS_STRICT", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)


@pytest.fixture(autouse=True)
def _stub_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never construct a real SDK provider in these tests."""
    monkeypatch.setattr(client_mod, "create_provider", lambda config: object())


@pytest.fixture
def stub_proxy(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Replace ``core.sandbox.proxy.get_proxy`` with a recording stub
    (same shape as core/llm/tests/test_egress.py's fixture)."""
    seen_calls: list[list[str]] = []

    class _StubProxy:
        port = 51234

    def stub_get_proxy(allowed_hosts: list[str], **kwargs: object) -> _StubProxy:
        seen_calls.append(list(allowed_hosts))
        return _StubProxy()

    import core.sandbox.proxy as proxy_mod
    monkeypatch.setattr(proxy_mod, "get_proxy", stub_get_proxy)
    return seen_calls


def test_direct_sdk_lane_routes_through_chokepoint(
    stub_proxy: list[list[str]],
) -> None:
    client_mod._provider_for_model("claude-opus-4-7", 120.0)
    assert os.environ.get("HTTPS_PROXY") == "http://127.0.0.1:51234"
    registered = {h for call in stub_proxy for h in call}
    assert "api.anthropic.com" in registered


def test_package_fetch_hosts_join_allowlist(
    stub_proxy: list[list[str]],
) -> None:
    """The chokepoint's HTTPS_PROXY capture applies to every
    proxy-env-honouring transport in the process, so cve-diff's own
    UrllibClient lanes (OSV / NVD / GitHub / distro trackers) must
    join the proxy allowlist or they fail closed at the chokepoint."""
    client_mod._provider_for_model("claude-opus-4-7", 120.0)
    registered = {h for call in stub_proxy for h in call}
    assert {
        "api.osv.dev",
        "services.nvd.nist.gov",
        "api.github.com",
        "security-tracker.debian.org",
        "ubuntu.com",
        "access.redhat.com",
    } <= registered


def test_dispatcher_route_skips_chokepoint(
    stub_proxy: list[list[str]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RAPTOR_LLM_SOCKET routes via the credential-isolation dispatcher
    (UDS) — its own chokepoint; no proxy bring-up, no env mutation."""
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/run/raptor/llm.sock")
    client_mod._provider_for_model("claude-opus-4-7", 120.0)
    assert stub_proxy == []
    assert "HTTPS_PROXY" not in os.environ


def test_claudecode_fallback_stays_mutation_free(
    stub_proxy: list[list[str]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The claudecode OAuth fallback is a subprocess transport
    (cc_dispatch proxies it separately) — empty allowlist, so the
    chokepoint is a no-op and the package fetch hosts are not
    registered on a proxy that was never brought up."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client_mod._provider_for_model("claude-opus-4-7", 120.0)
    assert stub_proxy == []
    assert "HTTPS_PROXY" not in os.environ


def test_strict_abort_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bring-up failure during provider construction takes the shared
    policy: RAPTOR_LLM_EGRESS_STRICT aborts instead of degrading to
    direct, un-allowlisted outbound."""
    def boom(allowed_hosts: list[str], **kwargs: object) -> None:
        raise OSError("simulated bind failure")

    import core.sandbox.proxy as proxy_mod
    monkeypatch.setattr(proxy_mod, "get_proxy", boom)
    monkeypatch.setenv("RAPTOR_LLM_EGRESS_STRICT", "1")
    from core.llm.egress import LLMEgressBringupError
    with pytest.raises(LLMEgressBringupError):
        client_mod._provider_for_model("claude-opus-4-7", 120.0)
