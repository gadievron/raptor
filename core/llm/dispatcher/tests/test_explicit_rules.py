"""A dedicated dispatcher must not discover unrelated ambient credentials."""

import pytest
import os

import httpx

from core.llm.dispatcher.auth import ProviderRule
from core.llm.dispatcher.server import LLMDispatcher


def test_explicit_rules_skip_credential_discovery_and_are_copied(monkeypatch):
    from core.llm.dispatcher import server

    def forbid_credentials():
        pytest.fail("explicit-rule dispatcher discovered ambient credentials")

    monkeypatch.setattr(server, "CredentialStore", forbid_credentials)
    rule = ProviderRule("anthropic", "https://api.anthropic.com", lambda: {"x-api-key": "fixture-key"})
    rules = {rule.name: rule}
    dispatcher = LLMDispatcher("explicit-rule-test", rules=rules)
    try:
        rules.clear()
        assert set(dispatcher._rules) == {"anthropic"}
        assert dispatcher._rules["anthropic"] is not rule
        assert dispatcher._rules["anthropic"].upstream_base_url == "https://api.anthropic.com"
        assert dispatcher._creds is None
    finally:
        dispatcher.shutdown()


@pytest.mark.parametrize("rules", [{}, {"wrong": ProviderRule("anthropic", "https://example.test", dict)}])
def test_invalid_explicit_rules_are_not_replaced_by_ambient_defaults(rules):
    with pytest.raises(ValueError, match="Explicit"):
        LLMDispatcher("invalid-explicit-rule", rules=rules)


@pytest.mark.parametrize("provider", ["anthropic", "gemini"])
def test_generation_plane_refuses_delegation_other_operations_and_models(provider):
    rule = ProviderRule(provider, "http://127.0.0.1:1", lambda: {"x-api-key": "fixture-key"})
    dispatcher = LLMDispatcher(
        "generation-scope", rules={provider: rule},
        generation_routes={provider: "fixture-model"}, token_budget=1,
    )
    try:
        legitimate = ("/anthropic/v1/messages" if provider == "anthropic" else
                      "/gemini/v1beta/models/fixture-model:generateContent")
        cases = [
            ("POST", "/_child/mint", b"{}"),
            ("POST", "/_token/renew", b"{}"),
            ("POST", f"/{provider}/v1/models", b"{}"),
            ("GET", legitimate, b"{}"),
            ("POST", legitimate, b'{"model":"other-model"}'),
            ("POST", legitimate, b'{"model":"fixture-model","model":"other-model"}'),
            ("POST", "/gemini/v1beta/models/other-model:generateContent", b"{}"),
        ]
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(dispatcher.socket_path))) as http:
            for method, path, body in cases:
                _, fd = dispatcher.allocate_worker("scope-test")
                try:
                    token = os.read(fd, 64).decode().strip()
                finally:
                    os.close(fd)
                response = http.request(method, "http://_" + path,
                                        headers={"X-Raptor-Token": token}, content=body)
                assert response.status_code == 403, (method, path, response.status_code)
        assert all(record.kind == "worker" for record in dispatcher._tokens.values())
    finally:
        dispatcher.shutdown()
