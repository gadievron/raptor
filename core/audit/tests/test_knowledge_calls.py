"""Admission views preserve ownership across helper threads."""
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.audit.knowledge_calls import KnowledgeCallRefused, observed_client, owned_call_scope


class Client:
    model_name = "scripted"

    def __init__(self):
        self.calls = 0
        self.ledger = object()

    def generate(self):
        self.calls += 1
        return {"ok": True}

    def generate_structured(self):
        return self.generate()


def test_owned_views_preserve_thread_admission_and_close():
    client = Client()
    entries = []
    assert observed_client(client) is client
    with owned_call_scope(lambda purpose, method: entries.append((purpose, method)) or True):
        view = observed_client(client, purpose="review")
        assert observed_client(view, purpose="review") is view
        assert view.ledger is client.ledger
        assert view.model_name == client.model_name
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(view.generate_structured).result() == {"ok": True}
        assert entries == [("review", "generate_structured")]
        assert client.calls == 1
        with owned_call_scope(lambda purpose, method: False):
            denied = observed_client(view, purpose="synthesis")
            with pytest.raises(KnowledgeCallRefused, match="unit_admission"):
                denied.generate()
        view.generate()
    assert client.calls == 2
    with pytest.raises(KnowledgeCallRefused, match="scope_closed"):
        view.generate()
    assert client.calls == 2


def test_synthesis_callable_captures_scope_without_caching_proxy(monkeypatch):
    from types import SimpleNamespace

    from core.audit.checker_synthesis import _build_llm_callable
    from core.llm.dispatcher import lifecycle
    from core.llm.providers import StructuredResponse

    class SynthesisClient(Client):
        def generate_structured(self, **kwargs):
            self.calls += 1
            return StructuredResponse(result={"rule": "scripted"}, raw="", cost=0, model="scripted")

    client = SynthesisClient()
    config = SimpleNamespace(llm_budget_client=client)
    routed = []
    monkeypatch.setattr(lifecycle, "ensure_route_for_client", lambda raw, *a, **k: routed.append(raw))
    entries = []
    with owned_call_scope(lambda purpose, method: entries.append((purpose, method)) or True):
        call, identity = _build_llm_callable(config)
        assert identity is client and config.llm_budget_client is client
        assert call("prompt", {}, "system") == {"rule": "scripted"}
    assert routed == [client]
    assert entries == [("synthesis", "generate_structured")]
    # A retained callable cannot buy another attempt after its unit closes.
    assert call("prompt", {}, "system") is None
    assert client.calls == 1
