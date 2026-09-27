"""``ensure_route_for_client`` — the shared self-serve dispatcher gate.

Five standalone CLIs used to open-code the same client→configs
plumbing in front of ``ensure_route_for_model_configs``; the shared
helper owns it now. Contract under test: plumb primary + fallbacks in
order under the caller's label, and NEVER raise — bring-up is
fire-and-forget, provider errors surface on the LLM call itself.
"""

from __future__ import annotations

from types import SimpleNamespace

from core.llm.dispatcher import lifecycle


def _client(primary=None, fallbacks=None):
    return SimpleNamespace(
        config=SimpleNamespace(
            primary_model=primary, fallback_models=fallbacks,
        ),
    )


def test_plumbs_primary_and_fallbacks_in_order(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_model_configs",
        lambda configs, label, run_dir=None:
            calls.append((list(configs), label, run_dir)),
    )
    primary = SimpleNamespace(provider="bedrock")
    fb1 = SimpleNamespace(provider="anthropic")
    fb2 = SimpleNamespace(provider="ollama")
    lifecycle.ensure_route_for_client(
        _client(primary, [fb1, fb2]), "test-cli",
    )
    assert calls == [([primary, fb1, fb2], "test-cli", None)]


def test_none_fallbacks_tolerated(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_model_configs",
        lambda configs, label, run_dir=None:
            calls.append((list(configs), label, run_dir)),
    )
    primary = SimpleNamespace(provider="bedrock")
    lifecycle.ensure_route_for_client(_client(primary, None), "test-cli")
    assert calls == [([primary], "test-cli", None)]


def test_never_raises_when_route_bringup_fails(monkeypatch):
    def _boom(configs, label, run_dir=None):
        raise RuntimeError("socket bind failed")
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_model_configs", _boom,
    )
    lifecycle.ensure_route_for_client(_client(), "test-cli")  # no raise


def test_never_raises_on_config_less_client(monkeypatch):
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_model_configs",
        lambda configs, label, run_dir=None: None,
    )

    class _Hostile:
        @property
        def config(self):
            raise AttributeError("no config on this client")

    lifecycle.ensure_route_for_client(_Hostile(), "test-cli")  # no raise


def test_run_dir_passes_through(monkeypatch, tmp_path):
    calls: list[tuple] = []
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_model_configs",
        lambda configs, label, run_dir=None:
            calls.append((list(configs), label, run_dir)),
    )
    primary = SimpleNamespace(provider="bedrock")
    lifecycle.ensure_route_for_client(
        _client(primary, None), "test-cli", run_dir=tmp_path,
    )
    assert calls == [([primary], "test-cli", tmp_path)]
