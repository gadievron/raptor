"""``_build_llm_callable`` — dispatcher self-serve route bootstrap.

Synthesis is the one /audit leg that builds its own LLM client, and
standalone entry points that reach it directly (``raptor-audit backlog
drain``) are their own dispatcher parent: without a route beside the
client, every dispatch on a dispatcher-only (Bedrock-routed) primary
dies at call time and the dark rows stay dark. Contract under test:
the route comes up AFTER the client is constructed (bring-up moves
provider credentials out of the environment — a client resolved later
may see none), for both the budget-client and fresh-client branches;
an unconstructible client is the no-llm verdict, never a raise; and
absent dispatcher machinery degrades to route-less synthesis.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import core.audit.checker_synthesis as checker_synthesis
import core.llm.dispatcher.lifecycle as lifecycle
import core.llm.transcript as transcript


def _fake_client() -> SimpleNamespace:
    return SimpleNamespace(generate_structured=lambda **kwargs: None)


def _config(tmp_path, **overrides: Any) -> SimpleNamespace:
    ns = SimpleNamespace(models=["some-model"], out_dir=tmp_path)
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def test_route_comes_up_after_the_fresh_client(tmp_path, monkeypatch):
    events: list[str] = []
    fake = _fake_client()
    routed: list[tuple] = []

    def fake_build(**kwargs: Any):
        events.append("build")
        return fake

    monkeypatch.setattr(transcript, "build_llm_client", fake_build)
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_client",
        lambda client, label, run_dir=None: (
            events.append("route"),
            routed.append((client, label, run_dir)),
        ),
    )

    result = checker_synthesis._build_llm_callable(_config(tmp_path))
    assert result is not None
    _callable, client = result
    assert client is fake
    assert events == ["build", "route"]  # client first, route second
    assert routed == [(fake, "checker-synthesis", tmp_path)]


def test_budget_client_branch_also_routed(tmp_path, monkeypatch):
    fake = _fake_client()
    routed: list[tuple] = []
    built: list[dict] = []

    monkeypatch.setattr(
        transcript, "build_llm_client",
        lambda **kwargs: built.append(kwargs),
    )
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_client",
        lambda client, label, run_dir=None:
            routed.append((client, label, run_dir)),
    )

    config = _config(tmp_path, llm_budget_client=fake)
    result = checker_synthesis._build_llm_callable(config)
    assert result is not None
    assert built == []  # budget client wins; no fresh construction
    assert routed == [(fake, "checker-synthesis", tmp_path)]


def test_default_sentinel_never_pins_the_client(tmp_path, monkeypatch):
    built: list[dict] = []

    def fake_build(**kwargs: Any):
        built.append(kwargs)
        return _fake_client()

    monkeypatch.setattr(transcript, "build_llm_client", fake_build)
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_client",
        lambda client, label, run_dir=None: None,
    )

    checker_synthesis._build_llm_callable(
        _config(tmp_path, models=["default"]))
    checker_synthesis._build_llm_callable(
        _config(tmp_path, models=["pinned-model"]))
    assert built == [{}, {"pinned_model": "pinned-model"}]


def test_fresh_client_is_memoised_per_config(tmp_path, monkeypatch):
    built: list[dict] = []

    def fake_build(**kwargs: Any):
        built.append(kwargs)
        return _fake_client()

    monkeypatch.setattr(transcript, "build_llm_client", fake_build)
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_client",
        lambda client, label, run_dir=None: None,
    )

    # Same config across calls (drain: one config, one call per row) —
    # exactly one construction, the second call reuses the first
    # client. Rebuilding after route bring-up moved credentials out of
    # the environment would resolve a different transport for row 2+.
    config = _config(tmp_path)
    first = checker_synthesis._build_llm_callable(config)
    second = checker_synthesis._build_llm_callable(config)
    assert first is not None and second is not None
    assert built == [{"pinned_model": "some-model"}]
    assert second[1] is first[1]

    # A different config object still gets its own client.
    other = checker_synthesis._build_llm_callable(_config(tmp_path))
    assert other is not None
    assert built == [{"pinned_model": "some-model"}] * 2
    assert other[1] is not first[1]


def test_unconstructible_client_is_no_llm_not_a_raise(tmp_path, monkeypatch):
    def broken_build(**kwargs: Any):
        raise ValueError("pinned provider is not available")

    monkeypatch.setattr(transcript, "build_llm_client", broken_build)
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_client",
        lambda client, label, run_dir=None: None,
    )

    # One transport fact = one no-llm verdict for the caller — never
    # an exception that callers would book as per-row synthesis errors.
    assert checker_synthesis._build_llm_callable(_config(tmp_path)) is None


def test_missing_dispatcher_machinery_degrades_routeless(
        tmp_path, monkeypatch):
    fake = _fake_client()
    monkeypatch.setattr(transcript, "build_llm_client", lambda **kw: fake)
    monkeypatch.setitem(sys.modules, "core.llm.dispatcher.lifecycle", None)

    result = checker_synthesis._build_llm_callable(_config(tmp_path))
    assert result is not None
    assert result[1] is fake
