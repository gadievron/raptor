"""``client_with_session_fallback`` — session transport for
dispatcher-only chains.

Contract under test: after the normal self-serve route attempt, a
client whose whole model chain is dispatcher-only (Bedrock) with
still no ``RAPTOR_LLM_SOCKET`` is swapped for a claudecode
session-transport client (the /agentic --gap-audit mechanism); with
no session transport either the caller gets ``None`` plus exactly ONE
notice. Everything else — routed chains, mixed chains, uninspectable
test fakes — passes through unchanged, and the helper never raises.

CI hermeticity: no network, no AWS, no dispatcher socket, no real
LLM. The route gate, the claudecode config builder, and the client
factory are all monkeypatched at their defining modules (the module
under test imports them at call time).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from core.llm import session_fallback
from core.llm.session_fallback import (
    FALLBACK_TAKEN_NOTICE,
    NO_TRANSPORT_NOTICE,
    OPT_OUT_ENV,
    client_with_session_fallback,
)


def _client(primary: Any = None, fallbacks: Any = None) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(
            primary_model=primary, fallback_models=fallbacks,
        ),
    )


def _bedrock() -> SimpleNamespace:
    return SimpleNamespace(provider="bedrock")


@pytest.fixture
def no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)
    monkeypatch.delenv(OPT_OUT_ENV, raising=False)


@pytest.fixture
def route_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Neutralise the real self-serve gate (no in-process dispatcher
    in tests) and record how it was invoked."""
    from core.llm.dispatcher import lifecycle
    calls: list[tuple] = []
    monkeypatch.setattr(
        lifecycle, "ensure_route_for_client",
        lambda client, label, run_dir=None:
            calls.append((client, label, run_dir)),
    )
    return calls


@pytest.fixture
def notices() -> list[str]:
    return []


def _no_claudecode(monkeypatch: pytest.MonkeyPatch) -> None:
    from core.llm import config as llm_config
    monkeypatch.setattr(llm_config, "_build_claudecode_config",
                        lambda: None)


def _claudecode_available(
    monkeypatch: pytest.MonkeyPatch, fallback_client: Any,
) -> list[Any]:
    """Fake claudecode config + factory; returns the configs the
    factory received."""
    from core.llm import config as llm_config, factory
    cc = SimpleNamespace(provider="claudecode")
    monkeypatch.setattr(llm_config, "_build_claudecode_config", lambda: cc)
    got: list[Any] = []
    def _get_client(config: Any = None, **kw: Any) -> Any:
        got.append(config)
        return fallback_client
    monkeypatch.setattr(factory, "get_client", _get_client)
    return got


def test_socket_present_returns_client_unchanged(
    monkeypatch, route_calls, notices,
):
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/fake.sock")
    client = _client(_bedrock(), [])
    out = client_with_session_fallback(client, "t", notice=notices.append)
    assert out is client
    assert notices == []


def test_non_dispatcher_chain_unchanged(no_socket, route_calls, notices,
                                        monkeypatch):
    _no_claudecode(monkeypatch)  # must not matter: never consulted
    client = _client(SimpleNamespace(provider="anthropic"), [])
    out = client_with_session_fallback(client, "t", notice=notices.append)
    assert out is client
    assert notices == []


def test_mixed_chain_keeps_configured_fallbacks(no_socket, route_calls,
                                                notices, monkeypatch):
    _no_claudecode(monkeypatch)
    client = _client(_bedrock(), [SimpleNamespace(provider="ollama")])
    out = client_with_session_fallback(client, "t", notice=notices.append)
    assert out is client
    assert notices == []


def test_dead_dispatcher_chain_falls_back_to_claudecode(
    no_socket, route_calls, notices, monkeypatch,
):
    marker = object()
    got = _claudecode_available(monkeypatch, marker)
    client = _client(_bedrock(), [_bedrock()])
    out = client_with_session_fallback(client, "t", notice=notices.append)
    assert out is marker
    assert notices == [FALLBACK_TAKEN_NOTICE]
    # The fallback chain is claudecode-only: no dispatcher-only entry
    # rides along to reintroduce per-call refusals.
    (cfg,) = got
    assert cfg.primary_model.provider == "claudecode"
    assert cfg.fallback_models == []


def test_no_transport_returns_none_with_single_notice(
    no_socket, route_calls, notices, monkeypatch,
):
    _no_claudecode(monkeypatch)
    from core.llm import factory
    monkeypatch.setattr(
        factory, "get_client",
        lambda *a, **k: pytest.fail("factory consulted without a "
                                    "claudecode config"),
    )
    out = client_with_session_fallback(
        _client(_bedrock(), []), "t", notice=notices.append)
    assert out is None
    assert notices == [NO_TRANSPORT_NOTICE]


def test_factory_none_means_no_transport(no_socket, route_calls, notices,
                                         monkeypatch):
    got = _claudecode_available(monkeypatch, None)
    out = client_with_session_fallback(
        _client(_bedrock(), []), "t", notice=notices.append)
    assert out is None
    assert got  # factory WAS consulted
    assert notices == [NO_TRANSPORT_NOTICE]


def test_uninspectable_client_passes_through(no_socket, route_calls,
                                             notices):
    class Opaque:
        @property
        def config(self) -> Any:
            raise AttributeError("no config on this fake")
    client = Opaque()
    out = client_with_session_fallback(client, "t", notice=notices.append)
    assert out is client
    assert notices == []


def test_empty_chain_passes_through(no_socket, route_calls, notices):
    client = _client(None, [])
    out = client_with_session_fallback(client, "t", notice=notices.append)
    assert out is client
    assert notices == []


def test_route_gate_still_runs_first_with_run_dir(
    no_socket, route_calls, notices, monkeypatch, tmp_path,
):
    _no_claudecode(monkeypatch)
    client = _client(_bedrock(), [])
    client_with_session_fallback(client, "my-label", run_dir=tmp_path,
                                 notice=notices.append)
    assert route_calls == [(client, "my-label", tmp_path)]


def test_route_gate_error_is_contained(no_socket, notices, monkeypatch):
    from core.llm.dispatcher import lifecycle
    def _boom(client: Any, label: str, run_dir: Any = None) -> None:
        raise RuntimeError("self-serve exploded")
    monkeypatch.setattr(lifecycle, "ensure_route_for_client", _boom)
    _no_claudecode(monkeypatch)
    out = client_with_session_fallback(
        _client(_bedrock(), []), "t", notice=notices.append)
    # Gate error contained; the dead chain still degrades cleanly.
    assert out is None
    assert notices == [NO_TRANSPORT_NOTICE]


def test_fallback_construction_error_never_raises(
    no_socket, route_calls, notices, monkeypatch,
):
    from core.llm import config as llm_config
    monkeypatch.setattr(
        llm_config, "_build_claudecode_config",
        lambda: (_ for _ in ()).throw(RuntimeError("builder exploded")),
    )
    client = _client(_bedrock(), [])
    out = client_with_session_fallback(client, "t", notice=notices.append)
    # Unexpected internal error: original client preserved (call-time
    # errors surface on the LLM call, the pre-existing behaviour).
    assert out is client


@pytest.mark.parametrize("spelling", ["1", "true", "yes", "on", "TRUE"])
def test_optout_knob_disables_swap_entirely(no_socket, route_calls,
                                            notices, monkeypatch,
                                            spelling: str):
    """RAPTOR_NO_SESSION_FALLBACK restores the plain refusal
    behaviour: the dead dispatcher-only chain is returned as-is, no
    session client is constructed, no notice is emitted.

    Parametrized over the canonical truthy spellings the docs row
    promises (``core.config.env_flag`` contract, case-insensitive) —
    a raw ``== "1"`` compare must NOT survive this test."""
    monkeypatch.setenv(OPT_OUT_ENV, spelling)
    from core.llm import config as llm_config, factory
    monkeypatch.setattr(
        llm_config, "_build_claudecode_config",
        lambda: pytest.fail("claudecode builder consulted despite the "
                            "opt-out"),
    )
    monkeypatch.setattr(
        factory, "get_client",
        lambda *a, **k: pytest.fail("factory consulted despite the "
                                    "opt-out"),
    )
    client = _client(_bedrock(), [_bedrock()])
    out = client_with_session_fallback(client, "t", notice=notices.append)
    assert out is client
    assert notices == []
    # The self-serve route attempt still ran (BASE behaviour kept).
    assert len(route_calls) == 1


def test_optout_knob_unset_still_swaps(no_socket, route_calls, notices,
                                       monkeypatch):
    """Two-direction pin for the opt-out: with the knob unset (the
    fixture deletes it) the swap is the commissioned default."""
    marker = object()
    _claudecode_available(monkeypatch, marker)
    out = client_with_session_fallback(
        _client(_bedrock(), []), "t", notice=notices.append)
    assert out is marker
    assert notices == [FALLBACK_TAKEN_NOTICE]


def test_fallback_notice_names_the_optout_env() -> None:
    """The operator learns of the knob exactly when the swap first
    fires — the notice line must name it."""
    assert OPT_OUT_ENV in FALLBACK_TAKEN_NOTICE


def test_fallback_config_pins_fallback_list_empty(no_socket, route_calls,
                                                  notices, monkeypatch):
    """The swap must pass ``fallback_models=[]`` EXPLICITLY.

    ``LLMConfig``'s field default_factory is bound at class creation,
    so patching ``_get_default_fallback_models`` cannot exercise the
    pin — and on a credential-less CI host the real default factory
    returns ``[]`` anyway, which would let an unpinned construction
    (mutant: drop ``fallback_models=[]``) pass vacuously. A shim
    config class whose default fallback list is a poison
    dispatcher-only entry makes the omission observable."""
    import dataclasses

    from core.llm import config as llm_config, factory

    @dataclasses.dataclass
    class ShimLLMConfig:
        primary_model: Any = None
        fallback_models: list = dataclasses.field(
            default_factory=lambda: [SimpleNamespace(provider="bedrock")])

    monkeypatch.setattr(llm_config, "LLMConfig", ShimLLMConfig)
    monkeypatch.setattr(
        llm_config, "_build_claudecode_config",
        lambda: SimpleNamespace(provider="claudecode"),
    )
    received: list = []
    marker = object()

    def _get_client(config: Any = None, **kw: Any) -> Any:
        received.append(config)
        return marker

    monkeypatch.setattr(factory, "get_client", _get_client)
    out = client_with_session_fallback(
        _client(_bedrock(), []), "t", notice=notices.append)
    assert out is marker
    (cfg,) = received
    assert cfg.fallback_models == []


def test_raising_notice_sink_keeps_fallback_client(no_socket, route_calls,
                                                   monkeypatch):
    """A broken notice sink must not discard the constructed session
    client (it previously leaked away as the dead client via the
    outer never-raise net)."""
    marker = object()
    _claudecode_available(monkeypatch, marker)

    def _boom_notice(msg: str) -> None:
        raise RuntimeError("notice sink exploded")

    out = client_with_session_fallback(
        _client(_bedrock(), []), "t", notice=_boom_notice)
    assert out is marker


def test_raising_notice_sink_keeps_none_degrade(no_socket, route_calls,
                                                monkeypatch):
    _no_claudecode(monkeypatch)

    def _boom_notice(msg: str) -> None:
        raise RuntimeError("notice sink exploded")

    out = client_with_session_fallback(
        _client(_bedrock(), []), "t", notice=_boom_notice)
    assert out is None


def test_default_notice_goes_to_logger(no_socket, route_calls, monkeypatch,
                                       caplog):
    _no_claudecode(monkeypatch)
    with caplog.at_level("WARNING", logger=session_fallback.__name__):
        out = client_with_session_fallback(_client(_bedrock(), []), "seam-x")
    assert out is None
    hits = [r for r in caplog.records
            if NO_TRANSPORT_NOTICE in r.getMessage()]
    assert len(hits) == 1
    assert "seam-x" in hits[0].getMessage()
