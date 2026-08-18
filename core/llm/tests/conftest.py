"""Per-directory test infra for ``core.llm`` tests.

Reset env vars + module state that ``core.llm.egress.enable_llm_egress``
mutates as a side effect of ``LLMClient.__init__``. Without this, any
test in this directory that constructs a real ``LLMClient`` (e.g.
``test_exclude_fallback``, ``test_ollama_warning``) leaks
``HTTPS_PROXY=127.0.0.1:<port>`` into ``os.environ``, which subsequent
tests in the pytest session pick up — notably
``core/sandbox/tests/test_e2e_sandbox::test_allowed_host_succeeds``,
where the in-process proxy reads it as a (now-dead) upstream chain
target and the test's curl call fails with exit 56.

Direct ``os.environ`` mutations bypass ``monkeypatch``'s auto-cleanup,
so the fixture below records explicit undo entries for them on the
shared per-test ``monkeypatch`` instance.
"""

from __future__ import annotations

import pytest

from core.testing import reset_llm_egress_state


@pytest.fixture(autouse=True)
def _isolate_scorecard(monkeypatch):
    """Prevent tests from writing to the production scorecard.

    Tests that construct LLMClient with bare model names (``"pro"``,
    ``"haiku"``) register an atexit flush that writes mock data into
    ``out/llm_scorecard.json``. Disabling here keeps the scorecard
    clean without touching every test's LLMConfig constructor.
    """
    from core.llm.client import LLMClient
    monkeypatch.setattr(
        LLMClient, "flush_usage_to_scorecard",
        lambda self, **kwargs: None,
    )


@pytest.fixture(autouse=True)
def _reset_llm_egress_state(monkeypatch):
    """Reset egress module flag, clear proxy env vars, and pin
    OLLAMA_HOST for every test in this directory.

    Shared body: :func:`core.testing.reset_llm_egress_state` — its
    docstring carries the hard-won mechanics (single monkeypatch undo
    stack; the setenv→delenv two-step for vars absent from the real
    env). This directory's history is why those mechanics exist: the
    manual pop-before-and-after version erased the operator's real
    proxy env for the remainder of the pytest process on
    mandatory-egress-proxy hosts, and a save/restore could not fix it
    because ``_isolate_scorecard``'s monkeypatch instantiates first
    and undoes after ours. The shared body also scrubs the FULL
    8-var proxy family (this copy had drifted to 4, leaving
    HTTP_PROXY/ALL_PROXY leaks possible)."""
    yield from reset_llm_egress_state(monkeypatch)


@pytest.fixture(autouse=True)
def _reset_operator_primary_override():
    """Snapshot + reset ``_operator_primary_override`` around every
    test in this directory.

    Defense-in-depth against tests elsewhere in the pytest session
    that invoke an operator-facing CLI in-process. Concretely,
    ``packages/code_understanding/tests/test_libexec_trajectory_e2e``
    imports ``libexec/raptor-understand`` and runs ``main()`` with
    ``--model fake-haiku-x``; that CLI pins the override to a fake
    anthropic ModelConfig. Without this reset the pinned model
    persists in module state and every subsequent core/llm test
    that expects the default resolution chain sees the leaked
    override instead — CI failed with three provider-preference
    tests returning ``fake-haiku-x`` when they expected other
    providers.
    """
    import core.llm.config as cfg
    saved = getattr(cfg, "_operator_primary_override", None)
    cfg._operator_primary_override = None
    try:
        yield
    finally:
        cfg._operator_primary_override = saved


@pytest.fixture(autouse=True)
def _scrub_dispatcher_route(monkeypatch):
    """Strip an ambient ``RAPTOR_LLM_SOCKET`` for every test in this
    directory.

    The credential-isolation dispatcher route wins over direct SDK
    construction inside ``create_provider`` and the provider
    constructors, so a socket path leaked into the environment (e.g.
    pytest run from a shell inside a RAPTOR-launched session) flips
    every direct-provider assertion (anthropic/openai routes in
    test_llm_callbacks_providers, test_turn_track_usage_and_factory)
    to the dispatcher path. Tests that exercise the dispatcher route
    on purpose set the var with ``monkeypatch.setenv`` inside the test
    body, which runs after this autouse scrub and wins."""
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
