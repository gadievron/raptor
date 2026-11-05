"""Per-directory test infra for ``core.llm`` tests.

The egress-reset fixture (proxy-env/OLLAMA_HOST hermeticity for tests
that construct real LLMClients) moved to the package-level conftest —
``core/llm/conftest.py`` — so the sibling test trees
(``dispatcher/tests``, ``scorecard/tests``, ``tool_use/tests``) are
covered too. Its history and load-bearing mechanics live on
``core.testing.reset_llm_egress_state``'s docstring.
"""

from __future__ import annotations

import os

import pytest

from core.testing.tempdirs import isolated_test_dir


@pytest.fixture(autouse=True)
def _private_fixture_files():
    """Create fixture files private (umask 0o077) for every test in
    this directory.

    Many tests here write keyed ``models.json`` fixtures with plain
    ``write_text``, whose mode otherwise inherits the RUNNER's umask
    (frequently 0644/0664) — and the models-config permission gate
    (``core.llm.models_config_perm``) fail-closes on a
    group/other-readable file that carries inline API keys. Pinning
    the umask keeps those fixtures hermetic against the runner's
    environment; tests exercising the gate itself set an explicit
    loose mode with ``chmod`` after creation, which wins over umask.
    """
    old = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(old)



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
def _isolated_cache_mac_key(tmp_path_factory, monkeypatch):
    """Point XDG_DATA_HOME at a per-test tmp dir.

    Every ``LLMClient`` cache write now mints an HMAC key under
    ``$XDG_DATA_HOME/raptor/llm-cache-mac.key``
    (``core.llm.cache_integrity``); without this isolation, any test
    that constructs a client would lazily create — or depend on — the
    developer's real key file. Same pattern as
    ``core/llm/scorecard/tests/conftest.py``.
    """
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(isolated_test_dir(tmp_path_factory, "xdg-data")),
    )




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


@pytest.fixture
def sysprompt_cache(tmp_path, monkeypatch):
    """Own prompt-cache state and disk paths without a process-wide ticker."""
    import threading
    from core.atomic_fs import rmtree_hardened
    from core.llm import cc_adapter
    from core.run import scratch, tmp_reaper

    parent = tmp_path / "prompt-cache"
    parent.mkdir()
    original_scratch = scratch.scratch_dir
    monkeypatch.setattr(cc_adapter, "_sysprompt_cache", {})
    monkeypatch.setattr(cc_adapter, "_sysprompt_dir", None)
    monkeypatch.setattr(cc_adapter, "_sysprompt_owner_pid", None)
    monkeypatch.setattr(cc_adapter, "_sysprompt_lock", threading.Lock())
    monkeypatch.setattr(tmp_reaper, "_RUNTIME_DIR_PREFIXES", set())
    monkeypatch.setattr(scratch, "_keepalive_paths", set())
    monkeypatch.setattr(scratch, "keepalive_register", lambda p: scratch._keepalive_paths.add(str(p)))
    monkeypatch.setattr(scratch, "keepalive_unregister", lambda p: scratch._keepalive_paths.discard(str(p)))
    monkeypatch.setattr(scratch, "scratch_dir", lambda prefix, **kw: original_scratch(prefix, dir=parent, **kw))
    try:
        yield cc_adapter
    finally:
        try:
            cc_adapter._cleanup_sysprompt_cache()
            assert not scratch._keepalive_paths, "prompt-cache keepalive was not released"
        finally:
            rmtree_hardened(parent)
