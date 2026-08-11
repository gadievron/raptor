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
so we pop them explicitly here.
"""

from __future__ import annotations

import os

import pytest


_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy")

# Pin OLLAMA_HOST to the documented default so these tests are hermetic
# against a developer's ambient env. A dev running Ollama exports the
# canonical schemeless ``OLLAMA_HOST=127.0.0.1:11434`` (or a remote
# host), which otherwise leaks into LLMClient/detection and makes the
# suite's outcome host-dependent. A test that genuinely exercises a
# specific host overrides this with its own ``monkeypatch.setenv``,
# which runs after this autouse setup and wins.
_DEFAULT_OLLAMA_HOST = "http://localhost:11434"


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
        LLMClient, "flush_usage_to_scorecard", lambda self: None,
    )


@pytest.fixture(autouse=True)
def _reset_llm_egress_state():
    """Reset egress module flag, clear proxy env vars, and pin
    OLLAMA_HOST before AND after every test in this directory."""
    from core.llm import egress
    _saved_ollama = os.environ.get("OLLAMA_HOST")
    egress._reset_for_tests()
    for var in _PROXY_VARS:
        os.environ.pop(var, None)
    os.environ["OLLAMA_HOST"] = _DEFAULT_OLLAMA_HOST
    yield
    egress._reset_for_tests()
    for var in _PROXY_VARS:
        os.environ.pop(var, None)
    if _saved_ollama is None:
        os.environ.pop("OLLAMA_HOST", None)
    else:
        os.environ["OLLAMA_HOST"] = _saved_ollama


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
