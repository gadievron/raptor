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
