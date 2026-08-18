"""LLM env hermeticity — the egress-reset fixture body.

``core.llm.egress.enable_llm_egress`` (an ``LLMClient.__init__`` side
effect) swaps ``HTTPS_PROXY``-family vars in ``os.environ`` to point
at the in-process loopback proxy. Without cleanup that dead pointer
leaks into every later suite in the same pytest session (observed:
sandbox curl tests and the semgrep registry probe failing only in
combined runs on proxied hosts). Two per-directory conftests carried
copies of the reset fixture and had already drifted — one scrubbed
only 4 of the 8 conventional proxy vars, the other lost the
``OLLAMA_HOST`` pin. This module is the single body both wrap.

Usage (per-directory conftest)::

    @pytest.fixture(autouse=True)
    def _reset_llm_egress_state(monkeypatch):
        yield from reset_llm_egress_state(monkeypatch)

Mechanics that are load-bearing (learned the hard way, see the
core/llm/tests conftest history):

* env mutations go through the SAME function-scoped ``monkeypatch``
  the tests themselves use, so setup deletions, per-test setenv
  calls, and the egress module's direct ``os.environ`` writes unwind
  on one undo stack;
* the ``setenv("")`` → ``delenv`` two-step records an undo entry even
  for vars ABSENT from the real env — ``delenv(raising=False)`` on a
  missing var records nothing, and the egress module's direct writes
  during a test would then survive undo and leak process-wide.
"""

from __future__ import annotations

from collections.abc import Iterator

# The full conventional proxy family. One drifted copy scrubbed only
# the HTTPS/NO subset, leaving HTTP_PROXY/ALL_PROXY leaks possible.
PROXY_ENV_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy",
)

# Pin OLLAMA_HOST to the documented default so suites are hermetic
# against a developer's ambient env. A dev running Ollama exports the
# canonical schemeless ``OLLAMA_HOST=127.0.0.1:11434`` (or a remote
# host), which otherwise leaks into LLMClient/detection and makes
# suite outcomes host-dependent. A test that genuinely exercises a
# specific host overrides with its own ``monkeypatch.setenv``, which
# runs after the autouse setup and wins.
DEFAULT_OLLAMA_HOST = "http://localhost:11434"


def reset_llm_egress_state(
    monkeypatch,
    *,
    pin_ollama_host: bool = True,
) -> Iterator[None]:
    """Fixture body: reset the egress module flag, scrub the proxy-env
    family, pin ``OLLAMA_HOST``, and reset again on teardown.

    Generator by design — conftests wrap it with ``yield from`` inside
    an autouse fixture so the teardown half runs at the right time.
    """
    from core.llm import egress
    egress._reset_for_tests()
    for var in PROXY_ENV_VARS:
        monkeypatch.setenv(var, "")
        monkeypatch.delenv(var)
    if pin_ollama_host:
        monkeypatch.setenv("OLLAMA_HOST", DEFAULT_OLLAMA_HOST)
    yield
    egress._reset_for_tests()


__all__ = [
    "DEFAULT_OLLAMA_HOST",
    "PROXY_ENV_VARS",
    "reset_llm_egress_state",
]
