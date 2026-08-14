"""Per-directory test infra for ``core.dataflow`` tests.

Egress-state hygiene: several tests here construct a real
``LLMClient`` (e.g. test_barrier_synth's model_completer tests),
whose ``__init__`` side-effect ``enable_llm_egress`` swaps
``HTTPS_PROXY`` in ``os.environ`` to the in-process loopback proxy
pointer. Without cleanup that dead pointer leaks into every later
suite in the same pytest session — on mandatory-egress-proxy hosts
the semgrep registry reachability probe in packages/static-analysis
then probes a dead port, drops all registry packs, and 11 unrelated
tests fail. Same guard as core/llm/tests/conftest.py, including the
setenv-then-delenv two-step that records an undo entry even for vars
absent from the real env (delenv(raising=False) alone records
nothing, so the egress module's direct writes would survive undo).
"""

import pytest

_PROXY_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy",
)


@pytest.fixture(autouse=True)
def _reset_llm_egress_state(monkeypatch):
    from core.llm import egress
    egress._reset_for_tests()
    for var in _PROXY_VARS:
        monkeypatch.setenv(var, "")
        monkeypatch.delenv(var)
    yield
    egress._reset_for_tests()
