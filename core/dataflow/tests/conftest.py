"""Per-directory test infra for ``core.dataflow`` tests.

Egress-state hygiene: several tests here construct a real
``LLMClient`` (e.g. test_barrier_synth's model_completer tests),
whose ``__init__`` side-effect ``enable_llm_egress`` swaps
``HTTPS_PROXY`` in ``os.environ`` to the in-process loopback proxy
pointer. Without cleanup that dead pointer leaks into every later
suite in the same pytest session — on mandatory-egress-proxy hosts
the semgrep registry reachability probe in packages/static-analysis
then probes a dead port, drops all registry packs, and 11 unrelated
tests fail.

Shared body: :func:`core.testing.reset_llm_egress_state` (this file
used to carry a copy of core/llm/tests' fixture, already drifted —
that copy lacked this one's full proxy-var family, this one lacked
its ``OLLAMA_HOST`` pin; the shared body has both).
"""

import pytest

from core.testing import reset_llm_egress_state


@pytest.fixture(autouse=True)
def _reset_llm_egress_state(monkeypatch):
    yield from reset_llm_egress_state(monkeypatch)
