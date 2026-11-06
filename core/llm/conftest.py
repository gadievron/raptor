"""Package-level test infra for everything under ``core/llm``.

The egress-reset fixture lived only in ``core/llm/tests/conftest.py``,
which does NOT cover the sibling test trees
(``dispatcher/tests``, ``scorecard/tests``, ``tool_use/tests``) — a
real-LLMClient constructor added to any of them would re-open the
proxy-env leak the audit conftest closed elsewhere. Hoisting the
wrapper to the package root covers every subtree.
"""

from __future__ import annotations

import pytest

from core.testing import reset_llm_egress_state


@pytest.fixture(autouse=True)
def _reset_llm_egress_state_pkg():
    with pytest.MonkeyPatch.context() as patch:
        yield from reset_llm_egress_state(patch)


@pytest.fixture
def monkeypatch(_reset_llm_egress_state_pkg, monkeypatch):
    """Keep inherited process guards inside the egress owner's lifetime."""
    yield monkeypatch
