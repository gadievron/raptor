"""Policies for tests that compile only repository-owned PoC fixtures."""
import sys

import pytest


@pytest.fixture
def owned_poc_compile_policy(monkeypatch):
    """Opt into reduced containment only for explicitly named fixture tests.

    Compiler/source-scanner tests use fixed test sources and need to run on
    CI hosts that block namespaces. Floor tests do not request this fixture.
    """
    from core.sandbox import context
    if ((sys.platform == 'linux' and not context.check_net_available())
            or (sys.platform == 'darwin' and not context.check_seatbelt_available())):
        monkeypatch.setenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', '1')
