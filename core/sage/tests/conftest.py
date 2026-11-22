"""Shared fixtures for the core/sage test package.

The server-identity gate (``core.sage.server_identity``) runs at
client acquisition and shells out to ``docker ps``; nearly every test
in this package fakes the SDK against the default localhost URL and
must stay hermetic — no docker, no subprocesses. The autouse fixture
below neutralises the gate at the ``core.sage.client`` binding, so
existing client/hook tests exercise their own behaviour unchanged.

Gate tests (``test_sage_server_identity.py``) are unaffected where
they target ``core.sage.server_identity`` directly, and override this
patch in-test (a later ``monkeypatch.setattr`` wins) where they pin
the client wiring itself.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _trusted_sage_server(monkeypatch):
    import core.sage.client as client_mod
    import core.sage.hooks as hooks_mod

    # hasattr-guarded so the fixture tolerates the binding's absence
    # (an implementation-reverted tree must fail only the gate's own
    # tests, not cascade an AttributeError through the whole package).
    # When the binding is absent, nothing in client.py calls it either.
    if hasattr(client_mod, "server_identity_ok"):
        monkeypatch.setattr(
            client_mod, "server_identity_ok", lambda url, service: True
        )
    # Same neutralisation at the hooks binding (the GPU probe gates
    # on server identity before touching the Ollama port).
    if hasattr(hooks_mod, "server_identity_ok"):
        monkeypatch.setattr(
            hooks_mod, "server_identity_ok", lambda url, service: True
        )
    # And keep the operator bypass out of test outcomes regardless of
    # the invoking shell's environment.
    monkeypatch.delenv("SAGE_SERVER_TRUSTED", raising=False)
