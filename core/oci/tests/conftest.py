"""Shared fixtures for ``core.oci`` tests.

The registry client validates the addresses a registry host actually
resolves to (``validate_resolved_registry_addresses``, DNS-rebinding
defence) before issuing any request. Tests are hermetic — no real
DNS — so resolution is stubbed to a fixed globally-routable address
by default. Tests that exercise the resolution gate itself
install their own consumer-local socket lookup after this
autouse fixture, preserving the shared socket module.
"""

from __future__ import annotations

import socket

import pytest

from core.oci import registry_hosts
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(autouse=True)
def _stub_getaddrinfo(monkeypatch):
    """Resolve every hostname to a globally-routable address.

    Documentation ranges (TEST-NET, 2001:db8::/32) are deliberately
    NOT used — they are non-global by definition and would trip the
    very gate this fixture exists to keep hermetic.
    """

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
            "", ("8.8.8.8", port or 443),
        )]

    patch_module_attribute(monkeypatch, registry_hosts, "socket", "getaddrinfo", fake_getaddrinfo)


@pytest.fixture(autouse=True)
def _owned_oci_scratch():
    from core.run import tmp_reaper
    from core.testing.module_state import isolated_module_state
    from core.testing.scratch_state import isolated_scratch_keepalive

    with isolated_module_state(tmp_reaper, {
        "_RUNTIME_DIR_PREFIXES": set(tmp_reaper._RUNTIME_DIR_PREFIXES),
    }), isolated_scratch_keepalive():
        yield
