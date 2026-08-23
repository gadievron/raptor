"""Shared fixtures for ``core.oci`` tests.

The registry client validates the addresses a registry host actually
resolves to (``validate_resolved_registry_addresses``, DNS-rebinding
defence) before issuing any request. Tests are hermetic — no real
DNS — so resolution is stubbed to a fixed globally-routable address
by default. Tests that exercise the resolution gate itself
monkeypatch ``socket.getaddrinfo`` with their own answers (a
test-local ``monkeypatch.setattr`` runs after this autouse fixture
and wins).
"""

from __future__ import annotations

import socket

import pytest


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

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
