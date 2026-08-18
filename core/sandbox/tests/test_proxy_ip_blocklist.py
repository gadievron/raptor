"""Gate-2 IP blocklist tests for the egress proxy's _ip_is_blocked.

IPv6 encodings that embed an IPv4 address (NAT64 64:ff9b::/96,
deprecated IPv4-compatible ::a.b.c.d, IPv4-mapped ::ffff:a.b.c.d)
must be judged by the embedded IPv4, not the enclosing IPv6's
is_global — otherwise a NAT64 spelling of the metadata service or an
RFC 1918 address slips past the block. Unparseable input fails
closed.
"""

from __future__ import annotations

import pytest

from core.sandbox.proxy import _ip_is_blocked


class TestGate2EmbeddedIPv4:

    @pytest.mark.parametrize("ip", [
        "64:ff9b::169.254.169.254",   # NAT64 → metadata
        "64:ff9b::a9fe:a9fe",         # same, hex spelling
        "64:ff9b::10.0.0.1",          # NAT64 → RFC 1918
        "::169.254.169.254",          # IPv4-compatible → metadata
        "::ffff:169.254.169.254",     # IPv4-mapped → metadata
        "10.0.0.1", "169.254.169.254", "127.0.0.1", "::1",
    ])
    def test_blocked(self, ip):
        assert _ip_is_blocked(ip) is True

    @pytest.mark.parametrize("ip", [
        "64:ff9b::8.8.8.8",   # NAT64 → public: legitimate NAT64 use
        "8.8.8.8",
        "2600::1",
    ])
    def test_allowed(self, ip):
        assert _ip_is_blocked(ip) is False

    def test_unparseable_fails_closed(self):
        assert _ip_is_blocked("not-an-ip") is True
