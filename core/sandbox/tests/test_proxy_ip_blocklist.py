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


class TestNat64NetworkSpecificPrefixes:
    """RFC 6052 network-specific prefixes: only the
    well-known prefix was decoded, so an NSP deployment's
    `<NSP>::169.254.169.254` classified is_global and smuggled the
    embedded metadata/RFC1918 target past gate 2. Operators declare
    their NSP via RAPTOR_NAT64_PREFIXES."""

    def test_wkp_still_decoded_without_knob(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_NAT64_PREFIXES", raising=False)
        assert _ip_is_blocked("64:ff9b::169.254.169.254") is True

    def test_nsp_embedded_metadata_blocked_when_declared(
            self, monkeypatch):
        monkeypatch.setenv(
            "RAPTOR_NAT64_PREFIXES", "2001:4860:64::/96",
        )
        assert _ip_is_blocked("2001:4860:64::169.254.169.254") is True
        assert _ip_is_blocked("2001:4860:64::10.0.0.1") is True
        # Public embedded v4 through the declared NSP stays allowed.
        assert _ip_is_blocked("2001:4860:64::8.8.8.8") is False

    def test_undeclared_nsp_documents_the_gap(self, monkeypatch):
        # Deployment-conditional by design: without the declaration
        # the NSP is indistinguishable from ordinary global IPv6.
        monkeypatch.delenv("RAPTOR_NAT64_PREFIXES", raising=False)
        assert _ip_is_blocked("2001:4860:64::169.254.169.254") is False

    def test_malformed_and_non_96_entries_ignored(self, monkeypatch):
        monkeypatch.setenv(
            "RAPTOR_NAT64_PREFIXES",
            "not-a-prefix, 10.0.0.0/8, 2001:4860::/128, 2001:4860:64::/96",
        )
        # The one valid entry still engages; the rest are dropped.
        assert _ip_is_blocked("2001:4860:64::192.168.1.1") is True
        assert _ip_is_blocked("8.8.8.8") is False

    def test_wider_than_96_rejected_not_misdecoded(self, monkeypatch):
        # RFC 6052 wider prefixes (/32-/64) embed the IPv4 at a
        # prefix-length-dependent position, NOT the low 32 bits — a
        # low-32 decode of a /64 declaration would re-check the wrong
        # address. The knob accepts exactly /96; anything else is
        # dropped loudly and provides no (false) coverage.
        monkeypatch.setenv("RAPTOR_NAT64_PREFIXES", "2001:4860:a::/64")
        # Low-32 spelling under the rejected /64 keeps its ordinary
        # global classification (no decode happens).
        assert _ip_is_blocked("2001:4860:a::7f00:1") is False

    def test_multiple_96_prefixes(self, monkeypatch):
        monkeypatch.setenv(
            "RAPTOR_NAT64_PREFIXES",
            "2001:4860:64::/96,2001:4860:a:b::/96",
        )
        assert _ip_is_blocked("2001:4860:a:b::7f00:1") is True
        assert _ip_is_blocked("2001:4860:64::10.1.2.3") is True
