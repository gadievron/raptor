"""Gate 2 on multi-record DNS answers (direct CONNECT path).

A hostname whose resolver answer mixes a public and a private record
is a rebinding / split-horizon signal, and happy-eyeballs may dial ANY
of the records — so gate 2 vets EVERY record before the dial, matching
the upstream path's fail-closed doctrine. Pre-fix only addrinfo[0] was
vetted: a blocked non-first record surfaced from the per-attempt check
as a plain OSError → result ``upstream_failed`` (502) — the attack
signal was invisible to the banner, the audit record, and triage.

Both directions:

  * mixed public/private answer → 403 + ``denied_resolved_ip`` naming
    the blocked record, and NO dial is attempted;
  * all-public answer → gate 2 stays out of the way; a connect failure
    is still classified ``upstream_failed`` (502), never as a denial.

No real network egress: the resolver is faked and the dial either must
not happen (denied) or fails synchronously (refused stub).
"""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


def _send_connect(port: int, target: str, timeout: float = 5.0) -> tuple:
    """Send a CONNECT to a proxy on (127.0.0.1, port); return
    (status_code, raw_response)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        req = (f"CONNECT {target} HTTP/1.1\r\n"
               f"Host: {target}\r\n\r\n").encode("latin-1")
        s.sendall(req)
        buf = b""
        while b"\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        parts = line.split(None, 2)
        status = (int(parts[1])
                  if len(parts) >= 2 and parts[1].isdigit() else 0)
        return status, buf
    finally:
        s.close()


def _ai(ip: str, port: int = 443) -> tuple:
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))


class TestGate2MultiRecordAnswers:

    def test_blocked_non_first_record_denied_not_connect_failure(
            self, reset_proxy):
        dials: list = []

        async def fake_gai(self, host, port):
            # First record public (TEST-NET-1 is non-global and would
            # trip gate 2 itself, so use a documented global address
            # stand-in: 93.184.216.34), second record private.
            return [_ai("93.184.216.34"), _ai("10.0.0.5")]

        async def no_dial(*a, **k):
            dials.append(k.get("host"))
            msg = "refused (test stub)"
            raise OSError(msg)

        proxy = proxy_mod.EgressProxy(allowed_hosts={"mixed.example"})
        try:
            token = proxy.register_sandbox(caller_label="test")
            try:
                with patch.object(proxy_mod.EgressProxy,
                                  "_cached_getaddrinfo", fake_gai), \
                     patch.object(proxy_mod.asyncio, "open_connection",
                                  no_dial):
                    status, _ = _send_connect(proxy.port,
                                              "mixed.example:443")
            finally:
                events = proxy.unregister_sandbox(token)
        finally:
            proxy.stop()

        assert status == 403, (
            f"blocked non-first record must deny the CONNECT (403), "
            f"got {status}")
        assert dials == [], (
            "no dial may be attempted for a CONNECT gate 2 denies")
        denied = [e for e in events if e["result"] == "denied_resolved_ip"]
        assert len(denied) == 1, f"events: {events}"
        assert denied[0]["resolved_ip"] == "10.0.0.5"
        assert not [e for e in events if e["result"] == "upstream_failed"], (
            "the denial must not be misclassified as a connect failure")

    def test_all_public_answer_not_denied(self, reset_proxy):
        dials: list = []

        async def fake_gai(self, host, port):
            return [_ai("93.184.216.34"), _ai("93.184.216.35")]

        async def refuse(*a, **k):
            dials.append(k.get("host"))
            msg = "refused (test stub)"
            raise OSError(msg)

        proxy = proxy_mod.EgressProxy(allowed_hosts={"clean.example"})
        try:
            token = proxy.register_sandbox(caller_label="test")
            try:
                with patch.object(proxy_mod.EgressProxy,
                                  "_cached_getaddrinfo", fake_gai), \
                     patch.object(proxy_mod.asyncio, "open_connection",
                                  refuse):
                    status, _ = _send_connect(proxy.port,
                                              "clean.example:443")
            finally:
                events = proxy.unregister_sandbox(token)
        finally:
            proxy.stop()

        assert status == 502, (
            f"all-public answer with refused dial is a connect failure "
            f"(502), got {status}")
        assert dials, "the dial stage must be reached for a clean answer"
        assert not [e for e in events
                    if e["result"] == "denied_resolved_ip"], (
            "a plain connect failure must never be classified as a "
            "gate-2 denial")
        assert [e for e in events if e["result"] == "upstream_failed"]


class TestWalkSerialGate2Preference:
    """_walk_serial must surface a gate-2 hit over a later ordinary
    connect error — the policy denial outranks noise — and must keep
    raising the ordinary error when no record was blocked."""

    def _run(self, coro):
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_gate2_outranks_later_connect_error(self, reset_proxy):
        async def refuse(*a, **k):
            msg = "refused (test stub)"
            raise OSError(msg)

        proxy = proxy_mod.EgressProxy(allowed_hosts={"x.example"})
        try:
            with patch.object(proxy_mod.asyncio, "open_connection",
                              refuse), \
                 pytest.raises(proxy_mod._Gate2BlockedError) as ei:
                self._run(proxy._happy_eyeballs_connect(
                    [_ai("10.0.0.5"), _ai("93.184.216.34")], 443))
            assert ei.value.blocked_ip == "10.0.0.5"
        finally:
            proxy.stop()

    def test_plain_failure_stays_plain(self, reset_proxy):
        async def refuse(*a, **k):
            msg = "refused (test stub)"
            raise OSError(msg)

        proxy = proxy_mod.EgressProxy(allowed_hosts={"x.example"})
        try:
            with patch.object(proxy_mod.asyncio, "open_connection",
                              refuse), \
                 pytest.raises(OSError) as ei:
                self._run(proxy._happy_eyeballs_connect(
                    [_ai("93.184.216.34")], 443))
            assert not isinstance(ei.value, proxy_mod._Gate2BlockedError)
        finally:
            proxy.stop()
