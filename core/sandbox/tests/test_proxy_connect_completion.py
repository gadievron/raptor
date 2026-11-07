"""Client and upstream completion failures produce truthful HTTP and event results."""

import asyncio
import json

import pytest

from core.sandbox import proxy as proxy_mod, egress_summary
from core.testing.module_bindings import mock_module_attribute
from core.sandbox.tests.test_proxy_connection_ownership import proxy as proxy, run, sockets


BAD_RESPONSES = [
    (b"HTTP/1.1 200 OK\r\n", "missing-terminator"),
    (b"HTTP/1.1 200 OK\r\nX: partial", "truncated-header"),
    (b"WRONG 200 OK\r\n\r\n", "wrong-protocol"),
    (b"HTTP/1.1 200 OK\r\nX: \x00\r\n\r\n", "header-control"),
    (b"HTTP/1.1 200 OK\r\nmissing-colon\r\n\r\n", "malformed-header"),
    (b"HTTP/1.1 200 " + b"x" * 5000 + b"\r\n\r\n", "status-line-cap"),
    (b"HTTP/1.1 200 OK\r\nX: " + b"x" * 5000 + b"\r\n\r\n", "header-line-cap"),
    (b"HTTP/1.1 200 OK\r\n" + b"X: a\r\n" * 101 + b"\r\n", "header-count-cap"),
    (b"HTTP/1.1 200 OK\r\n" + (b"X: " + b"x" * 1000 + b"\r\n") * 17 + b"\r\n", "header-byte-cap"),
    (b"HTTP/1.1 407 owned\r\n\r\n", "non-success-control"),
]


@pytest.mark.parametrize("response", [pytest.param(data, id=name) for data, name in BAD_RESPONSES])
def test_invalid_upstream_response_is_502_failed_and_closed(proxy, monkeypatch, tmp_path, response):
    async def scenario():
        async with sockets() as dial:
            backend = await dial()
            client = await dial()
            proxy._upstream = ("127.0.0.1", 1234)
            async def vetted(*args):
                return None
            monkeypatch.setattr(proxy, "_vet_upstream_target", vetted)
            reader = asyncio.StreamReader()
            reader.feed_data(b"CONNECT owned.invalid:443 HTTP/1.1\r\n\r\n")
            reader.feed_eof()
            backend[3].write(response)
            await backend[3].drain()
            backend[3].write_eof()
            async def connect(**kwargs):
                return backend[:2]
            token = proxy.register_sandbox()
            try:
                with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                    await asyncio.wait_for(proxy._serve_tunnel(reader, client[1]), 2)
                status = await asyncio.wait_for(client[2].readuntil(b"\r\n"), 2)
                assert status.startswith(b"HTTP/1.1 502 ")
                assert backend[1].is_closing()
            finally:
                events = proxy.unregister_sandbox(token)
            assert [event["result"] for event in events] == ["upstream_failed"]
            return events
    events = run(proxy, scenario())
    assert proxy.snapshot()["connections_failed"] == 1
    # Actual downstream reader: bookkeeping remains a failed connection,
    # never an allowed event after a truncated/malformed response head.
    (tmp_path / proxy_mod.PROXY_EVENTS_FILENAME).write_text(
        "".join(json.dumps(event) + "\n" for event in events))
    result = egress_summary.summarise_egress(tmp_path)
    assert result["failed"] == result["total_connections"] == 1
    assert result["allowed"] == result["denied"] == 0


@pytest.mark.parametrize("partial", [b"", b"X: unfinished", b"X: a\r\n", b"X: " + b"a" * 5000 + b"\r\n"],
                         ids=["eof", "partial-header", "missing-empty-line", "overlong"])
def test_incomplete_client_headers_never_reach_upstream_selection(proxy, monkeypatch, partial):
    async def scenario():
        async with sockets() as dial:
            client = await dial()
            proxy._upstream = ("127.0.0.1", 1234)
            selected = []
            async def forbidden(*args):
                selected.append(True)
                raise AssertionError("incomplete request reached target vetting")
            monkeypatch.setattr(proxy, "_vet_upstream_target", forbidden)
            reader = asyncio.StreamReader()
            reader.feed_data(b"CONNECT owned.invalid:443 HTTP/1.1\r\n" + partial)
            reader.feed_eof()
            token = proxy.register_sandbox()
            try:
                await proxy._serve_tunnel(reader, client[1])
                status = await asyncio.wait_for(client[2].readuntil(b"\r\n"), 2)
                assert status.startswith(b"HTTP/1.1 400 ") and not selected
            finally:
                events = proxy.unregister_sandbox(token)
            assert [event["result"] for event in events] == ["bad_request"]
    run(proxy, scenario())


def test_mid_header_client_deadline_is_408_before_vetting(proxy, monkeypatch):
    monkeypatch.setattr(proxy_mod, "_PROXY_HANDSHAKE_DEADLINE_S", 0.02)
    async def scenario():
        async with sockets() as dial:
            client = await dial()
            proxy._upstream = ("127.0.0.1", 1234)
            async def forbidden(*args):
                raise AssertionError("expired request reached target vetting")
            monkeypatch.setattr(proxy, "_vet_upstream_target", forbidden)
            reader = asyncio.StreamReader()
            reader.feed_data(b"CONNECT owned.invalid:443 HTTP/1.1\r\nX: unfinished")
            await asyncio.wait_for(proxy._serve_tunnel(reader, client[1]), 2)
            status = await asyncio.wait_for(client[2].readuntil(b"\r\n"), 2)
            assert status.startswith(b"HTTP/1.1 408 ")
    run(proxy, scenario())


def test_upstream_header_timeout_is_502_with_no_success_ack(proxy, monkeypatch):
    async def scenario():
        async with sockets() as dial:
            backend = await dial()
            client = await dial()
            proxy._upstream = ("127.0.0.1", 1234)
            proxy._upstream_handshake_timeout = 0.02
            async def vetted(*args):
                return None
            monkeypatch.setattr(proxy, "_vet_upstream_target", vetted)
            reader = asyncio.StreamReader()
            reader.feed_data(b"CONNECT owned.invalid:443 HTTP/1.1\r\n\r\n")
            backend[3].write(b"HTTP/1.1 200 OK\r\n")
            await backend[3].drain()
            async def connect(**kwargs):
                return backend[:2]
            with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                await asyncio.wait_for(proxy._serve_tunnel(reader, client[1]), 1)
            status = await asyncio.wait_for(client[2].readuntil(b"\r\n"), 2)
            assert status.startswith(b"HTTP/1.1 502 ") and backend[1].is_closing()
    run(proxy, scenario())


@pytest.mark.parametrize("bad", ["nan", "NaN", "inf", "+inf", "-inf", "1e999"])
def test_nonfinite_upstream_budget_falls_back(monkeypatch, bad):
    monkeypatch.setenv(proxy_mod._UPSTREAM_HANDSHAKE_TIMEOUT_ENV, bad)
    assert proxy_mod._upstream_handshake_timeout() == proxy_mod._PROXY_READ_TIMEOUT_S


def test_complete_upstream_head_relays_the_following_payload_unchanged(proxy, monkeypatch):
    async def scenario():
        async with sockets() as dial:
            backend = await dial()
            client = await dial()
            proxy._upstream = ("127.0.0.1", 1234)
            async def vetted(*args):
                return None
            monkeypatch.setattr(proxy, "_vet_upstream_target", vetted)
            reader = asyncio.StreamReader()
            reader.feed_data(b"CONNECT owned.invalid:443 HTTP/1.1\r\n\r\n")
            reader.feed_eof()
            payload = b"\x00\xffowned-payload\r\n"
            backend[3].write(b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n" + payload)
            await backend[3].drain()
            backend[3].write_eof()
            async def connect(**kwargs):
                return backend[:2]
            token = proxy.register_sandbox()
            try:
                with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                    await asyncio.wait_for(proxy._serve_tunnel(reader, client[1]), 2)
                reply = await asyncio.wait_for(client[2].read(), 2)
                assert reply == b"HTTP/1.1 200 Connection established\r\n\r\n" + payload
            finally:
                events = proxy.unregister_sandbox(token)
            assert [event["result"] for event in events] == ["allowed"]
            assert events[0]["bytes_u2c"] == len(payload)
    run(proxy, scenario())
