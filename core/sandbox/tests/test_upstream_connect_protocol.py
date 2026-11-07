"""Bounded upstream response framing, deadline coverage and byte preservation."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from core.sandbox import _upstream_connect as protocol
from core.testing.module_bindings import mock_module_attribute


def _run(coroutine):
    # A private loop avoids replacing any borrowed current-loop binding.
    loop = asyncio.SelectorEventLoop()
    try:
        return loop.run_until_complete(coroutine)
    finally:
        async def retire():
            tasks = asyncio.all_tasks() - {asyncio.current_task()}
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        try:
            loop.run_until_complete(retire())
        finally:
            loop.close()


def exchange(response, *, host="owned.invalid", port=443):
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(response)
        reader.feed_eof()
        writer = Mock(spec=asyncio.StreamWriter, drain=AsyncMock())
        connect = AsyncMock(return_value=(reader, writer))
        result = await protocol.negotiate_connect(connect, host, port, 5)
        return result, writer
    return _run(scenario())


@pytest.mark.parametrize("response", [
    b"HTTP/1.1 200 OK\r\n\r\n", b"HTTP/1.0 200\r\n\r\n",
    b"HTTP/1.1 200 Connection established\r\nProxy-Agent: owned\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nX-Value:\t\xff\r\n\r\n",
], ids=["http11", "http10-no-reason", "header", "obs-text-value"])
def test_complete_success_is_accepted(response):
    (_, writer), captured = exchange(response)
    assert writer is captured
    captured.write.assert_called_once_with(
        b"CONNECT owned.invalid:443 HTTP/1.1\r\nHost: owned.invalid:443\r\n\r\n")


BAD = [
    (b"", "eof"), (b"HTTP/1.1 200", "truncated-status"),
    (b"HTTP/1.1 200 OK\r\n", "missing-terminator"),
    (b"HTTP/1.1 200 OK\r\nX: partial", "truncated-header"),
    (b"GARBAGE 200 OK\r\n\r\n", "wrong-protocol"),
    (b"HTTP/2 200 OK\r\n\r\n", "wrong-version"),
    (b"HTTP/1.1\t200 OK\r\n\r\n", "tab-separator"),
    (b" HTTP/1.1 200 OK\r\n\r\n", "leading-space"),
    (b"HTTP/1.1 2000 OK\r\n\r\n", "long-code"),
    (b"HTTP/1.1 +200 OK\r\n\r\n", "signed-code"),
    (b"HTTP/1.1 200 O\x00K\r\n\r\n", "status-nul"),
    (b"HTTP/1.1 200 O\nK\r\n\r\n", "status-bare-lf"),
    (b"HTTP/1.1 200 OK\r\nmissing-colon\r\n\r\n", "header-no-colon"),
    (b"HTTP/1.1 200 OK\r\n: empty-name\r\n\r\n", "empty-name"),
    (b"HTTP/1.1 200 OK\r\nX Name: a\r\n\r\n", "space-in-name"),
    (b"HTTP/1.1 200 OK\r\n X: a\r\n\r\n", "folded-header"),
    (b"HTTP/1.1 200 OK\r\nX: \x00\r\n\r\n", "header-nul"),
    (b"HTTP/1.1 200 OK\r\nX: \x7f\r\n\r\n", "header-del"),
    (b"HTTP/1.1 407 auth\r\n\r\n", "auth-rejection"),
    (b"HTTP/1.1 503 unavailable\r\n\r\n", "upstream-unavailable"),
]


@pytest.mark.parametrize("response", [pytest.param(data, id=name) for data, name in BAD])
def test_incomplete_malformed_and_rejected_heads_fail(response):
    with pytest.raises(protocol.UpstreamConnectError):
        exchange(response)


@pytest.mark.parametrize("kind", ["status-line", "header-line", "header-count", "header-bytes"])
def test_response_size_and_count_caps(kind):
    responses = {
        "status-line": b"HTTP/1.1 200 " + b"x" * protocol.MAX_STATUS_BYTES + b"\r\n\r\n",
        "header-line": b"HTTP/1.1 200 OK\r\nX: " + b"x" * protocol.MAX_HEADER_LINE_BYTES + b"\r\n\r\n",
        "header-count": b"HTTP/1.1 200 OK\r\n" + b"X: a\r\n" * (protocol.MAX_HEADERS + 1) + b"\r\n",
        "header-bytes": b"HTTP/1.1 200 OK\r\n" + (b"X: " + b"x" * 1000 + b"\r\n") * 17 + b"\r\n",
    }
    with pytest.raises(protocol.UpstreamConnectError):
        exchange(responses[kind])


@pytest.mark.parametrize("header", [b"Content-Length: 1000000", b"Transfer-Encoding: chunked", b"X: retained"])
def test_bytes_after_head_belong_to_the_tunnel(header):
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 200 OK\r\n" + header + b"\r\n\r\n\x00\xffpayload\r\n")
        writer = Mock(spec=asyncio.StreamWriter, drain=AsyncMock())
        result, _ = await protocol.negotiate_connect(AsyncMock(return_value=(reader, writer)), "x", 443, 5)
        assert await result.readexactly(11) == b"\x00\xffpayload\r\n"
    _run(scenario())


@pytest.mark.parametrize("host,authority", [("owned.invalid", "owned.invalid:443"),
                                           ("2606:2800:220:1::", "[2606:2800:220:1::]:443")],
                         ids=["dns", "ipv6"])
def test_connect_authority_has_correct_ipv6_bracketing(host, authority):
    (_, _), writer = exchange(b"HTTP/1.1 200 OK\r\n\r\n", host=host)
    assert writer.write.call_args.args[0] == (
        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").encode("ascii")


def test_one_deadline_encloses_connect_write_status_and_all_headers():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 200 OK\r\nX: a\r\nY: b\r\n\r\n")
        active, budgets, phases = [], [], []
        real_timeout = asyncio.timeout
        class Deadline:
            def __init__(self, seconds):
                budgets.append(seconds)
                self.scope = real_timeout(seconds)
            async def __aenter__(self):
                await self.scope.__aenter__()
                active.append(True)
            async def __aexit__(self, *args):
                active.pop()
                return await self.scope.__aexit__(*args)
        def phase(name):
            assert active == [True]
            phases.append(name)
        async def connect():
            phase("connect")
            return reader, writer
        async def drain():
            phase("drain")
        real_read = reader.readuntil
        async def read(*args):
            phase("read")
            return await real_read(*args)
        reader.readuntil = read
        writer = Mock(spec=asyncio.StreamWriter, drain=drain)
        writer.write.side_effect = lambda data: phase("write")
        with mock_module_attribute(protocol, "asyncio", "timeout", Deadline):
            await protocol.negotiate_connect(connect, "owned.invalid", 443, 5)
        assert budgets == [5]
        assert phases == ["connect", "write", "drain", "read", "read", "read", "read"]
    _run(scenario())


@pytest.mark.parametrize("phase", ["connect", "drain", "status", "headers"])
def test_the_shared_deadline_cancels_every_stalled_phase(phase):
    async def scenario():
        reader = asyncio.StreamReader()
        if phase == "headers":
            reader.feed_data(b"HTTP/1.1 200 OK\r\n")
        writer = Mock(spec=asyncio.StreamWriter, drain=AsyncMock())
        async def stall():
            await asyncio.Event().wait()
        if phase == "drain":
            writer.drain.side_effect = stall
        async def connect():
            if phase == "connect":
                await stall()
            return reader, writer
        with pytest.raises(protocol.UpstreamConnectError, match="TimeoutError"):
            await asyncio.wait_for(protocol.negotiate_connect(connect, "x", 443, 0.01), 2)
    _run(scenario())


@pytest.mark.parametrize("boundary", ["status", "header", "count"])
def test_exact_line_and_count_limits_remain_accepted(boundary):
    if boundary == "status":
        prefix = b"HTTP/1.1 200 "
        response = prefix + b"x" * (protocol.MAX_STATUS_BYTES - len(prefix) - 2) + b"\r\n\r\n"
    elif boundary == "header":
        response = b"HTTP/1.1 200 OK\r\nX:" + b"x" * (protocol.MAX_HEADER_LINE_BYTES - 4) + b"\r\n\r\n"
    else:
        response = b"HTTP/1.1 200 OK\r\n" + b"X: a\r\n" * protocol.MAX_HEADERS + b"\r\n"
    exchange(response)


@pytest.mark.parametrize("reason", [b"private-response-detail", b"\x1b[31mprivate-response-detail"])
def test_failure_diagnostics_do_not_echo_upstream_reason_text(reason):
    with pytest.raises(protocol.UpstreamConnectError) as failure:
        exchange(b"HTTP/1.1 407 " + reason + b"\r\n\r\n")
    assert "private-response-detail" not in str(failure.value)
    assert "\x1b" not in str(failure.value)
