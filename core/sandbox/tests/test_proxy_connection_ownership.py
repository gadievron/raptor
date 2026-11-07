"""Outbound proxy streams survive racing and cancellation without losing owners."""

import asyncio
from contextlib import asynccontextmanager, suppress
import socket
from unittest.mock import Mock

import pytest

from core.sandbox import proxy as proxy_mod
from core.sandbox._request_head import ParsedRequestLine
from core.testing.module_bindings import patch_module_attribute, mock_module_attribute


@pytest.fixture
def proxy(monkeypatch):
    parser = Mock(landlocked=True)
    parser.parse.return_value = ParsedRequestLine("owned.invalid", 443)
    patch_module_attribute(monkeypatch, proxy_mod, "parser_jail", "get_parser_jail", lambda: parser)
    instance = proxy_mod.EgressProxy(["owned.invalid"])
    # Give original consumers the same empty registry during baseline
    # reproduction, so failures establish lost ownership, not missing fields.
    if not hasattr(instance, "_upstream_writers"):
        instance._upstream_writers = set()
    monkeypatch.setattr(proxy_mod, "_HAPPY_EYEBALLS_DELAY", 0)
    try:
        yield instance
    finally:
        instance.stop(drain_timeout=0)
        assert not instance.is_alive()


def run(proxy, coroutine):
    return asyncio.run_coroutine_threadsafe(coroutine, proxy._loop).result(8)


@asynccontextmanager
async def sockets():
    accepted = asyncio.Queue()
    writers = []
    real_open = asyncio.open_connection
    def accept(reader, writer):
        writers.append(writer)
        accepted.put_nowait((reader, writer))
    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async def dial():
        reader, writer = await real_open("127.0.0.1", port)
        writers.append(writer)
        peer_reader, peer_writer = await accepted.get()
        return reader, writer, peer_reader, peer_writer
    try:
        yield dial
    finally:
        server.close()
        for writer in writers:
            writer.close()
            writer.transport.abort()
        for writer in writers:
            with suppress(OSError, RuntimeError):
                await writer.wait_closed()
        await server.wait_closed()


def addresses(families=(socket.AF_INET6, socket.AF_INET)):
    return [(family, socket.SOCK_STREAM, 0, "", (ip, 443))
            for family, ip in zip(families, ("2606:2800:220:1::", "93.184.216.34"))]


@pytest.mark.parametrize("winner_family", [socket.AF_INET6, socket.AF_INET], ids=["v6", "v4"])
@pytest.mark.parametrize("late_success", [False, True], ids=["cancelled-loser", "late-success-loser"])
def test_race_retires_loser_before_returning_one_live_winner(proxy, winner_family, late_success):
    async def scenario():
        async with sockets() as dial:
            pairs = {family: await dial() for family in (socket.AF_INET6, socket.AF_INET)}
            entered = set()
            both = asyncio.Event()
            finished = []
            async def connect(*, family, **kwargs):
                entered.add(family)
                if len(entered) == 2:
                    both.set()
                await both.wait()
                if family != winner_family:
                    try:
                        await asyncio.Event().wait()
                    except asyncio.CancelledError:
                        for _ in range(5):
                            await asyncio.sleep(0)
                        finished.append(family)
                        if not late_success:
                            pairs[family][1].close()  # connector owns until return
                            raise
                return pairs[family][:2]
            with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                result = await proxy._happy_eyeballs_connect(addresses(), 443)
            winner = pairs[winner_family][1]
            loser = pairs[socket.AF_INET if winner_family == socket.AF_INET6 else socket.AF_INET6][1]
            assert result[1] is winner and not winner.is_closing()
            assert finished and loser.is_closing()
            assert not proxy._upstream_writers
    run(proxy, scenario())


def test_simultaneous_success_closes_every_unselected_stream(proxy):
    async def scenario():
        async with sockets() as dial:
            pairs = {family: await dial() for family in (socket.AF_INET6, socket.AF_INET)}
            entered = set()
            ready = asyncio.Event()
            async def connect(*, family, **kwargs):
                entered.add(family)
                if len(entered) == 2:
                    ready.set()
                await ready.wait()
                return pairs[family][:2]
            with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                _, winner, _ = await proxy._happy_eyeballs_connect(addresses(), 443)
            assert sum(not pair[1].is_closing() for pair in pairs.values()) == 1
            assert not winner.is_closing()
    run(proxy, scenario())


@pytest.mark.parametrize("cancel_phase", ["delay", "race", "retirement"])
def test_parent_cancellation_closes_all_untransferred_results(proxy, monkeypatch, cancel_phase):
    async def scenario():
        async with sockets() as dial:
            pairs = {family: await dial() for family in (socket.AF_INET6, socket.AF_INET)}
            entered = asyncio.Event()
            seen = set()
            retiring = asyncio.Event()
            release_cleanup = asyncio.Event()
            async def connect(*, family, **kwargs):
                seen.add(family)
                if cancel_phase == "delay" or len(seen) == 2:
                    entered.set()
                if cancel_phase == "retirement" and family == socket.AF_INET:
                    return pairs[family][:2]
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    if cancel_phase == "retirement":
                        retiring.set()
                        try:
                            await release_cleanup.wait()
                        except BaseException:
                            pairs[family][1].close()
                            raise
                    return pairs[family][:2]
            if cancel_phase == "delay":
                monkeypatch.setattr(proxy_mod, "_HAPPY_EYEBALLS_DELAY", 60)
            with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                task = asyncio.create_task(proxy._happy_eyeballs_connect(addresses(), 443))
                await asyncio.wait_for(entered.wait(), 2)
                if cancel_phase == "retirement":
                    await asyncio.wait_for(retiring.wait(), 2)
                task.cancel()
                release_cleanup.set()
                with pytest.raises(asyncio.CancelledError):
                    await task
            for family in seen:
                assert pairs[family][1].is_closing()
            assert not proxy._upstream_writers
    run(proxy, scenario())


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6], ids=["v4", "v6"])
def test_single_family_success_keeps_transferred_writer_open(proxy, family):
    async def scenario():
        async with sockets() as dial:
            pair = await dial()
            async def connect(**kwargs):
                return pair[:2]
            with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                result = await proxy._happy_eyeballs_connect(addresses((family,)), 443)
            assert result[1] is pair[1] and not pair[1].is_closing()
    run(proxy, scenario())


@pytest.mark.parametrize("phase", ["request-write", "drain", "status", "headers"])
@pytest.mark.parametrize("failure", ["error", "cancel"])
def test_upstream_negotiation_failure_closes_backend_before_propagating(proxy, monkeypatch, phase, failure):
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
            failure_type = asyncio.CancelledError if failure == "cancel" else RuntimeError
            def fail_write(*args):
                raise failure_type("owned write fault")
            async def fail(*args, **kwargs):
                raise failure_type("owned negotiation fault")
            if phase == "request-write":
                monkeypatch.setattr(backend[1], "write", fail_write)
            elif phase == "drain":
                monkeypatch.setattr(backend[1], "drain", fail)
            elif phase == "status":
                monkeypatch.setattr(backend[0], "readuntil", fail)
            else:
                backend[3].write(b"HTTP/1.1 200 Connection established\r\n")
                await backend[3].drain()
                real_read = backend[0].readuntil
                calls = []
                async def headers(*args, **kwargs):
                    calls.append(True)
                    if len(calls) == 1:
                        return await real_read(*args, **kwargs)
                    return await fail()
                monkeypatch.setattr(backend[0], "readuntil", headers)
            async def connect(**kwargs):
                return backend[:2]
            with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                with pytest.raises(failure_type):
                    await proxy._serve_tunnel(reader, client[1])
            assert backend[1].is_closing()
            assert not proxy._upstream_writers
    run(proxy, scenario())


@pytest.mark.parametrize("phase", ["status", "headers"])
def test_oversized_upstream_line_cannot_strand_a_connected_backend(proxy, monkeypatch, phase):
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
            prefix = b"HTTP/1.1 200 Connection established\r\n" if phase == "headers" else b""
            backend[3].write(prefix + b"x" * 70000)
            await backend[3].drain()
            async def connect(**kwargs):
                return backend[:2]
            with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                with pytest.raises(asyncio.LimitOverrunError):
                    await proxy._serve_tunnel(reader, client[1])
            assert backend[1].is_closing()
            assert not proxy._upstream_writers
    run(proxy, scenario())


def test_closed_owner_disposes_a_late_connector_result(proxy):
    async def scenario():
        async with sockets() as dial:
            pair = await dial()
            owner = proxy_mod._ProxyStreamOwner(proxy._upstream_writers)
            owner.close()
            with pytest.raises(asyncio.CancelledError):
                owner.adopt(pair[1])
            assert pair[1].is_closing() and not proxy._upstream_writers
    run(proxy, scenario())


def test_transferred_stream_remains_owned_by_enclosing_tunnel(proxy):
    async def scenario():
        async with sockets() as dial:
            pair = await dial()
            owner = proxy_mod._ProxyStreamOwner(proxy._upstream_writers)
            async def connect(**kwargs):
                return pair[:2]
            with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                await proxy._happy_eyeballs_connect(addresses((socket.AF_INET,)), 443, owner=owner)
            assert pair[1] in proxy._upstream_writers and not pair[1].is_closing()
            owner.close()
            assert pair[1].is_closing() and not proxy._upstream_writers
    run(proxy, scenario())


@pytest.mark.parametrize("failure_type", [OSError, RuntimeError])
def test_failed_close_still_aborts_the_owned_transport(proxy, monkeypatch, failure_type):
    async def scenario():
        async with sockets() as dial:
            pair = await dial()
            owner = proxy_mod._ProxyStreamOwner(proxy._upstream_writers)
            owner.adopt(pair[1])
            def failed():
                raise failure_type("close failed")
            with monkeypatch.context() as fault:
                fault.setattr(pair[1], "close", failed)
                owner.close()
            await asyncio.sleep(0)
            assert pair[1].is_closing() and not proxy._upstream_writers
    run(proxy, scenario())


def test_failed_abort_remains_owned_until_cleanup_retry(proxy, monkeypatch):
    async def scenario():
        async with sockets() as dial:
            pair = await dial()
            owner = proxy_mod._ProxyStreamOwner(proxy._upstream_writers)
            owner.adopt(pair[1])
            original = pair[1].transport.abort
            calls = []
            def failed_once():
                calls.append(True)
                if len(calls) == 1:
                    raise OSError("abort failed")
                original()
            with monkeypatch.context() as fault:
                fault.setattr(pair[1].transport, "abort", failed_once)
                owner.close()
                assert pair[1] in proxy._upstream_writers
                owner.close()
            assert len(calls) == 2 and not proxy._upstream_writers
    run(proxy, scenario())


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6], ids=["v4", "v6"])
def test_handoff_to_closed_tunnel_scope_disposes_the_winner(proxy, family):
    async def scenario():
        async with sockets() as dial:
            pair = await dial()
            owner = proxy_mod._ProxyStreamOwner(proxy._upstream_writers)
            owner.close()
            async def connect(**kwargs):
                return pair[:2]
            with mock_module_attribute(proxy_mod, "asyncio", "open_connection", connect):
                with pytest.raises(asyncio.CancelledError):
                    await proxy._happy_eyeballs_connect(addresses((family,)), 443, owner=owner)
            assert pair[1].is_closing() and not proxy._upstream_writers
    run(proxy, scenario())


@pytest.mark.parametrize("blocked_family", [socket.AF_INET, socket.AF_INET6], ids=["v4", "v6"])
def test_all_failed_race_preserves_the_policy_denial(proxy, blocked_family):
    async def scenario():
        rows = addresses()
        index = 0 if blocked_family == socket.AF_INET6 else 1
        blocked = "::1" if blocked_family == socket.AF_INET6 else "10.0.0.1"
        rows[index] = (blocked_family, socket.SOCK_STREAM, 0, "", (blocked, 443))
        attempted = []
        async def refused(**kwargs):
            attempted.append(kwargs["host"])
            raise ConnectionRefusedError("owned refusal")
        with mock_module_attribute(proxy_mod, "asyncio", "open_connection", refused):
            with pytest.raises(proxy_mod._Gate2BlockedError) as failure:
                await proxy._happy_eyeballs_connect(rows, 443)
        assert failure.value.blocked_ip == blocked
        assert blocked not in attempted and len(attempted) == 1
    run(proxy, scenario())


def test_shutdown_retries_registered_upstream_cleanup(proxy, monkeypatch):
    async def scenario():
        async with sockets() as dial:
            pair = await dial()
            owner = proxy_mod._ProxyStreamOwner(proxy._upstream_writers)
            owner.adopt(pair[1])
            def failed():
                raise OSError("transient abort failure")
            with monkeypatch.context() as fault:
                fault.setattr(pair[1].transport, "abort", failed)
                owner.close()
                assert pair[1] in proxy._upstream_writers
    run(proxy, scenario())
    proxy.stop(drain_timeout=0)
    assert not proxy._upstream_writers and proxy._shutdown_complete


def test_stop_joins_the_idle_rpc_executor(proxy):
    async def scenario():
        return await asyncio.to_thread(lambda: __import__("threading").current_thread())
    worker = run(proxy, scenario())
    proxy.stop(drain_timeout=0)
    assert not worker.is_alive()
