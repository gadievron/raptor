"""Loop exit must release every proxy listener, not only the main one."""

import tempfile
from unittest.mock import Mock

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def proxy(monkeypatch):
    monkeypatch.setattr(proxy_mod.parser_jail, "get_parser_jail", lambda: Mock())
    instance = proxy_mod.EgressProxy([])
    try:
        yield instance
    finally:
        # Retain the actual socket owners for cleanup even if a regression
        # leaves server.close() unusable after the event loop has closed.
        servers = [instance._server, *instance._tcp_lane_servers.values(),
                   *instance._unix_servers.values()]
        sockets = [
            sock for server in servers if server is not None
            for sock in server._sockets or ()
        ]
        instance.stop(drain_timeout=0)
        for sock in sockets:
            sock.close()


def stop_loop(proxy):
    proxy._loop.call_soon_threadsafe(proxy._loop.stop)
    proxy._thread.join(5)
    assert not proxy.is_alive()


@pytest.mark.parametrize("public_stop", [False, True])
def test_all_listener_sockets_close_on_loop_exit(proxy, public_stop):
    port = proxy.bind_tcp_lane()
    with tempfile.TemporaryDirectory(prefix="rpt-exit-", dir="/tmp") as directory:
        path = directory + "/proxy.sock"
        proxy.bind_unix(path)
        servers = [
            proxy._server, proxy._tcp_lane_servers[port], proxy._unix_servers[path],
        ]
        if public_stop:
            proxy.stop(drain_timeout=0)
        else:
            stop_loop(proxy)
        assert proxy._loop.is_closed()
        assert all(not server.is_serving() for server in servers)
        assert all(server.sockets == () for server in servers)


def test_one_close_error_does_not_skip_other_listeners(proxy, monkeypatch):
    first = proxy.bind_tcp_lane()
    second = proxy.bind_tcp_lane()
    server = proxy._tcp_lane_servers[first]
    original_close = server.close

    def close():
        original_close()
        raise OSError("close reported an error")

    monkeypatch.setattr(server, "close", close)
    stop_loop(proxy)
    assert proxy._loop.is_closed()
    assert proxy._server.sockets == ()
    assert proxy._tcp_lane_servers[first].sockets == ()
    assert proxy._tcp_lane_servers[second].sockets == ()


def test_tracked_unix_handlers_are_cancelled_on_unexpected_exit(proxy):
    handler = Mock()
    proxy._unix_tasks.add(handler)
    stop_loop(proxy)
    handler.cancel.assert_called_once()
    assert proxy._unix_tasks == set()


@pytest.mark.parametrize("unix", [False, True])
def test_new_binds_are_refused_once_shutdown_starts(proxy, tmp_path, unix):
    proxy._stopping = True
    with pytest.raises(RuntimeError, match="stopping"):
        if unix:
            proxy.bind_unix(str(tmp_path / "proxy.sock"))
        else:
            proxy.bind_tcp_lane()
    assert proxy._tcp_lane_servers == {}
    assert proxy._unix_servers == {}


@pytest.mark.parametrize("unix", [False, True])
def test_listener_finishing_during_shutdown_is_closed_before_publication(
    proxy, tmp_path, monkeypatch, unix,
):
    server = Mock(_sockets=[], sockets=[])

    async def bind(*args, **kwargs):
        proxy._stopping = True
        return server

    method = "start_unix_server" if unix else "start_server"
    monkeypatch.setattr(proxy_mod.asyncio, method, bind)
    with pytest.raises(RuntimeError, match="stopped during listener creation"):
        if unix:
            proxy.bind_unix(str(tmp_path / "proxy.sock"))
        else:
            proxy.bind_tcp_lane()
    server.close.assert_called_once()
    assert proxy._tcp_lane_servers == {}
    assert proxy._tcp_lanes == {}
    assert proxy._unix_servers == {}
    assert proxy._unix_lanes == {}
