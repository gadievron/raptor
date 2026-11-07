"""Corpus replay's real I/O fixture also works without an operator corpus."""
from contextlib import contextmanager
from importlib import import_module

import pytest


@pytest.mark.parametrize('probe', ['http', 'tcp'])
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_native_replay_fixture_routes_and_restores(probe, finish):
    from core.env import verify as engine
    from core.container import proc
    from cve_env.tools import verify as adapter

    native = import_module('packages.cve_env.tests.unit.test_bench_replay_verify')
    owners = [(engine, 'socket'), (adapter, 'time'), (proc, 'subprocess')]
    before = [(owner, name, getattr(owner, name), dict(vars(getattr(owner, name))))
              for owner, name in owners]
    exchange = engine._http_exchange
    try:
        with contextmanager(native._verify_io_mocked.__wrapped__)():
            if probe == 'http':
                result = adapter.check_http(host_ip='127.0.0.1', host_port=8080)
                assert engine._http_exchange.call_count == 1
            else:
                result = adapter.check_tcp_probe(host_ip='127.0.0.1', host_port=6379,
                                                 expected_response_contains='PONG')
                assert engine.socket.create_connection.call_count == 1
            assert result['passed'], result
            for owner, name, borrowed, snapshot in before:
                assert getattr(owner, name) is not borrowed
                assert set(vars(borrowed)) == set(snapshot)
                assert all(vars(borrowed)[key] is value for key, value in snapshot.items())
            if finish == 'error':
                raise RuntimeError('owned exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        assert engine._http_exchange is exchange
        for owner, name, borrowed, snapshot in before:
            assert getattr(owner, name) is borrowed
            assert set(vars(borrowed)) == set(snapshot)
            assert all(vars(borrowed)[key] is value for key, value in snapshot.items())
