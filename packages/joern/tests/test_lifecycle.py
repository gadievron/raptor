"""Borrower identity and finalization over the graph-service transport."""

import gc

from packages.joern import lifecycle
from packages.joern.client import GraphClient
from packages.joern.tests.test_broker import controller as controller
from packages.joern.tunables import JoernTunables


def _clients(monkeypatch, controller):
    owner, graph, workers = controller
    factory = lambda *a, **kw: GraphClient(tunables=JoernTunables(), endpoint=(owner.root, owner.token))
    monkeypatch.setattr(lifecycle.GraphClient, "from_tunables", factory)
    first = lifecycle.joern_acquire()
    second = lifecycle.joern_acquire()
    first.bind_graph(graph)
    second.bind_graph(graph)
    return first, second, workers


def test_release_and_finalization_cannot_stop_another_borrower(monkeypatch, controller):
    first, second, workers = _clients(monkeypatch, controller)
    try:
        lifecycle.joern_release(token=first._lifecycle_token, srv=first)
        del first
        gc.collect()
        assert second.query("query").ok
        assert workers[0].stops == 0
    finally:
        lifecycle.joern_release(srv=second)
    assert workers[0].stopped.wait(2)


def test_repeated_token_release_is_idempotent(monkeypatch, controller):
    first, second, workers = _clients(monkeypatch, controller)
    token = first._lifecycle_token
    try:
        lifecycle.joern_release(token=token)
        lifecycle.joern_release(token=token)
        assert second.query("query").ok
        assert workers[0].stops == 0
    finally:
        first.stop()
        second.stop()


def test_mismatched_token_and_bare_release_affect_no_borrower(monkeypatch, controller):
    first, second, workers = _clients(monkeypatch, controller)
    try:
        lifecycle.joern_release(token=first._lifecycle_token, srv=second)
        lifecycle.joern_release()
        assert first.query("first").ok and second.query("second").ok
        assert workers[0].stops == 0
    finally:
        first.stop()
        second.stop()


def test_no_restart_probe_does_not_boot_an_unavailable_worker(monkeypatch):
    from unittest.mock import Mock
    client = GraphClient()
    lease = Mock()
    lease.status.return_value = {"ready": False, "generation": 1}
    client._lease = lease
    try:
        result = client.query("probe", no_restart=True)
        assert result.errors
        lease.recover.assert_not_called()
        lease.query.assert_not_called()
    finally:
        client.stop()
