"""Borrower identity and finalization over the graph-service transport."""

import gc
import weakref

from packages.joern import lifecycle
from packages.joern.client import GraphClient
from packages.joern.tests.test_broker import controller as controller
from packages.joern.tunables import JoernTunables


def _clients(monkeypatch, controller):
    owner, graph, workers = controller
    original_factory = vars(GraphClient)["from_tunables"]

    class BoundGraphClient(GraphClient):
        @classmethod
        def from_tunables(cls, *args, **kwargs):
            return GraphClient(tunables=JoernTunables(), endpoint=(owner.root, owner.token))

    monkeypatch.setattr(lifecycle, "GraphClient", BoundGraphClient)
    assert vars(GraphClient)["from_tunables"] is original_factory
    first = lifecycle.joern_acquire()
    second = lifecycle.joern_acquire()
    first.bind_graph(graph)
    second.bind_graph(graph)
    return first, second, workers


def test_release_and_finalization_cannot_stop_another_borrower(monkeypatch, controller):
    first, second, workers = _clients(monkeypatch, controller)
    try:
        lifecycle.joern_release(token=first._lifecycle_token, srv=first)
        reference = weakref.ref(first)
        del first
        # The released client is acyclic; avoid scanning the old worker heap.
        gc.collect(0)
        assert reference() is None
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
