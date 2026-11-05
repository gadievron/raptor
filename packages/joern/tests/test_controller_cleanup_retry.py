"""Released leases must not discard retained process or graph ownership."""

from unittest.mock import Mock

import pytest

from packages.joern import artifacts, services
from packages.joern.models import JoernCPG
from packages.joern.tunables import JoernTunables


class Worker:
    def __init__(self):
        self.start = Mock()
        self.import_cpg = Mock(return_value=True)
        self.stop = Mock()


@pytest.fixture
def model(tmp_path, monkeypatch):
    monkeypatch.setattr(services, "toolchain_identity", lambda: "fixture")
    source = tmp_path / "source.bin"
    source.write_bytes(b"graph")
    workers = []

    def factory(*args, **kwargs):
        worker = Worker()
        workers.append(worker)
        return worker

    pool = services.GraphServices(tmp_path / "workers", factory=factory)
    yield pool, JoernCPG(source, tmp_path), workers
    for worker in workers:
        worker.stop.side_effect = None
        worker.stop.return_value = None
    pool.close()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stage", ["factory", "start", "import"])
def test_failed_start_retains_graph_until_cleanup_retry(
    model, monkeypatch, error, stage
):
    pool, graph, workers = model
    failure = error("startup failed")

    def factory(*args, **kwargs):
        if stage == "factory":
            raise failure
        worker = Worker()
        workers.append(worker)
        (worker.start if stage == "start" else worker.import_cpg).side_effect = failure
        return worker

    pool.factory = factory
    with monkeypatch.context() as fault:
        fault.setattr(artifacts.FrozenGraph, "close", lambda self: False)
        with pytest.raises(error) as caught:
            pool.acquire(graph, JoernTunables(heap_mb=64))
        assert caught.value is failure
        assert not pool.leases
        assert len(pool.workers) == 1
        entry = next(iter(pool.workers.values()))
        assert entry.state == "retained"
        assert entry.graph.path.exists()
        retained = entry.graph.path
    pool.close()
    assert not pool.workers
    assert not retained.exists()


def test_failed_graph_removal_survives_last_release_and_retries_on_close(
    model, monkeypatch
):
    pool, graph, workers = model
    lease = pool.acquire(graph, JoernTunables(heap_mb=64))
    entry = next(iter(pool.workers.values()))
    retained = entry.graph.path
    with monkeypatch.context() as fault:
        fault.setattr(artifacts.FrozenGraph, "close", lambda self: False)
        assert pool.release(lease) is False
        assert not pool.leases
        assert entry.state == "retained" and retained.exists()
    pool.close()
    assert not pool.workers and not retained.exists()


def test_unverified_stop_never_removes_graph_and_retries_on_repeated_close(model):
    pool, graph, workers = model
    lease = pool.acquire(graph, JoernTunables(heap_mb=64))
    worker = workers[0]
    worker.stop.return_value = False
    entry = next(iter(pool.workers.values()))
    retained = entry.graph.path
    assert pool.release(lease) is False
    pool.close()
    assert entry.state == "retained" and retained.exists()
    worker.stop.return_value = None
    pool.close()
    assert not pool.workers and not retained.exists()


def test_one_graph_cleanup_error_does_not_skip_other_workers(
    model, tmp_path, monkeypatch
):
    pool, graph, workers = model
    pool.acquire(graph, JoernTunables(heap_mb=64))
    first = next(iter(pool.workers.values()))
    source2 = tmp_path / "source2.bin"
    source2.write_bytes(b"second graph")
    pool.acquire(JoernCPG(source2, tmp_path), JoernTunables(heap_mb=64))
    second = next(entry for entry in pool.workers.values() if entry is not first)
    close = artifacts.FrozenGraph.close
    with monkeypatch.context() as fault:

        def busy(graph):
            if graph is first.graph:
                raise OSError("busy")
            return close(graph)

        fault.setattr(artifacts.FrozenGraph, "close", busy)
        pool.close()
        assert len(pool.workers) == 1
        assert first.graph.path.exists()
        assert not second.graph.path.exists()
    pool.close()
    assert not pool.workers and not first.graph.path.exists()
