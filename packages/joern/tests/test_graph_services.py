"""Multiple borrowers must not own or invalidate each other's worker."""

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from packages.joern.models import JoernCPG, JoernResult
from packages.joern.services import GraphServices
from packages.joern.tunables import JoernTunables


class Worker:
    def __init__(self):
        self.starts = self.imports = self.stops = self.restarts = 0
        self.cpg_load_epoch = 0
        self._cpg_loaded = False
        self.entered = threading.Event()
        self.proceed = threading.Event()
        self.proceed.set()
        self.error = None
        self.stopped = threading.Event()

    def start(self):
        self.starts += 1

    def import_cpg(self, path, **kw):
        self.imports += 1
        self.path = path
        self._cpg_loaded = True
        self.cpg_load_epoch += 1
        return True

    def stop(self):
        self.stops += 1
        self.stopped.set()

    def interrupt(self):
        self.proceed.set()

    def restart(self):
        self.restarts += 1
        self._cpg_loaded = True
        self.cpg_load_epoch += 1
        return True

    def query(self, query, **kw):
        self.entered.set()
        assert self.proceed.wait(3), "query fixture was not released"
        return JoernResult(query=query, errors=[self.error] if self.error else [])

    def query_cancellable(self, query, cancel_check, **kw):
        self.entered.set()
        while not self.proceed.wait(0.01):
            if cancel_check():
                return JoernResult(query=query, errors=["cancelled"])
        return self.query(query, **kw)


@pytest.fixture
def model(tmp_path):
    workers = []

    def factory(*a, **kw):
        worker = Worker()
        workers.append(worker)
        return worker

    pool = GraphServices(tmp_path / "workers", factory=factory)
    source = tmp_path / "cache.bin"
    source.write_bytes(b"first graph")
    graph = JoernCPG(source, tmp_path)
    yield pool, graph, workers
    for worker in workers:
        worker.proceed.set()
    pool.close()


def test_same_graph_shares_one_import_and_independent_leases(model):
    pool, graph, workers = model
    first = pool.acquire(graph, JoernTunables())
    second = pool.acquire(graph, JoernTunables(query_timeout_s=999))
    assert len(workers) == 1
    assert workers[0].imports == 1
    pool.release(first)
    pool.release(first)
    assert workers[0].stops == 0
    assert pool.execute(second, "query").ok
    pool.release(second)
    assert workers[0].stops == 1
    assert not workers[0].path.exists()


def test_different_graph_cannot_replace_another_borrowers_binding(model):
    pool, graph, workers = model
    first = pool.acquire(graph, JoernTunables())
    graph.path.write_bytes(b"second graph")
    second = pool.acquire(graph, JoernTunables())
    assert len(workers) == 2
    assert workers[0].path.read_bytes() == b"first graph"
    assert workers[1].path.read_bytes() == b"second graph"
    pool.release(first)
    assert pool.execute(second, "query").ok
    assert workers[1].stops == 0


def test_busy_worker_does_not_block_status_or_new_borrow(model):
    pool, graph, workers = model
    first = pool.acquire(graph, JoernTunables())
    worker = workers[0]
    worker.proceed.clear()
    with ThreadPoolExecutor() as executor:
        query = executor.submit(pool.execute, first, "long query")
        assert worker.entered.wait(2)
        try:
            second = pool.acquire(graph, JoernTunables(), timeout=0.2)
            assert pool.status(second)["ready"]
            assert worker.stops == worker.restarts == 0
        finally:
            worker.proceed.set()
        assert query.result(timeout=2).ok


def test_queue_deadline_does_not_restart_a_healthy_worker(model):
    pool, graph, workers = model
    lease = pool.acquire(graph, JoernTunables())
    worker = workers[0]
    worker.proceed.clear()
    with ThreadPoolExecutor() as executor:
        running = executor.submit(pool.execute, lease, "long query")
        assert worker.entered.wait(2)
        try:
            reply = pool.execute(lease, "queued", queue_timeout=0.01)
            assert reply.errors == ["Joern queue deadline expired"]
            assert worker.restarts == worker.stops == 0
        finally:
            worker.proceed.set()
        assert running.result(timeout=2).ok


def test_restart_invalidates_queued_requests_instead_of_replaying_them(model):
    pool, graph, workers = model
    lease = pool.acquire(graph, JoernTunables())
    worker = workers[0]
    worker.error = "query timed out after 10s"
    worker.proceed.clear()
    with ThreadPoolExecutor() as executor:
        running = executor.submit(pool.execute, lease, "stuck")
        assert worker.entered.wait(2)
        queued = executor.submit(pool.execute, lease, "queued")
        try:
            with pool.changed:
                assert pool.changed.wait_for(lambda: next(iter(pool.workers.values())).pending == 2, timeout=2)
        finally:
            worker.proceed.set()
        assert running.result(timeout=2).errors
        assert "restart" in queued.result(timeout=2).errors[0].lower()
        assert worker.restarts == 1
        assert pool.status(lease)["generation"] == 2


def test_failed_import_releases_worker_and_graph_copy(tmp_path):
    worker = Worker()
    worker.import_cpg = lambda *a, **kw: False
    pool = GraphServices(tmp_path / "workers", factory=lambda *a, **kw: worker)
    source = tmp_path / "graph.bin"
    source.write_bytes(b"graph")
    with pytest.raises(RuntimeError, match="import failed"):
        pool.acquire(JoernCPG(source, tmp_path), JoernTunables())
    assert worker.stops == 1
    assert pool.workers == pool.leases == {}
    assert list((tmp_path / "workers").iterdir()) == []


def test_closed_controller_never_admits_another_owner(model):
    pool, graph, workers = model
    lease = pool.acquire(graph, JoernTunables())
    pool.close()
    with pytest.raises(RuntimeError, match="closed"):
        pool.acquire(graph, JoernTunables())
    assert not pool.status(lease)["ready"]
    assert workers[0].stops == 1


def test_stale_cancellation_token_cannot_interrupt_another_query(model):
    pool, graph, workers = model
    lease = pool.acquire(graph, JoernTunables())
    old = object()
    assert pool.execute_request(lease, "old", old).ok
    worker = workers[0]
    worker.entered.clear()
    worker.proceed.clear()
    with ThreadPoolExecutor() as executor:
        running = executor.submit(pool.execute_request, lease, "new", object())
        assert worker.entered.wait(2)
        try:
            pool.interrupt(lease, old)
            assert not worker.proceed.is_set()
        finally:
            worker.proceed.set()
        assert running.result(timeout=2).ok


def test_concurrent_cold_borrowers_publish_only_one_worker(model):
    pool, graph, workers = model
    with ThreadPoolExecutor(max_workers=4) as executor:
        leases = list(executor.map(lambda _: pool.acquire(graph, JoernTunables()), range(4)))
    assert len(set(leases)) == 4
    assert len(workers) == 1 and workers[0].imports == 1
    for lease in leases:
        pool.release(lease)
    assert workers[0].stops == 1


def test_cancellation_before_admission_does_not_interrupt_worker(model):
    pool, graph, workers = model
    lease = pool.acquire(graph, JoernTunables())
    result = pool.execute_request(lease, "cancelled", object(), cancel_check=lambda: True)
    assert result.errors == ["cancelled before execution"]
    assert workers[0].starts == 1
    assert workers[0].stops == workers[0].restarts == 0


def test_unverified_teardown_retains_artifact_and_blocks_replacement(model):
    pool, graph, workers = model
    lease = pool.acquire(graph, JoernTunables())
    worker = workers[0]
    worker.stop = lambda: False
    pool.release(lease)
    assert worker.path.exists(), "live worker's graph must not be removed"
    assert next(iter(pool.workers.values())).state == "retained"
    with pytest.raises(RuntimeError, match="failed"):
        pool.acquire(graph, JoernTunables())
    assert len(workers) == 1


def test_no_restart_probe_cannot_leave_hidden_work_running(model):
    pool, graph, workers = model
    lease = pool.acquire(graph, JoernTunables())
    worker = workers[0]
    worker.error = "query timed out after 5s"
    result = pool.execute(lease, "probe", no_restart=True)
    assert result.errors
    assert worker.stops == 1 and worker.restarts == 0
    assert not pool.status(lease)["ready"]
    worker.error = None
    assert pool.recover(lease)["ready"]
    assert pool.execute(lease, "next request").ok


def test_active_cancellation_invalidates_queued_borrower_then_allows_recovery(model):
    pool, graph, workers = model
    active = pool.acquire(graph, JoernTunables())
    queued_lease = pool.acquire(graph, JoernTunables())
    worker = workers[0]
    worker.proceed.clear()
    cancel = threading.Event()
    with ThreadPoolExecutor() as executor:
        running = executor.submit(pool.execute, active, "active", cancel_check=cancel.is_set)
        assert worker.entered.wait(2)
        queued = executor.submit(pool.execute, queued_lease, "queued")
        try:
            with pool.changed:
                assert pool.changed.wait_for(lambda: next(iter(pool.workers.values())).pending == 2, timeout=2)
            cancel.set()
            assert "cancelled" in running.result(timeout=2).errors[0]
            assert "restart" in queued.result(timeout=2).errors[0].lower()
            assert not pool.status(queued_lease)["ready"]
            assert pool.recover(queued_lease)["ready"]
            worker.proceed.set()
            assert pool.execute(queued_lease, "fresh generation").ok
        finally:
            cancel.set()
            worker.proceed.set()
