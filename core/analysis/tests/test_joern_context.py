"""A nested or parallel graph session cannot overwrite another registration."""

from concurrent.futures import ThreadPoolExecutor
import threading

from core.analysis import reach_audit


def test_nested_registration_restores_outer_client():
    outer, inner = object(), object()
    first = reach_audit.set_joern_server(outer)
    try:
        second = reach_audit.set_joern_server(inner)
        assert reach_audit._joern_server.get() is inner
        reach_audit.reset_joern_server(second)
        assert reach_audit._joern_server.get() is outer
    finally:
        reach_audit.reset_joern_server(first)


def test_parallel_registrations_remain_bound_to_their_own_graph():
    barrier = threading.Barrier(2)
    clients = [object(), object()]

    def task(client):
        token = reach_audit.set_joern_server(client)
        try:
            barrier.wait(timeout=2)
            return reach_audit._joern_server.get()
        finally:
            reach_audit.reset_joern_server(token)

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert list(executor.map(task, clients)) == clients


def test_pool_jobs_capture_parent_binding_and_restore_reused_worker():
    clients = [object(), object()]
    gate = threading.Event()
    def read_after_gate():
        assert gate.wait(2)
        return reach_audit._joern_server.get()
    with ThreadPoolExecutor(max_workers=1) as executor:
        jobs = []
        for client in clients:
            token = reach_audit.set_joern_server(client)
            try:
                jobs.append(reach_audit.submit_with_joern(executor, read_after_gate))
            finally:
                reach_audit.reset_joern_server(token)
        gate.set()
        assert [job.result(timeout=2) for job in jobs] == clients
        assert executor.submit(reach_audit._joern_server.get).result(timeout=2) is None
