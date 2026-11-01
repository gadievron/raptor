"""Graph-bound worker ownership, borrower leases and serialized execution.

Only this controller owns worker processes. Frontends receive lease clients;
the transport can close a lease without transferring process ownership.
"""

from __future__ import annotations

import hashlib

from core.json import dumps_canonical
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .artifacts import FrozenGraph, graph_digest, toolchain_identity
from .models import JoernCPG, JoernResult
from .server import JoernServer, _RESTARTING_ERROR
from .tunables import JoernTunables


def _confined_worker(tunables, **kwargs):
    if tunables.heap_mb is None:
        from dataclasses import replace
        default = JoernTunables.from_tuning()
        if default.heap_mb is None:
            raise RuntimeError("persistent Joern worker requires a bounded heap")
        tunables = replace(tunables, heap_mb=default.heap_mb,
                           heap_is_derived=default.heap_is_derived)
    return JoernServer.from_tunables(tunables, confined=True, **kwargs)


@dataclass
class _Worker:
    graph: FrozenGraph | None
    server: JoernServer | None
    leases: set[str] = field(default_factory=set)
    serial: threading.Lock = field(default_factory=threading.Lock)
    state: str = "starting"
    generation: int = 1
    pending: int = 0
    last_recovery: float | None = None
    active_request: object | None = None
    active_lease: str | None = None


class GraphServices:
    """Single process-owner control plane; all RPC handlers share this object."""

    def __init__(self, directory: Path, *, factory=_confined_worker,
                 queue_limit: int = 64):
        self.directory = directory
        self.factory = factory
        self.queue_limit = queue_limit
        self.changed = threading.Condition()
        self.workers: dict[str, _Worker] = {}
        self.leases: dict[str, str] = {}
        self.closed = False

    def acquire(self, cpg: JoernCPG, tunables: JoernTunables,
                *, timeout: float = 1200) -> str:
        if cpg.build_failed:
            raise ValueError("a failed graph build cannot be admitted")
        if tunables.heap_mb is None:
            from dataclasses import replace
            defaults = JoernTunables.from_tuning()
            if defaults.heap_mb is None:
                raise RuntimeError("Joern worker requires a bounded heap")
            tunables = replace(tunables, heap_mb=defaults.heap_mb,
                               heap_is_derived=defaults.heap_is_derived)
        source_digest = cpg.content_digest or graph_digest(cpg.path)
        # Query deadlines belong to requests; the actual worker heap and
        # backend version determine whether a JVM is compatible for sharing.
        key = hashlib.sha256(dumps_canonical([
            source_digest, toolchain_identity(), tunables.heap_mb,
            tunables.heap_is_derived,
        ]).encode()).hexdigest()
        deadline = time.monotonic() + timeout
        lease = uuid.uuid4().hex
        with self.changed:
            if self.closed:
                raise RuntimeError("Joern controller is closed")
            while key in self.workers and self.workers[key].state != "ready":
                if self.workers[key].state in ("failed", "retained"):
                    raise RuntimeError("Joern worker failed; recovery required")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Joern worker admission deadline expired")
                self.changed.wait(remaining)
                if self.closed:
                    raise RuntimeError("Joern controller is closed")
            entry = self.workers.get(key)
            if entry is not None:
                entry.leases.add(lease)
                self.leases[lease] = key
                return lease
            entry = _Worker(None, None, leases={lease})
            self.workers[key] = entry
        graph = server = None
        try:
            graph = FrozenGraph.copy(cpg.path, directory=self.directory,
                                     expected=source_digest)
            server = self.factory(tunables, orphan_idle_ttl_s=10,
                                  graph_read_paths=(str(graph.path.parent),))
            entry.graph, entry.server = graph, server
            server.start()
            if not server.import_cpg(graph.path, timeout=tunables.import_timeout_s):
                detail = str(getattr(server, "_last_post_error", ""))
                reason = "timed out" if "timed out" in detail else "connection lost" if "connect" in detail else "failed"
                raise RuntimeError(f"Joern graph import failed: {reason}")
            with self.changed:
                if self.closed:
                    raise RuntimeError("Joern controller closed during startup")
                self.leases[lease] = key
                entry.state = "ready"
                self.changed.notify_all()
        except BaseException:
            retained = False
            if server is not None:
                try:
                    retained = server.stop() is False
                except Exception:
                    retained = True
            if graph is not None and not retained:
                graph.close()
            with self.changed:
                if retained:
                    entry.state = "retained"
                    entry.leases.clear()
                else:
                    self.workers.pop(key, None)
                self.changed.notify_all()
            raise
        return lease

    def status(self, lease: str) -> dict:
        with self.changed:
            key = self.leases.get(lease)
            entry = self.workers.get(key) if key is not None else None
            if entry is None:
                return {"ready": False, "generation": 0, "state": "closed"}
            server, graph = entry.server, entry.graph
            if server is None or graph is None:
                return {"ready": False, "generation": entry.generation, "state": entry.state}
            process = getattr(server, "_proc", None)
            alive = process is None or process.poll() is None
            return {"ready": entry.state == "ready" and server._cpg_loaded and alive,
                    "generation": entry.generation,
                    "pending": entry.pending,
                    "state": entry.state,
                    "heap_mb": getattr(entry.server, "_heap_mb", None),
                    "heap_is_derived": getattr(entry.server, "_heap_is_derived", False),
                    "graph_bytes": graph.path.stat().st_size}

    def has_lease(self, lease: str) -> bool:
        with self.changed:
            return lease in self.leases

    def interrupt(self, lease: str, request_id: object):
        """Abort only the execution identified by this handler's private token."""
        with self.changed:
            key = self.leases.get(lease)
            entry = self.workers.get(key) if key is not None else None
            if entry is None:
                # A control connection may have released the lease already.
                entry = next((item for item in self.workers.values()
                              if item.active_lease == lease), None)
            if entry is None or entry.active_request is not request_id:
                return
            server = entry.server
            if server is not None:
                server.interrupt()

    def recover(self, lease: str, *, cooldown_s=300) -> dict:
        with self.changed:
            key = self.leases.get(lease)
            entry = self.workers.get(key) if key is not None else None
            if entry is None or entry.state in ("starting", "recovering", "draining") or entry.server is None:
                return {"ready": False, "generation": 0}
        server = entry.server
        if not entry.serial.acquire(blocking=False):
            return self.status(lease)
        try:
            with self.changed:
                if lease not in self.leases or entry.state == "draining":
                    return {"ready": False, "generation": 0}
                if self.status(lease)["ready"]:
                    return self.status(lease)
                now = time.monotonic()
                if entry.last_recovery is not None and now - entry.last_recovery < cooldown_s:
                    return self.status(lease)
                entry.last_recovery = now
                entry.state = "recovering"
            recovered = False
            try:
                recovered = bool(server.restart())
            finally:
                with self.changed:
                    entry.generation += 1
                    entry.state = ("ready" if recovered and server._cpg_loaded else "failed") if entry.leases else "draining"
                    self.changed.notify_all()
            return self.status(lease)
        finally:
            entry.serial.release()

    def release(self, lease: str) -> bool:
        with self.changed:
            key = self.leases.pop(lease, None)
            if key is None:
                return True
            entry = self.workers.get(key)
            if entry is None:
                return True
            server, graph = entry.server, entry.graph
            if server is None or graph is None:
                return False
            entry.leases.discard(lease)
            if entry.leases:
                return True
            entry.state = "draining"
        # Queries already admitted finish or observe cancellation first.
        # An acquisition cannot create a replacement while teardown runs.
        with entry.serial:
            try:
                stopped = server.stop()
            except Exception:
                stopped = False
            with self.changed:
                if stopped is False:
                    entry.state = "retained"
                else:
                    graph.close()
                    self.workers.pop(key, None)
                self.changed.notify_all()
            return stopped is not False

    def execute(self, lease: str, query: str, *, timeout: int = 300,
                queue_timeout: float = 300, cancel_check=None,
                validate: bool = True, check_length: bool = True,
                no_restart: bool = False) -> JoernResult:
        return self._execute(lease, query, timeout=timeout, queue_timeout=queue_timeout,
                             cancel_check=cancel_check, validate=validate,
                             check_length=check_length, no_restart=no_restart)

    def execute_request(self, lease, query, request_id, **kwargs):
        return self._execute(lease, query, request_id=request_id, **kwargs)

    def _execute(self, lease, query, *, timeout=300, queue_timeout=300,
                 cancel_check=None, validate=True, check_length=True,
                 no_restart=False, request_id=None):
        with self.changed:
            key = self.leases.get(lease)
            entry = self.workers.get(key) if key is not None else None
            if entry is None:
                return JoernResult(query=query, errors=["Joern lease is closed"])
            if entry.state != "ready":
                return JoernResult(query=query, errors=[_RESTARTING_ERROR])
            if entry.pending >= self.queue_limit:
                return JoernResult(query=query, errors=["Joern request queue is full"])
            generation = entry.generation
            entry.pending += 1
            self.changed.notify_all()
        acquired = False
        try:
            deadline = time.monotonic() + queue_timeout
            while True:
                if cancel_check is not None and cancel_check():
                    return JoernResult(query=query, errors=["cancelled before execution"])
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return JoernResult(query=query, errors=["Joern queue deadline expired"])
                acquired = entry.serial.acquire(timeout=min(remaining, 0.05))
                if acquired:
                    break
            with self.changed:
                if lease not in self.leases:
                    return JoernResult(query=query, errors=["Joern lease is closed"])
                if entry.generation != generation or entry.state != "ready":
                    return JoernResult(query=query, errors=[_RESTARTING_ERROR])
                if cancel_check is not None and cancel_check():
                    return JoernResult(query=query, errors=["cancelled before execution"])
                entry.active_request, entry.active_lease = request_id, lease
            before = entry.server.cpg_load_epoch
            if cancel_check is None or request_id is not None:
                result = entry.server.query(query, timeout=timeout, validate=validate,
                                            check_length=check_length, no_restart=True, isolate_scope=True)
            else:
                result = entry.server.query_cancellable(
                    query, timeout=timeout, cancel_check=cancel_check,
                    validate=validate, check_length=check_length, isolate_scope=True,
                )
            if cancel_check is not None and cancel_check():
                entry.server.stop()
                with self.changed:
                    entry.generation += 1
                    entry.state = "failed" if entry.leases else "draining"
                return JoernResult(query=query, errors=["cancelled"])
            # Only the controller holding the execution lane may recover.
            # Queue expiry never reaches this branch and never kills a JVM.
            execution_lost = result.execution_incomplete or any(
                "timed out" in error or "server process exited" in error
                for error in result.errors
            ) or not entry.server._cpg_loaded
            if execution_lost and no_restart:
                # The caller may decline a new boot, but cannot abandon work
                # in the shared REPL. Stop it and defer recovery to the next
                # actual request. Queue expiry never enters this branch.
                entry.server.stop()
                with self.changed:
                    entry.generation += 1
                    entry.state = "failed" if entry.leases else "draining"
                    self.changed.notify_all()
                return result
            with self.changed:
                needs_restart = bool(entry.leases) and execution_lost
            if needs_restart:
                with self.changed:
                    entry.state = "recovering"
                    entry.last_recovery = time.monotonic()
                recovered = False
                try:
                    recovered = bool(entry.server.restart())
                finally:
                    with self.changed:
                        entry.generation += 1
                        entry.state = ("ready" if recovered and entry.server._cpg_loaded else "failed") if entry.leases else "draining"
                        self.changed.notify_all()
            elif entry.server.cpg_load_epoch != before:
                with self.changed:
                    entry.generation += 1
                    self.changed.notify_all()
            return result
        finally:
            with self.changed:
                if acquired:
                    entry.active_request = entry.active_lease = None
                entry.pending -= 1
                self.changed.notify_all()
            if acquired:
                entry.serial.release()

    def close(self):
        with self.changed:
            self.closed = True
            self.changed.notify_all()
            leases = list(self.leases)
        for lease in leases:
            self.release(lease)
