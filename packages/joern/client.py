"""Analysis-compatible client for a graph-bound, controller-owned worker."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import tempfile
import uuid

from .broker import BrokerLease, discover
from .models import JoernCPG, JoernResult
from .server import JoernServer
from .tunables import JoernTunables

_INITIAL_BASE = os.environ.get("_RAPTOR_JOERN_TMP_BASE", os.environ.get("RAPTOR_WORK_DIR", os.environ.get("TMPDIR")))
if _INITIAL_BASE:
    _INITIAL_BASE = str(Path(_INITIAL_BASE).absolute())


def runtime_base():
    if _INITIAL_BASE is not None:
        if not _INITIAL_BASE:
            raise ValueError("Joern requires a usable explicit TMPDIR")
        return Path(_INITIAL_BASE).resolve(strict=True)
    if os.sys.platform == "darwin":
        value = os.confstr(65537)  # _CS_DARWIN_USER_TEMP_DIR
        if not value:
            raise RuntimeError("macOS private temporary directory unavailable")
        return Path(value).resolve(strict=True)
    return Path(tempfile.gettempdir()).resolve(strict=True)


class GraphClient(JoernServer):
    """Template/rendering compatibility without any local JVM ownership."""

    def __init__(self, *, tunables=None, runtime=None, endpoint=None, **kwargs):
        super().__init__(**kwargs)
        self._tunables = tunables or JoernTunables(
            heap_mb=self._heap_mb, heap_is_derived=self._heap_is_derived,
            query_timeout_s=self._query_timeout_s,
        )
        self._query_timeout_s = self._tunables.query_timeout_s
        self._runtime = runtime
        self._endpoint = endpoint
        self._lease = None
        self._binding_epoch = 0
        self._graph_bytes = None
        # Compatibility token identifies this borrower, not a shared lineage.
        self._lifecycle_token = uuid.uuid4().hex

    @classmethod
    def from_tunables(cls, tunables=None, **kwargs):
        # Lifetime/guard kwargs belong to the controller's worker, not clients.
        kwargs.pop("orphan_idle_ttl_s", None)
        return cls(tunables=tunables or JoernTunables.from_tuning(), **kwargs)

    def start(self):
        # Worker admission happens after the graph bytes are known. In
        # particular, do not reserve a query JVM while its parser is running.
        return None

    def bind_graph(self, cpg: JoernCPG, *, timeout=None):
        from dataclasses import replace
        cpg = replace(cpg, path=cpg.path.resolve(), target=cpg.target.resolve())
        tunables = self._tunables
        if timeout is not None:
            tunables = replace(tunables, import_timeout_s=timeout)
        self.stop()
        endpoint = self._endpoint or discover(Path(self._runtime) if self._runtime else runtime_base())
        self._last_post_error = ""
        try:
            broker_root, broker_token = endpoint
            self._lease = BrokerLease.acquire(broker_root, broker_token, cpg, tunables)
            status = self._lease.status()
            if not status["ready"]:
                status = self._lease.recover()
            if not status.get("ready"):
                self.stop()
                return False
            self._heap_mb = status.get("heap_mb")
            self._graph_bytes = status.get("graph_bytes")
            self._heap_is_derived = status.get("heap_is_derived", False)
        except Exception as error:
            self._last_post_error = str(error)
            self.stop()
            raise
        self._cpg_loaded = True
        self._cpg_path = cpg.path
        self._binding_epoch += 1
        return True

    def import_cpg(self, cpg_path, *, timeout=None):
        path = Path(cpg_path).resolve(strict=True)
        return self.bind_graph(JoernCPG(path, path.parent), timeout=timeout)

    def import_code(self, target_path, *, timeout=300):
        from .runner import build_cpg, cleanup_cpg
        graph = build_cpg(Path(target_path), timeout=timeout,
                          heap_mb=self._tunables.heap_mb,
                          heap_is_derived=self._tunables.heap_is_derived)
        try:
            if graph.build_failed or not graph.exists():
                return False
            return self.bind_graph(graph, timeout=timeout)
        finally:
            if graph.exists():
                cleanup_cpg(graph)

    def stop(self):
        return self._close_lease(wait=True)

    def _close_lease(self, *, wait):
        lease = getattr(self, "_lease", None)
        self._lease = None
        self._cpg_loaded = False
        self._graph_bytes = None
        if lease is not None:
            return lease.close(wait=wait)
        return True

    def stop_fast(self, *args, **kwargs):
        self._close_lease(wait=False)

    def close_workspace(self):
        self.stop()

    def query(self, cpgql, *, timeout=None, validate=True, check_length=True,
              no_restart=False):
        lease = self._lease
        if lease is None:
            return JoernResult(query=cpgql, errors=["no CPG loaded (call import_cpg first)"])
        ready = self.is_alive() if no_restart else self.ensure_alive()
        if not ready:
            return JoernResult(query=cpgql, errors=["Joern worker is unavailable"])
        return lease.query(cpgql, timeout=timeout or self._query_timeout_s,
                           validate=validate, check_length=check_length,
                           no_restart=no_restart)

    def query_cancellable(self, cpgql, *, cancel_check=None, timeout=None,
                          validate=True, check_length=True, **kwargs):
        lease = self._lease
        if lease is None:
            return JoernResult(query=cpgql, errors=["no CPG loaded (call import_cpg first)"])
        if not self.ensure_alive():
            return JoernResult(query=cpgql, errors=["Joern worker is unavailable"])
        return lease.query(cpgql, timeout=timeout or self._query_timeout_s,
                           cancel_check=cancel_check, validate=validate,
                           check_length=check_length)

    def _status(self):
        lease = getattr(self, "_lease", None)
        if lease is not None:
            with contextlib.suppress(OSError, ValueError, EOFError):
                return lease.status()
        return {"ready": False, "generation": 0}

    def cpg_size_bytes(self):
        return self._graph_bytes

    def is_alive(self):
        return self._status()["ready"]

    def health_check(self, **kwargs):
        return self.is_alive()

    def ensure_alive(self, **kwargs):
        if self.is_alive():
            return True
        if self._lease is not None:
            with contextlib.suppress(OSError, ValueError, EOFError):
                return bool(self._lease.recover().get("ready"))
        return False

    @property
    def cpg_load_epoch(self):
        return (self._binding_epoch << 32) + self._status()["generation"]

    @property
    def restarting(self):
        return self._lease is not None and self._status().get("state") in ("starting", "recovering")

    @classmethod
    def connect_existing(cls, **kwargs):
        raise RuntimeError("acquire a graph-bound client instead of a raw Joern endpoint")

    def restart(self):
        # A borrower cannot kill/restart other callers' work. Execution
        # failures are recovered by the controller owning that generation.
        return False

    def __del__(self):
        with contextlib.suppress(Exception):
            self.stop_fast()
