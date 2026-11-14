"""Bounded one-shot public catalog handoff over an owned socketpair endpoint.

Callers create a socketpair and pass only the receiving endpoint to the worker.
Start that reader before sending: large snapshots need concurrent consumption.
Both operations consume and close their endpoint, including on failure. No
environment lookup, config fallback, provider call or thread is implicit here.
The launcher still owns process creation and capability authorisation.
"""

from __future__ import annotations

import math
import socket
import struct
import time

from core.llm.catalog import MAX_CATALOG_BYTES, CatalogError, PublicCatalog

_HEADER = struct.Struct("!I")


class CatalogBootstrapError(RuntimeError):
    """Failed handoff; never authorises credential-bearing fallback."""


def _deadline(timeout: float) -> float:
    if (type(timeout) not in (int, float) or timeout <= 0 or timeout > 60
            or not math.isfinite(timeout)):
        raise CatalogBootstrapError("Invalid catalog bootstrap timeout")
    return time.monotonic() + timeout


def _remaining(sock: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CatalogBootstrapError("Catalog bootstrap deadline exceeded")
    sock.settimeout(remaining)


def send_catalog(sock: socket.socket, catalog: PublicCatalog, *, timeout: float = 5) -> None:
    """Send a framed public snapshot and close the owned endpoint.

    The peer must already be reading, usually in a spawned worker. This is a
    blocking send bounded by one total deadline, not a queue for a future spawn.
    """
    with sock:
        deadline = _deadline(timeout)
        if type(catalog) is not PublicCatalog:
            raise CatalogBootstrapError("Expected public model catalog")
        try:
            raw = catalog.to_bytes()
            _remaining(sock, deadline)
            sock.sendall(_HEADER.pack(len(raw)))
            _remaining(sock, deadline)
            sock.sendall(raw)
        except (OSError, CatalogError):
            raise CatalogBootstrapError("Could not send public model catalog") from None


def _read_exact(sock: socket.socket, size: int, deadline: float) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        _remaining(sock, deadline)
        chunk = sock.recv(min(size - len(chunks), 65536))
        if not chunk:
            raise CatalogBootstrapError("Truncated public model catalog")
        chunks.extend(chunk)
    return bytes(chunks)


def receive_catalog(sock: socket.socket, *, timeout: float = 5) -> PublicCatalog:
    """Read exactly one bounded frame and EOF, then close the owned endpoint.

    Malformed, timed-out and unsupported snapshots are errors. The caller must
    not turn them into local credential/config reads in this worker.
    """
    with sock:
        deadline = _deadline(timeout)
        try:
            size, = _HEADER.unpack(_read_exact(sock, _HEADER.size, deadline))
            if not 0 < size <= MAX_CATALOG_BYTES:
                raise CatalogBootstrapError("Invalid public model catalog size")
            raw = _read_exact(sock, size, deadline)
            _remaining(sock, deadline)
            if sock.recv(1):
                raise CatalogBootstrapError("Trailing public model catalog data")
            catalog = PublicCatalog.from_bytes(raw)
            _remaining(sock, deadline)
            return catalog
        except (OSError, CatalogError):
            raise CatalogBootstrapError("Could not receive public model catalog") from None
