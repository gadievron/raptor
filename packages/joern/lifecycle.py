"""Borrower compatibility API for controller-owned graph services.

There is no shared PID/refcount file. Each acquired client has its own lease;
closing that client never signals a worker another client is using.
"""

from __future__ import annotations

import contextlib
import logging
import threading
import weakref

from .client import GraphClient
from .tunables import JoernTunables

logger = logging.getLogger(__name__)
_borrowers: weakref.WeakValueDictionary[str, GraphClient] = weakref.WeakValueDictionary()
_lock = threading.Lock()


def joern_acquire(tunables: JoernTunables | None = None) -> GraphClient | None:
    """Create a borrower; worker admission waits until its graph is known."""
    client = GraphClient.from_tunables(tunables)
    with _lock:
        _borrowers[client._lifecycle_token] = client
    return client


def joern_release(token: str | None = None, srv: GraphClient | None = None) -> None:
    """Release exactly this borrower. Repeated release is harmless.

    A token identifies a single client, not a worker generation or a refcount.
    Bare releases cannot identify an owner and deliberately affect nothing.
    """
    with _lock:
        if srv is not None:
            actual = getattr(srv, "_lifecycle_token", None)
            if token is not None and token != actual:
                logger.warning("Joern release token does not identify this borrower")
                return
            if actual is not None:
                _borrowers.pop(actual, None)
        elif token is not None:
            srv = _borrowers.pop(token, None)
        else:
            logger.warning("Joern release requires the acquired client or its token")
            return
    if srv is not None:
        srv.stop()



@contextlib.contextmanager
def shared_joern_session(tunables: JoernTunables | None = None):
    client = joern_acquire(tunables)
    try:
        yield client
    finally:
        if client is not None:
            joern_release(srv=client)


joern_session = shared_joern_session
