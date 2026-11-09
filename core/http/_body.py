"""Deadlines and ownership for pooled urllib3 response bodies."""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any, Self

from urllib3.response import HTTPResponse

from core.http import HttpError, StreamWallclockExceeded


class BodyDeadline:
    """Interrupt a blocked body read without racing a reused pooled socket.

    urllib3 can return a connection to its pool while a read completes.
    Temporarily holding its pool reference keeps that socket owned until
    the watchdog has stopped. An expired watchdog shuts down only that
    owned socket; response cleanup remains on the reading thread.

    Socket lookup follows the pinned urllib3/http.client stack. Responses
    without a real socket (for example BytesIO-backed responses) use the
    same deadline checks without starting a watchdog thread.
    """

    def __init__(
        self, response: Any, deadline: float,
        *, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.response = response
        self.deadline = deadline
        self.clock = clock
        self._expired = threading.Event()
        self._timer: threading.Timer | None = None
        self._pool: Any = None
        self._held = False

    def _stop(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            if self._timer.ident is not None:
                self._timer.join()

    def _restore(self) -> None:
        if self._held:
            self.response._pool = self._pool
            self._held = False

    def check(self) -> None:
        if self._expired.is_set() or self.clock() >= self.deadline:
            raise StreamWallclockExceeded("Total timeout exceeded while reading HTTP response body")

    def __enter__(self) -> Self:
        self.check()
        if isinstance(self.response, HTTPResponse):
            self._pool = self.response._pool
            self.response._pool = None
            self._held = True
            try:
                fp = getattr(self.response._fp, "fp", None)
                sock = getattr(getattr(fp, "raw", None), "_sock", None)
                if not isinstance(sock, socket.socket):
                    sock = getattr(self.response.connection, "sock", None)
                if isinstance(sock, socket.socket):
                    def expire() -> None:
                        self._expired.set()
                        with contextlib.suppress(OSError, ValueError):
                            sock.shutdown(socket.SHUT_RDWR)

                    self._timer = threading.Timer(max(0.0, self.deadline - self.clock()), expire)
                    self._timer.daemon = True
                    self._timer.start()
            except BaseException:
                try:
                    self._stop()
                finally:
                    self._restore()
                raise
        return self

    def __exit__(self, _kind: object, error: BaseException | None, _tb: object) -> None:
        try:
            self._stop()
        finally:
            self._restore()
        # Preserve process-control exceptions; turn watchdog-induced EOF or
        # socket failures into the public HttpError-derived deadline signal.
        if error is None or isinstance(error, Exception):
            self.check()


def release_response(response: Any, *, reusable: bool = False) -> None:
    """Release completed connections, close partial responses without draining.

    A byte-bounded drain is still time-unbounded against a stalled peer.
    Completed real responses can reuse their connection; partial/error
    responses are closed before their connection is returned to the pool.
    """
    if reusable and isinstance(response, HTTPResponse) and response.isclosed():
        response.release_conn()
    try:
        response.close()
    except Exception:
        # A failed close must not put a possibly-live partial connection back
        # in the pool. Retire its slot even if closing the connection fails.
        if isinstance(response, HTTPResponse) and response._connection is not None:
            connection = response._connection
            try:
                connection.close()
            finally:
                response._connection = None
                if response._pool is not None:
                    response._pool._put_conn(None)
        raise
    else:
        response.release_conn()


@contextmanager
def response_body(response: Any, deadline: float, *, clock: Callable[[], float]):
    """Own deadline setup, blocked reads and cleanup, including setup failures."""
    reusable = False
    primary = None
    try:
        with BodyDeadline(response, deadline, clock=clock) as guard:
            yield guard
        reusable = True
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            release_response(response, reusable=reusable)
        except Exception:
            if primary is None:
                raise HttpError("HTTP response cleanup failed") from None
            primary.add_note("HTTP response cleanup also failed")
