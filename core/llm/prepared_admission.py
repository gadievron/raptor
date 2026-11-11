"""Owned admission of one prepared SDK request before transport dispatch.

The token travels with an SDK request so synchronous helper threads retain
the same admission owner. It is removed before the request reaches transport.
Callback commitment is distinct from evidence that any bytes were sent.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from threading import Event, Lock, RLock
from typing import Any
from uuid import uuid4

from .budget_errors import LLMCallAdmissionRefused


WIRE_HEADER = "X-Raptor-Attempt-Admission"

_registry_lock = Lock()
_registry: dict[str, _PreparedAttempt] = {}


class _PreparedAttempt:
    def __init__(self, callback: Callable[[Any], None]):
        self._token = uuid4().hex
        self._callback = callback
        self._lock = RLock()
        self._closed = Event()
        self._issued = False
        self._admitted = False
        self._failure: BaseException | None = None

    @property
    def token(self) -> str:
        return self._token

    @property
    def admitted(self) -> bool:
        """Whether the callback committed admission, not whether wire ran."""
        with self._lock:
            return self._admitted

    def _admit(self, request: Any) -> None:
        with self._lock:
            if self._closed.is_set():
                raise LLMCallAdmissionRefused("owned model attempt is closed")
            if self._failure is not None:
                raise self._failure
            if self._issued:
                raise LLMCallAdmissionRefused(
                    "another generation requires a new admitted model attempt")
            self._issued = True
            try:
                self._callback(request)
            except BaseException as error:
                self._failure = error
                raise
            self._admitted = True
            if self._closed.is_set():
                raise LLMCallAdmissionRefused("owned model attempt closed during admission")

    def _close(self) -> None:
        # Closing must not wait behind callback IO. A callback already in
        # progress records its commitment but checks closure before dispatch.
        self._closed.set()


@contextmanager
def prepared_attempt(callback: Callable[[Any], None]) -> Iterator[_PreparedAttempt]:
    """Own a callback for one prepared generation and retire it on exit."""
    if not callable(callback):
        raise TypeError("prepared attempt admission must be callable")
    state = _PreparedAttempt(callback)
    with _registry_lock:
        while state.token in _registry:
            state._token = uuid4().hex
        _registry[state.token] = state
    try:
        yield state
    finally:
        try:
            state._close()
        finally:
            with _registry_lock:
                _registry.pop(state.token, None)


def admit_prepared_request(request: Any) -> None:
    """HTTPX hook: consume an owned token and admit before transport runs."""
    token = request.headers.pop(WIRE_HEADER, None)
    if token is None:
        return
    with _registry_lock:
        state = _registry.get(token)
    if state is None:
        raise LLMCallAdmissionRefused("prepared model attempt is unavailable or closed")
    state._admit(request)
