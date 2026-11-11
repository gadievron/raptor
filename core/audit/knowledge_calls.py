"""Scoped admission of high-level client calls owned by a review unit.

These observations include client response-cache replays, but exclude hidden
transport retries. The underlying budget client remains the spend authority.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from threading import Event
from typing import TypeVar, cast

Admission = Callable[[str, str], bool]
T = TypeVar("T")


class KnowledgeCallRefused(RuntimeError):
    """A unit admission refusal, rather than a global budget failure."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Owned client dispatch refused ({reason})")


@dataclass
class _Scope:
    admit: Admission
    closed: Event
    work_id: str | None = None
    beneficiaries: tuple[str, ...] = ()


_current: ContextVar[_Scope | None] = ContextVar("audit_knowledge_call_scope", default=None)


@contextmanager
def owned_call_scope(admit: Admission, *, work_id: str | None = None,
                     beneficiaries: tuple[str, ...] = ()) -> Iterator[None]:
    scope = _Scope(admit, Event(), work_id, tuple(beneficiaries))
    token = _current.set(scope)
    try:
        yield
    finally:
        scope.closed.set()
        _current.reset(token)


def accounting_context_kwargs(client: object, *, work_id: str | None,
                              beneficiaries: tuple[str, ...]) -> dict:
    """Forward pipeline provenance only to an explicit accounting protocol."""
    try:
        version = getattr(client, "_attempt_accounting_protocol", None)
    except Exception:
        return {}
    if type(version) is not int or version != 1 or not work_id:
        return {}
    return {"accounting_work_id": work_id,
            "accounting_beneficiaries": tuple(dict.fromkeys(beneficiaries))}


class _ObservedClient:
    def __init__(self, client: object, scope: _Scope, purpose: str):
        self.__wrapped__ = client
        self._scope = scope
        self._purpose = purpose

    def __getattr__(self, name: str):
        return getattr(self.__wrapped__, name)

    def _invoke(self, method: str, args: tuple, kwargs: dict):
        if self._scope.closed.is_set():
            raise KnowledgeCallRefused("scope_closed")
        if not self._scope.admit(self._purpose, method):
            raise KnowledgeCallRefused("unit_admission")
        owned = accounting_context_kwargs(
            self.__wrapped__, work_id=self._scope.work_id,
            beneficiaries=self._scope.beneficiaries,
        )
        return getattr(self.__wrapped__, method)(*args, **{**kwargs, **owned})

    def generate(self, *args, **kwargs):
        return self._invoke("generate", args, kwargs)

    def generate_structured(self, *args, **kwargs):
        return self._invoke("generate_structured", args, kwargs)


def observed_client(client: T, *, purpose: str = "auxiliary") -> T:
    """Capture admission for helper threads without mutating shared clients."""
    scope = _current.get()
    if client is None or scope is None:
        return client
    if isinstance(client, _ObservedClient):
        if client._scope is scope and client._purpose == purpose:
            return client
        client = cast(T, client.__wrapped__)
    return cast(T, _ObservedClient(client, scope, purpose))
