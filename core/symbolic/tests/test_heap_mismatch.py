"""Tests for the heap-mismatch engine's allocation tracking.

The allocation list lives in angr's ``state.globals``, whose ``copy``
on state fork is SHALLOW — the list object is shared between sibling
states.  These tests pin the copy-on-write discipline of the alloc
recorder without needing angr: a stand-in state whose ``globals`` dict
is shallow-copied reproduces exactly the sharing semantics of
``SimStateGlobals.copy``.
"""

from __future__ import annotations

from core.symbolic._heap_mismatch import _ALLOC_KEY, _append_alloc


class _FakeState:
    """Duck-typed stand-in for an angr state: ``globals`` is a dict."""

    def __init__(self, globals_dict: dict | None = None) -> None:
        self.globals: dict = {} if globals_dict is None else globals_dict

    def fork(self) -> _FakeState:
        # Shallow copy — the same semantics as SimStateGlobals.copy:
        # values (the alloc list) are NOT copied.
        return _FakeState(dict(self.globals))


def test_append_alloc_does_not_leak_into_forked_sibling() -> None:
    """An allocation recorded in one branch must not appear in the
    mutually exclusive sibling branch — a leaked entry lets the safe
    branch's copy satisfy ``dst == <other branch's alloc>`` and mint a
    false heap-overflow confirmation."""
    parent = _FakeState()
    _append_alloc(parent, "p0", 8)
    child_a = parent.fork()
    child_b = parent.fork()
    _append_alloc(child_a, "pa", 16)
    assert child_b.globals[_ALLOC_KEY] == [("p0", 8)]
    assert parent.globals[_ALLOC_KEY] == [("p0", 8)]
    assert child_a.globals[_ALLOC_KEY] == [("p0", 8), ("pa", 16)]


def test_append_alloc_records_in_own_state() -> None:
    state = _FakeState()
    _append_alloc(state, "p1", 32)
    _append_alloc(state, "p2", 64)
    assert state.globals[_ALLOC_KEY] == [("p1", 32), ("p2", 64)]
