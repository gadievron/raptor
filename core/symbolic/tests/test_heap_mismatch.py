"""Tests for the heap-mismatch engine.

Allocation tracking: the allocation list lives in angr's
``state.globals``, whose ``copy`` on state fork is SHALLOW — the list
object is shared between sibling states.  The tracking tests pin the
copy-on-write discipline of the alloc recorder without needing angr:
a stand-in state whose ``globals`` dict is shallow-copied reproduces
exactly the sharing semantics of ``SimStateGlobals.copy``.

Public wrapper: ``find_heap_mismatch_witness`` runs through the same
isolation dispatch as the other engines; the wrapper tests here cover
its failure-shape contract end-to-end (real child spawn) plus the
full witness solve (slow tier).
"""

from __future__ import annotations

from pathlib import Path

import pytest

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


def test_missing_binary_returns_failure_result(tmp_path: Path) -> None:
    """Missing binary → succeeded=False + descriptive reason through
    the REAL isolation dispatch (child spawn included) — the same
    failure-shape contract the sibling engines pin."""
    pytest.importorskip("angr")
    from core.symbolic._heap_mismatch import find_heap_mismatch_witness

    result = find_heap_mismatch_witness(
        tmp_path / "does-not-exist",
        target_address=0x400000,
        timeout=10.0,
    )
    assert result.succeeded is False
    assert "not found" in result.reason
    assert result.concrete_input is None


#: One symbolic-length copy into a smaller heap allocation: the copy
#: hook's ``count > alloc_size`` query is satisfiable at the first
#: memcpy call, so the solve stays fast and deterministic.
#:
#: The ``n > 9`` guard makes the witness assertion sharp: the path
#: constraints admit ten models (n in 0..9) of which exactly ONE
#: overflows the 8-byte allocation. A witness concretised under path
#: constraints alone lands on a benign n most of the time (observed
#: 5/6 runs); a witness pinned to the overflow condition must carry
#: n == 9.
_HEAP_MISMATCH_SOURCE = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    unsigned char n = 0;
    char src[256];
    if (read(0, &n, 1) != 1) return 1;
    if (read(0, src, sizeof src) < 0) return 1;
    if (n > 9) return 1;
    char *dst = malloc(8);
    if (!dst) return 1;
    memcpy(dst, src, n);
    return 0;
}
"""


@pytest.mark.slow
def test_heap_mismatch_witness_end_to_end(tmp_path: Path) -> None:
    """Full pipeline through the public wrapper: hooked exploration
    finds the satisfiable ``count > alloc_size`` copy and returns a
    concrete stdin witness plus the copy-function evidence."""
    pytest.importorskip("angr")
    from core.symbolic import load_binary
    from core.symbolic._heap_mismatch import find_heap_mismatch_witness
    from core.symbolic.tests.conftest import compile_fixture

    binary = compile_fixture(tmp_path, _HEAP_MISMATCH_SOURCE)
    # The engine finds via its hook predicate, not the address; the
    # entry point just has to pass the mapped-segment sanity gate.
    entry = load_binary(binary).entry_point
    result = find_heap_mismatch_witness(
        binary,
        target_address=entry,
        timeout=120.0,
    )
    assert result.succeeded is True, result.reason
    assert result.concrete_input is not None
    assert result.metadata.get("copy_fn") == "memcpy"
    assert result.metadata.get("call_addr") is not None
    # The witness must itself trigger the overflow. Byte 0 of stdin is
    # the copy count ``n`` and the tracked allocation is 8 bytes, so a
    # witness pinned to ``count > alloc_size`` always carries n > 8.
    # An engine that only checks satisfiability without pinning dumps
    # ANY model of the bare path constraints (n == 0 reaches the same
    # copy), laundering a feasibility check into a "concrete stdin
    # witness triggers heap-copy overflow" confirmation.
    assert len(result.concrete_input) >= 1
    assert result.concrete_input[0] > 8, (
        f"witness copy count {result.concrete_input[0]} does not "
        "exceed the 8-byte allocation — the overflow condition was "
        "not pinned into the witness solve"
    )
