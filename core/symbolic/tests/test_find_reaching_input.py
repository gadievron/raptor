"""Tests for core.symbolic.find_reaching_input.

Covers the failure modes callers depend on for LLM decision-making:
missing binary, out-of-range address, timeout budgeting, and the
successful-path shape. Success-path testing uses a hand-authored
tiny C target that reaches a known address via natural CFG (no
overflow modelling required — that's a separate primitive).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip("angr")  # suite asserts real-angr behaviour


def _compile(source: str, tmp_path: Path, extra_flags: tuple = ()) -> Path:
    """Compile a C source string to an ELF; skip test if gcc missing."""
    src = tmp_path / "t.c"
    src.write_text(source)
    binary = tmp_path / "t"
    result = subprocess.run(
        ["gcc", "-O0", "-g", "-no-pie", "-fno-stack-protector",
         *extra_flags, str(src), "-o", str(binary)],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        pytest.skip(f"gcc: {result.stderr[:120]}")
    return binary


def test_missing_binary_returns_failure_result(tmp_path: Path):
    """Missing binary → succeeded=False + descriptive reason. Does
    NOT raise — LLM consumers branch on the returned shape."""
    from core.symbolic import find_reaching_input

    result = find_reaching_input(
        tmp_path / "does-not-exist",
        target_address=0x400000,
        timeout=1.0,
    )
    assert result.succeeded is False
    assert "not found" in result.reason
    assert result.wall_seconds >= 0.0


def test_unmapped_target_address_returns_failure(tmp_path: Path):
    """Target address outside any mapped segment → fast failure with
    descriptive reason (before spending exploration budget)."""
    from core.symbolic import find_reaching_input

    binary = _compile(
        """
        #include <stdio.h>
        int main(void) { puts("hi"); return 0; }
        """, tmp_path,
    )
    # 0xFFFFFF00 is well past any typical mapped range for a small
    # non-PIE static-address ELF.
    result = find_reaching_input(
        binary,
        target_address=0xFFFFFF00,
        timeout=5.0,
    )
    assert result.succeeded is False
    assert "not in a mapped segment" in result.reason
    assert result.metadata.get("target_address") == 0xFFFFFF00


def test_reaches_target_via_natural_cfg(tmp_path: Path):
    """Small target with a single unconditional path from main to
    a labelled address (via puts). angr should reach the puts@plt
    call site without needing input steering.

    Success criteria: succeeded=True, concrete_input bytes present
    (even if empty — the target reads no stdin so any input works),
    reason mentions "found reaching".
    """
    from core.symbolic import find_reaching_input, load_binary

    binary = _compile(
        """
        #include <stdio.h>
        void marker(void) { puts("REACHED"); }
        int main(void) { marker(); return 0; }
        """, tmp_path,
    )
    info = load_binary(binary)
    assert "marker" in info.symbols
    result = find_reaching_input(
        binary,
        target_address=info.symbols["marker"],
        timeout=15.0,
    )
    assert result.succeeded, f"expected success, got: {result.reason}"
    assert result.concrete_input is not None
    assert "found reaching input" in result.reason
    assert result.wall_seconds > 0.0
    assert result.states_explored > 0


def test_pc_control_shape_documented_not_reachable(tmp_path: Path):
    """Regression pin for the documented limitation: a stack-overflow-
    only overflow-to-PC target CANNOT be solved by bare
    find_reaching_input. This test enforces that behaviour so a
    future refactor doesn't silently start "succeeding" via a
    concretisation that doesn't actually reach the target.

    Once an explicit-overflow-model primitive lands, this test
    should move to a "expected-limitation" fixture."""
    from core.symbolic import find_reaching_input, load_binary

    binary = _compile(
        """
        #include <stdio.h>
        #include <unistd.h>
        void win(void) { puts("PWNED"); }
        int main(void) {
            char buf[16];
            read(0, buf, 128);  // overflow!
            return 0;
        }
        """, tmp_path,
    )
    info = load_binary(binary)
    result = find_reaching_input(
        binary,
        target_address=info.symbols["win"],
        timeout=8.0,
    )
    # DOCUMENTED LIMITATION: angr's default explore doesn't naturally
    # discover the overflow-writes-saved-RIP path. The test pins
    # "failure or timeout" — the moment this changes, the docstring
    # in _reach.py needs revising too.
    assert result.succeeded is False
    assert any(marker in result.reason for marker in
               ("no path to target", "timeout"))


def test_timeout_reports_states_explored(tmp_path: Path):
    """Even on timeout, states_explored is populated — useful for
    LLM to distinguish "target was hard" (many states) from "target
    was pathological" (crashed early, zero states)."""
    from core.symbolic import find_reaching_input

    binary = _compile(
        """
        #include <stdio.h>
        #include <unistd.h>
        void deep(int n) { if (n > 0) deep(n - 1); puts("done"); }
        int main(void) { deep(100); return 0; }
        """, tmp_path,
    )
    # Tight timeout on a recursive target → likely timeout.
    result = find_reaching_input(
        binary,
        target_address=0x401000,  # arbitrary in-range address
        timeout=0.5,
    )
    # States_explored is populated regardless of outcome.
    assert result.states_explored >= 0
    assert result.wall_seconds >= 0.0


@pytest.mark.slow
def test_solver_hard_target_terminates_within_budget(tmp_path: Path):
    """A hostile target whose branch guard is a hard SMT instance
    must TERMINATE near the declared budget, not hang inside a single
    native z3 call (observed pre-fix: indefinite, SIGTERM-deferred).
    The z3 per-call budget bounds total wall time by roughly
    deadline + one solver timeout."""
    import time

    from core.symbolic import find_reaching_input, load_binary
    from core.symbolic.tests.conftest import (
        SOLVER_HARD_SOURCE, compile_fixture,
    )

    binary = compile_fixture(tmp_path, SOLVER_HARD_SOURCE)
    info = load_binary(binary)
    t0 = time.monotonic()
    result = find_reaching_input(
        binary, target_address=info.symbols["win"], timeout=5.0,
    )
    wall = time.monotonic() - t0
    assert wall < 30.0, f"budget not enforced: {wall:.0f}s for timeout=5"
    assert result.succeeded is False
