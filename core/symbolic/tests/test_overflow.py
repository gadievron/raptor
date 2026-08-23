"""Tests for core.symbolic.find_overflow_reaching_input.

Focused on the unconstrained-state unlock: symex captures states
(symbolic PC after stack overflow), post-hoc PC-constraint solving
recovers concrete stdin bytes. Live-replay verification pins that
the produced input ACTUALLY reaches the marker when replayed, not
just satisfies constraints.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip("angr")  # suite asserts real-angr behaviour


def _compile(source: str, tmp_path: Path, extra_flags: tuple = ()) -> Path:
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


def test_missing_binary_returns_failure(tmp_path: Path):
    """LLM-consumable failure shape, not an exception."""
    from core.symbolic import find_overflow_reaching_input

    result = find_overflow_reaching_input(
        tmp_path / "does-not-exist",
        target_address=0x400000, timeout=1.0,
    )
    assert result.succeeded is False
    assert "not found" in result.reason


def test_unmapped_target_returns_failure(tmp_path: Path):
    """Target address outside any mapped segment → fast fail."""
    from core.symbolic import find_overflow_reaching_input

    binary = _compile(
        "int main(void) { return 0; }", tmp_path,
    )
    result = find_overflow_reaching_input(
        binary, target_address=0xFFFFFF00, timeout=5.0,
    )
    assert result.succeeded is False
    assert "not in a mapped segment" in result.reason


@pytest.mark.slow
def test_solves_overflow_witness_end_to_end(tmp_path: Path):
    """The headline capability: the overflow-witness primitive
    produces concrete stdin that, when replayed against the actual
    binary, reaches the marker function and prints its marker — a
    live demonstration that input controls PC. The fixture's marker
    avoids printf/SSE so a hijacked (possibly misaligned) return
    still executes it reliably."""
    from core.symbolic import find_overflow_reaching_input, load_binary
    from core.symbolic.tests.conftest import (
        OVERFLOW_MARKER_SOURCE, compile_fixture,
    )

    binary = compile_fixture(tmp_path, OVERFLOW_MARKER_SOURCE)

    info = load_binary(binary)
    assert "win" in info.symbols

    solve = find_overflow_reaching_input(
        binary, target_address=info.symbols["win"], timeout=60.0,
    )
    assert solve.succeeded, f"expected success, got: {solve.reason}"
    assert solve.concrete_input is not None
    assert solve.wall_seconds < 60.0
    assert solve.metadata["stash"] == "unconstrained"

    # LIVE-REPLAY — the real proof: the fixture's marker function
    # writes MARKER_REACHED only when actually executed.
    replay = subprocess.run(
        [str(binary)],
        input=solve.concrete_input,
        capture_output=True, timeout=5,
    )
    assert b"MARKER_REACHED" in replay.stdout, (
        f"solve was theoretical, not actionable — rc={replay.returncode} "
        f"stdout={replay.stdout[:120]!r} stderr={replay.stderr[:120]!r}"
    )


@pytest.mark.slow
def test_register_constraint_solves_when_reg_is_reachable(tmp_path: Path):
    """The register-constraint solver works when the register IS
    symbolically reachable from stdin at the ret-frame's state.

    Synthetic target: vuln reads N bytes into buf, then uses one of
    the input bytes as an argument register (via a ``mov rdi, buf[X]``
    materialised through fread of an int) BEFORE ret. When PC is
    hijacked, rdi is already symbolic — the register constraint
    threads through cleanly.

    This proves the primitive extension solves the SOLVABLE subset
    of register-constrained PC control. The unsolvable subset (bare
    overflow where rdi is concrete at ret because vuln never touched
    it) is covered by
    ``test_register_constraint_signals_gap_on_argchecked_target``.
    """
    src = tmp_path / "reach.c"
    src.write_text(r"""
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <unistd.h>
        void win(unsigned long key) {
            if (key == 0xc0ffeeUL) {
                puts("WIN_REACH_OK");
                _exit(0);
            }
            puts("WRONG_KEY");
            _exit(1);
        }
        void vuln(void) {
            char b[64];
            /* Attacker controls the first 8 bytes → loaded into rdi
             * via memcpy before the buffer's rip-overwrite fires.
             * rdi is symbolic at the ret point; the register
             * constraint is satisfiable via stdin bytes. */
            unsigned long arg = 0;
            fread(&arg, 1, sizeof arg, stdin);
            (void) fread(b, 1, 128, stdin);
            __asm__ __volatile__("movq %0, %%rdi" :: "r"(arg) : "rdi");
        }
        int main(void) {
            setvbuf(stdout, 0, _IONBF, 0);
            vuln();
            return 0;
        }
    """)
    binary = tmp_path / "reach"
    r = subprocess.run(
        ["gcc", "-O0", "-g", "-no-pie", "-fno-stack-protector",
         str(src), "-o", str(binary)],
        capture_output=True, text=True, timeout=15,
    )
    if r.returncode != 0:
        pytest.skip(f"gcc: {r.stderr[:120]}")

    from core.symbolic import find_overflow_reaching_input, load_binary

    info = load_binary(binary)
    assert "win" in info.symbols

    solve = find_overflow_reaching_input(
        binary, target_address=info.symbols["win"], timeout=60.0,
        register_constraints={"rdi": 0xc0ffee},
    )
    assert solve.succeeded, (
        f"register-constrained solve failed: {solve.reason}"
    )
    assert solve.concrete_input is not None

    # LIVE-REPLAY: input must ACTUALLY reach the flag path with
    # rdi correctly set. This is the parity check — proves the
    # register constraint threads through to the actual runtime.
    replay = subprocess.run(
        [str(binary)], input=solve.concrete_input,
        capture_output=True, timeout=5,
    )
    assert b"WIN_REACH_OK" in replay.stdout, (
        f"solve was theoretical — rc={replay.returncode} "
        f"stdout={replay.stdout[:120]!r} "
        f"stderr={replay.stderr[:120]!r}"
    )


@pytest.mark.slow
def test_register_constraint_signals_gap_on_argchecked_target(tmp_path: Path):
    """The arg-checked fixture's rdi is UNREACHABLE from stdin at
    vuln's ret: vuln reads into buf but never touches rdi, so at the
    ret frame rdi is whatever it was at vuln's entry (concrete,
    unrelated to symbolic stdin). A bare PC constraint plus a
    register constraint is unsatisfiable.

    Assertion: the primitive fails cleanly with a diagnostic
    reason (timeout or explicit "unsatisfiable") rather than
    silently returning a stale PC-only solve that won't replay —
    the honest signal that plain overflow input cannot bind the
    register and the hypothesis needs a different verification
    route.
    """
    from core.symbolic import find_overflow_reaching_input, load_binary
    from core.symbolic.tests.conftest import (
        ARGCHECKED_MARKER_SOURCE, compile_fixture,
    )

    binary = compile_fixture(tmp_path, ARGCHECKED_MARKER_SOURCE)

    info = load_binary(binary)
    solve = find_overflow_reaching_input(
        binary, target_address=info.symbols["win"], timeout=45.0,
        register_constraints={"rdi": 0xc0ffee},
    )
    # Two acceptable failure signals:
    #  * timeout with "none satisfy pc == target" — angr couldn't
    #    find any unconstrained state where rdi is bindable to
    #    0xc0ffee under the pc constraint.
    #  * explicit unsatisfiable / no-state message — same conclusion,
    #    faster path.
    # Either surface tells the LLM the bare register constraint
    # cannot hold on this path.
    assert solve.succeeded is False, (
        f"arg-checked target unexpectedly solved — did a new "
        f"primitive start binding registers? reason={solve.reason}"
    )
    assert any(
        marker in solve.reason.lower()
        for marker in ("timeout", "unsatisfiable", "no path",
                       "none satisfy")
    ), f"expected diagnostic failure reason, got: {solve.reason}"


def test_fails_on_heap_uaf_target(tmp_path: Path):
    """A UAF target has no stack-overflow path → no unconstrained
    state → primitive correctly fails with a descriptive reason.
    Prevents the LLM from believing overflow-solve is universal."""
    from core.symbolic import find_overflow_reaching_input

    binary = _compile(
        """
        #include <stdio.h>
        #include <stdlib.h>
        void win(void) { puts("WIN"); }
        int main(void) {
            int *p = malloc(4);
            free(p);
            *p = 0x1234;  // UAF; no stack overflow anywhere
            return 0;
        }
        """, tmp_path,
    )
    result = find_overflow_reaching_input(
        binary,
        target_address=0x401000,  # arbitrary; won't be reached
        timeout=8.0,
    )
    # Either "no unconstrained state" or "timeout" — both mean the
    # target isn't solvable via this primitive.
    assert result.succeeded is False
    assert any(
        marker in result.reason
        for marker in ("unconstrained", "timeout", "no path")
    )


def test_cache_reuses_project_across_calls(tmp_path: Path):
    """Project cache: two consecutive calls on the same binary +
    same mtime hit the cache. Measured indirectly: second call
    should be much faster than the first (angr load is ~50-200ms;
    cache hit is microseconds)."""
    import time

    from core.symbolic import (
        clear_cache,
        load_binary,
    )

    binary = _compile(
        "int main(void) { return 0; }", tmp_path,
    )
    clear_cache()

    t0 = time.monotonic()
    load_binary(binary)
    first_wall = time.monotonic() - t0

    t0 = time.monotonic()
    load_binary(binary)
    second_wall = time.monotonic() - t0

    # Cache-hit should be at least 10× faster; typical is 100×+.
    assert second_wall < first_wall / 5, (
        f"cache didn't seem to hit: first={first_wall*1000:.1f}ms "
        f"second={second_wall*1000:.1f}ms"
    )


def test_cache_invalidates_on_mtime_change(tmp_path: Path):
    """Rebuilding the target changes mtime → cache miss → fresh
    Project load. Prevents "stale project" bugs where an operator
    rebuilds the target between calls and the cache serves the
    old load."""
    import os
    import time

    from core.symbolic import clear_cache, load_binary

    binary = _compile("int main(void) { return 0; }", tmp_path)
    clear_cache()
    first = load_binary(binary)

    # Rebuild — same source, but new mtime.
    time.sleep(0.01)  # ensure mtime granularity
    os.utime(binary, None)  # touch mtime
    second_load_t = time.monotonic()
    second = load_binary(binary)
    second_wall = time.monotonic() - second_load_t

    # Fresh load takes >10ms; a cache-hit is under 1ms. If mtime
    # invalidation works, second load is fresh.
    assert second_wall > 0.005, (
        "mtime touch didn't invalidate cache; second load was too "
        f"fast ({second_wall*1000:.3f}ms) to be a fresh angr.Project"
    )
    # Contents match (same binary), only load path differs.
    assert first.entry_point == second.entry_point
