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


def _counting_project(monkeypatch) -> list:
    """Patch ``angr.Project`` with a counting wrapper and return the
    call log. Construction count is the cache's observable behaviour:
    hit = no new Project, miss = exactly one. Wall-clock ratios (the
    previous approach) depend on host load and flake on busy runners."""
    import angr

    real_project = angr.Project
    calls: list = []

    def counting(*args, **kwargs):
        calls.append(args)
        return real_project(*args, **kwargs)

    monkeypatch.setattr(angr, "Project", counting)
    return calls


def test_cache_reuses_project_across_calls(tmp_path: Path, monkeypatch):
    """Project cache: two consecutive calls on the same binary +
    same mtime hit the cache — the second call constructs no new
    ``angr.Project``."""
    from core.symbolic import (
        clear_cache,
        load_binary,
    )

    binary = _compile(
        "int main(void) { return 0; }", tmp_path,
    )
    clear_cache()
    calls = _counting_project(monkeypatch)

    load_binary(binary)
    assert len(calls) == 1

    load_binary(binary)
    assert len(calls) == 1, (
        "second load constructed a fresh angr.Project — cache miss "
        "on identical path + mtime"
    )


def test_cache_invalidates_on_mtime_change(tmp_path: Path, monkeypatch):
    """Rebuilding the target changes mtime → cache miss → fresh
    Project load. Prevents "stale project" bugs where an operator
    rebuilds the target between calls and the cache serves the
    old load."""
    import os
    import time

    from core.symbolic import clear_cache, load_binary

    binary = _compile("int main(void) { return 0; }", tmp_path)
    clear_cache()
    calls = _counting_project(monkeypatch)
    first = load_binary(binary)
    assert len(calls) == 1

    # Rebuild — same source, but new mtime.
    time.sleep(0.01)  # ensure mtime granularity
    os.utime(binary, None)  # touch mtime
    second = load_binary(binary)

    assert len(calls) == 2, (
        "mtime touch didn't invalidate cache; second load reused the "
        "stale angr.Project"
    )
    # Contents match (same binary), only load path differs.
    assert first.entry_point == second.entry_point


def test_register_snapshot_on_hijack_solve(tmp_path: Path):
    """A successful hijack solve carries the register state at the
    redirected PC: rsp is concrete (the frame is fixed once the
    overflow layout is chosen); the snapshot marks attacker-steerable
    registers symbolic rather than inventing values for them."""
    from core.symbolic import find_overflow_reaching_input, load_binary
    from core.symbolic.tests.conftest import (
        OVERFLOW_MARKER_SOURCE, compile_fixture,
    )

    binary = compile_fixture(tmp_path, OVERFLOW_MARKER_SOURCE)
    info = load_binary(binary)
    solve = find_overflow_reaching_input(
        binary, target_address=info.symbols["win"], timeout=60.0,
    )
    assert solve.succeeded, solve.reason

    snap = solve.metadata.get("register_snapshot")
    assert snap, "hijack solve must carry a register snapshot"
    assert "rip" not in snap  # PC is constrained by construction
    for name, entry in snap.items():
        assert ("value" in entry) ^ entry.get("symbolic", False), (
            f"{name}: exactly one of concrete/symbolic — got {entry}"
        )
    assert "value" in snap["rsp"], "stack pointer should be concrete"
    assert isinstance(snap["rsp"]["value"], int)


def test_memory_snapshot_on_hijack_solve(tmp_path: Path):
    """The hijacked state carries an rsp-relative stack window:
    concrete slots only (attacker-steerable slots stay absent),
    JSON-safe, keys in the [rsp+K] shape one-gadget constraints use."""
    import json as _json
    import re as _re

    from core.symbolic import find_overflow_reaching_input, load_binary
    from core.symbolic.tests.conftest import (
        OVERFLOW_MARKER_SOURCE, compile_fixture,
    )

    binary = compile_fixture(tmp_path, OVERFLOW_MARKER_SOURCE)
    info = load_binary(binary)
    solve = find_overflow_reaching_input(
        binary, target_address=info.symbols["win"], timeout=60.0,
    )
    assert solve.succeeded, solve.reason
    mem = solve.metadata.get("memory_snapshot")
    if mem is None:
        # every slot attacker-influenced on this fixture — legal,
        # but the register snapshot must still be present
        assert solve.metadata["register_snapshot"]
        return
    key_re = _re.compile(r"\Arsp\+0x[0-9a-f]+\Z")
    for slot, value in mem.items():
        assert key_re.match(slot), slot
        assert isinstance(value, int)
    _json.dumps(mem)  # JSON-safe end to end


def test_memory_snapshot_semantics(tmp_path: Path):
    """Two fixtures pin the memory-capture semantics.

    Smashing fixture (256-byte overflow): every program-written slot
    in the window is attacker-clobbered (symbolic) and the loader
    model's layout zeros above the entry stack pointer are excluded —
    the snapshot honestly reports NOTHING rather than model artifacts.

    Surviving fixture (40-byte overflow, stops at the return
    address): main's zeroed locals survive above the smashed frame
    and are captured as genuine concrete slots — the values one-
    gadget memory constraints ([rsp+K] == NULL) can be judged on.
    """
    from core.symbolic import find_overflow_reaching_input, load_binary
    from core.symbolic.tests.conftest import (
        OVERFLOW_MARKER_SOURCE, compile_fixture,
    )

    smash_src = OVERFLOW_MARKER_SOURCE.replace(
        "int main(void) {",
        "int main(void) {\n"
        "    volatile long zeroed[8];\n"
        "    for (int i = 0; i < 8; i++) zeroed[i] = 0;\n",
        1,
    )
    smash_dir = tmp_path / "smash"
    smash_dir.mkdir()
    binary = compile_fixture(smash_dir, smash_src)
    info = load_binary(binary)
    solve = find_overflow_reaching_input(
        binary, target_address=info.symbols["win"], timeout=60.0,
    )
    assert solve.succeeded, solve.reason
    assert solve.metadata.get("memory_snapshot") is None

    surviving_src = smash_src.replace("read(0, buf, 256)",
                                      "read(0, buf, 40)")
    assert "read(0, buf, 40)" in surviving_src
    surv_dir = tmp_path / "surv"
    surv_dir.mkdir()
    binary2 = compile_fixture(surv_dir, surviving_src)
    info2 = load_binary(binary2)
    solve2 = find_overflow_reaching_input(
        binary2, target_address=info2.symbols["win"], timeout=60.0,
    )
    assert solve2.succeeded, solve2.reason
    mem = solve2.metadata.get("memory_snapshot") or {}
    assert mem, "surviving zeroed locals should be captured"
    assert any(v == 0 for v in mem.values())
    for slot, value in mem.items():
        assert slot.startswith("rsp+0x")
        assert isinstance(value, int)


@pytest.mark.slow
def test_declared_length_overflow_solves(tmp_path: Path):
    """The classic declared-length shape (attacker length byte drives
    fread + memcpy) previously wedged z3 at ASSERT time — the solver
    timeout only bounds check-sat — and burned the whole budget for
    an honest-but-empty inconclusive. Adversarial size concretization
    pins symbolic sizes to their max satisfiable value at the
    SimProcedure boundary; the witness must solve fast AND replay to
    a real crash."""
    from core.symbolic import find_overflow_reaching_input, load_binary
    from core.symbolic.tests.conftest import (
        DECLARED_LENGTH_SOURCE, compile_fixture,
    )

    binary = compile_fixture(tmp_path, DECLARED_LENGTH_SOURCE)
    info = load_binary(binary)
    solve = find_overflow_reaching_input(
        binary, target_address=info.symbols["handle_frame"], timeout=60.0,
    )
    assert solve.succeeded, solve.reason
    assert solve.wall_seconds < 30.0

    replay = subprocess.run(
        [str(binary)], input=solve.concrete_input,
        capture_output=True, timeout=5,
    )
    assert replay.returncode < 0 or replay.returncode > 128, (
        f"witness did not crash the target: rc={replay.returncode}"
    )


def test_size_pin_helper():
    """_pin_size constrains a symbolic size to max-under-cap and
    leaves concrete or over-cap-forced sizes alone."""
    pytest.importorskip("angr")
    import claripy

    from core.symbolic._concretize import _pin_size

    class _Solver:
        def __init__(self):
            self._extra = []

        def max(self, v):
            import claripy as c
            s = c.Solver()
            for e in self._extra:
                s.add(e)
            return s.max(v)

        def satisfiable(self, extra_constraints=()):
            import claripy as c
            s = c.Solver()
            for e in list(self._extra) + list(extra_constraints):
                s.add(e)
            return s.satisfiable()

        def add(self, e):
            self._extra.append(e)

    class _State:
        solver = None

    st = _State()
    st.solver = _Solver()
    v = claripy.BVS("n", 64)
    st.solver.add(v <= 0x50)
    _pin_size(st, v, 0x1000)
    assert st.solver.max(v) == 0x50  # pinned to its own max
    s2 = _State()
    s2.solver = _Solver()
    w = claripy.BVS("m", 64)
    s2.solver.add(w >= 0x100000)  # forced above cap: left alone
    before = len(s2.solver._extra)
    _pin_size(s2, w, 0x1000)
    assert len(s2.solver._extra) == before


def test_canary_presence_flagged(tmp_path: Path):
    """A hijack solve on a stack-protected binary carries
    canary_present=True — the model guard is solver-chosen, so the
    witness is model-optimistic and consumers must weight it."""
    import subprocess as _sp

    from core.symbolic import find_overflow_reaching_input, load_binary
    from core.symbolic.tests.conftest import OVERFLOW_MARKER_SOURCE

    src = tmp_path / "t.c"
    src.write_text(OVERFLOW_MARKER_SOURCE)
    binary = tmp_path / "t"
    r = _sp.run(
        ["gcc", "-O0", "-g", "-fstack-protector-strong", "-no-pie",
         str(src), "-o", str(binary)],
        capture_output=True, text=True, timeout=15,
    )
    if r.returncode != 0:
        pytest.skip(f"gcc: {r.stderr[:120]}")
    info = load_binary(binary)
    solve = find_overflow_reaching_input(
        binary, target_address=info.symbols["win"], timeout=60.0,
    )
    if not solve.succeeded:
        pytest.skip(f"no model witness on this toolchain: {solve.reason[:80]}")
    assert solve.metadata["canary_present"] is True


def test_no_canary_not_flagged(tmp_path: Path):
    from core.symbolic import find_overflow_reaching_input, load_binary
    from core.symbolic.tests.conftest import (
        OVERFLOW_MARKER_SOURCE, compile_fixture,
    )
    binary = compile_fixture(tmp_path, OVERFLOW_MARKER_SOURCE)
    info = load_binary(binary)
    solve = find_overflow_reaching_input(
        binary, target_address=info.symbols["win"], timeout=60.0,
    )
    assert solve.succeeded
    assert solve.metadata["canary_present"] is False
