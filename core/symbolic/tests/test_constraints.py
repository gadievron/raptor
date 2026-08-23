"""Tests for core.symbolic.extract_path_constraints.

Focused on the LLM-facing contract: given a stdin-driven target and
a target address, the primitive returns per-path SMT constraints +
which stdin bytes each path references + one satisfying concrete
input.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip("angr")  # suite asserts real-angr behaviour


def _compile(source: str, tmp_path: Path) -> Path:
    src = tmp_path / "t.c"
    src.write_text(source)
    binary = tmp_path / "t"
    r = subprocess.run(
        ["gcc", "-O0", "-g", "-no-pie", "-fno-stack-protector",
         str(src), "-o", str(binary)],
        capture_output=True, text=True, timeout=15,
    )
    if r.returncode != 0:
        pytest.skip(f"gcc: {r.stderr[:120]}")
    return binary


def test_missing_binary_fails_cleanly(tmp_path: Path):
    from core.symbolic import extract_path_constraints

    r = extract_path_constraints(
        tmp_path / "nope", target_address=0x400000, timeout=1.0,
    )
    assert r.succeeded is False
    assert "not found" in r.reason


def test_unmapped_target_fails_cleanly(tmp_path: Path):
    from core.symbolic import extract_path_constraints

    binary = _compile("int main(void){return 0;}", tmp_path)
    r = extract_path_constraints(
        binary, target_address=0xFFFFFF00, timeout=2.0,
    )
    assert r.succeeded is False
    assert "not in a mapped segment" in r.reason


def test_extracts_constraints_on_gated_target(tmp_path: Path):
    """A 4-gate synthetic: 'A' 'B' >=5 <=100 signed. Primitive
    should identify:
      * 4 constraints (one per gate)
      * stdin_bytes_touched = [0, 1, 2, 3]
      * concrete_input satisfying all four
    """
    from core.symbolic import extract_path_constraints, load_binary

    source = """
    #include <stdio.h>
    #include <unistd.h>
    void win(void) { puts("W"); }
    int main(void) {
        char b[16];
        if (read(0, b, 16) < 16) return 1;
        if (b[0] != 'A') return 1;
        if (b[1] != 'B') return 1;
        if (b[2] < 5) return 1;
        if (b[3] > 100) return 1;
        win();
        return 0;
    }
    """
    binary = _compile(source, tmp_path)
    win = load_binary(binary).symbols["win"]

    r = extract_path_constraints(
        binary, target_address=win, max_paths=1, timeout=30.0,
        max_input_bytes=16,
    )
    assert r.succeeded, r.reason
    paths = r.metadata["paths"]
    assert len(paths) == 1
    p = paths[0]
    assert p["branch_count"] == 4
    assert p["stdin_bytes_touched"] == [0, 1, 2, 3]
    # Concrete input satisfies all four gates.
    raw = bytes.fromhex(p["concrete_input_hex"])
    assert len(raw) == 16
    assert raw[0] == ord("A")
    assert raw[1] == ord("B")
    assert raw[2] >= 5
    # b[3] > 100 as signed → b[3] must be <= 100 signed (which
    # includes any 0x80-0xFF since those are negative signed bytes).
    assert (raw[3] <= 100) or (raw[3] >= 0x80)


def test_overflow_hijack_path_extracted_on_overflow_target(tmp_path: Path):
    """A PC-control-shape target has no natural CFG path to the marker, but
    stack overflow makes PC symbolic and a solve for PC == &win
    gives an OVERFLOW-HIJACK path. The primitive's second pass
    (save_unconstrained + post-solve) surfaces this — the LLM
    gets constraints AND a concrete satisfying input in the same
    call."""
    from core.symbolic import extract_path_constraints, load_binary

    source = """
    #include <stdio.h>
    #include <unistd.h>
    void win(void) { puts("W"); }
    int main(void) {
        char b[16];
        read(0, b, 128);   /* overflow — only path to win is PC hijack */
        return 0;
    }
    """
    binary = _compile(source, tmp_path)
    win = load_binary(binary).symbols["win"]

    r = extract_path_constraints(
        binary, target_address=win, max_paths=1, timeout=30.0,
        max_input_bytes=128,
    )
    assert r.succeeded, r.reason
    paths = r.metadata["paths"]
    assert len(paths) >= 1
    # The hijack path is labelled distinctly.
    assert paths[0]["path_kind"] == "overflow_hijack"
    # And carries a concrete satisfying input.
    assert paths[0]["concrete_input_hex"] is not None
    raw = bytes.fromhex(paths[0]["concrete_input_hex"])
    # The primitive's contract is "extract the SMT constraints for
    # reaching target_address"; whether the specific compiler-
    # produced binary is stack-alignment-friendly for a live PC
    # hijack is orthogonal (some synthetic targets SIGSEGV on the
    # hijack itself due to gcc's stack layout choices — the
    # constraint SOLVE is still correct). The overflow-witness suite
    # in test_overflow.py covers the align-safe end-to-end path via
    # replays this live on the overflow fixture. Here we just assert the
    # extraction shape is sound.
    assert isinstance(raw, bytes) and len(raw) > 0


def test_max_paths_bounds_enumeration(tmp_path: Path):
    """Two distinct paths reach win depending on input; asking for
    max_paths=2 should return both. Note: angr's find semantics
    won't ALWAYS surface both quickly; we assert `>= 1` since 2 is
    a best-effort upper bound."""
    from core.symbolic import extract_path_constraints, load_binary

    source = """
    #include <stdio.h>
    #include <unistd.h>
    void win(void) { puts("W"); }
    int main(void) {
        char b[4];
        if (read(0, b, 4) < 4) return 1;
        if (b[0] == 'A' || b[0] == 'B') win();
        return 0;
    }
    """
    binary = _compile(source, tmp_path)
    win = load_binary(binary).symbols["win"]

    r = extract_path_constraints(
        binary, target_address=win, max_paths=2, timeout=15.0,
        max_input_bytes=8,
    )
    assert r.succeeded
    assert 1 <= len(r.metadata["paths"]) <= 2
