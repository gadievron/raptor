"""Tests for the availability-guard shape.

Guarantees the LLM tool surface stays consistent whether angr is
installed or not: primitives return a clean SymbolicResult with
succeeded=False + a descriptive reason + metadata pointing at the
missing dep, rather than raising ImportError.
"""
from __future__ import annotations

import pytest

from unittest.mock import patch



def test_angr_available_true_here():
    """Sanity — where angr is installed, the guard reads True."""
    pytest.importorskip("angr")
    from core.symbolic._availability import angr_available, clear_probe_cache
    clear_probe_cache()
    assert angr_available() is True

def test_z3_available_true_here():
    """Where either backend is installed, the guard reads True."""
    import importlib.util
    if not (importlib.util.find_spec("z3")
            or importlib.util.find_spec("claripy")):
        pytest.skip("neither z3 nor claripy installed")
    from core.symbolic._availability import clear_probe_cache, z3_available
    clear_probe_cache()
    assert z3_available() is True


def test_find_reaching_input_degrades_cleanly_without_angr(tmp_path):
    """When angr is unavailable, find_reaching_input returns a
    SymbolicResult with succeeded=False + a diagnostic reason
    pointing at the missing dep, not an ImportError."""
    from core.symbolic import find_reaching_input
    from core.symbolic._availability import clear_probe_cache

    binary = tmp_path / "dummy"
    binary.write_bytes(b"\x7fELFdummy")

    with patch("core.symbolic._availability._probe",
               side_effect=lambda name, mod: False):
        clear_probe_cache()
        r = find_reaching_input(binary, target_address=0x400000, timeout=1)
    clear_probe_cache()

    assert r.succeeded is False
    assert "angr" in r.reason
    assert r.metadata.get("unavailable_dep") == "angr"
    assert r.metadata.get("primitive") == "find_reaching_input"


def test_find_overflow_reaching_input_degrades_cleanly_without_angr(tmp_path):
    from core.symbolic import find_overflow_reaching_input
    from core.symbolic._availability import clear_probe_cache

    binary = tmp_path / "dummy"
    binary.write_bytes(b"\x7fELFdummy")

    with patch("core.symbolic._availability._probe",
               side_effect=lambda name, mod: False):
        clear_probe_cache()
        r = find_overflow_reaching_input(binary, target_address=0x400000, timeout=1)
    clear_probe_cache()

    assert r.succeeded is False
    assert "angr" in r.reason
    assert r.metadata.get("unavailable_dep") == "angr"


def test_discover_fmtstr_slots_degrades_cleanly_without_angr(tmp_path):
    from core.symbolic import discover_fmtstr_slots
    from core.symbolic._availability import clear_probe_cache

    binary = tmp_path / "dummy"
    binary.write_bytes(b"\x7fELFdummy")

    with patch("core.symbolic._availability._probe",
               side_effect=lambda name, mod: False):
        clear_probe_cache()
        r = discover_fmtstr_slots(
            binary, sink_addr=0x400000, fmt_arg_index=1, timeout=1,
        )
    clear_probe_cache()

    assert r.succeeded is False
    assert "angr" in r.reason


def test_extract_path_constraints_degrades_cleanly_without_angr(tmp_path):
    from core.symbolic import extract_path_constraints
    from core.symbolic._availability import clear_probe_cache

    binary = tmp_path / "dummy"
    binary.write_bytes(b"\x7fELFdummy")

    with patch("core.symbolic._availability._probe",
               side_effect=lambda name, mod: False):
        clear_probe_cache()
        r = extract_path_constraints(
            binary, target_address=0x400000, timeout=1,
        )
    clear_probe_cache()

    assert r.succeeded is False
    assert "angr" in r.reason


def test_load_binary_pyelftools_fallback_matches_angr_path(tmp_path):
    """load_binary must return the SAME BinaryInfo under both the
    angr path and the pyelftools fallback. Guarantees consumers
    (LLM tool wrappers, tests) work identically whether the heavy
    dep is present or not.
    """
    pytest.importorskip("elftools")
    pytest.importorskip("angr")
    import subprocess
    from core.symbolic import load_binary
    from core.symbolic._availability import clear_probe_cache

    src = tmp_path / "t.c"
    src.write_text("int main(){return 0;} int win(){return 42;}")
    binary = tmp_path / "t"
    r = subprocess.run(
        ["gcc", "-O0", "-g", "-no-pie", str(src), "-o", str(binary)],
        capture_output=True, text=True, timeout=15,
    )
    if r.returncode != 0:
        pytest.skip(f"gcc: {r.stderr[:120]}")

    clear_probe_cache()
    angr_info = load_binary(binary)

    def _no_angr(name, mod):
        return name != "angr"

    with patch("core.symbolic._availability._probe", side_effect=_no_angr):
        clear_probe_cache()
        py_info = load_binary(binary)
    clear_probe_cache()

    assert angr_info.arch_name == py_info.arch_name
    assert angr_info.bits == py_info.bits
    assert angr_info.entry_point == py_info.entry_point
    assert angr_info.is_pie == py_info.is_pie
    # win symbol should be present in both — non-PIE binary
    assert "win" in angr_info.symbols
    assert angr_info.symbols["win"] == py_info.symbols["win"]
