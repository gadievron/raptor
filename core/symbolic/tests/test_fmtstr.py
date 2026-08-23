"""Tests for core.symbolic.discover_fmtstr_slots.

Focused on the LLM-facing contract: given a fmt sink address the
primitive returns a per-slot classification (code/stack/data/stdin/
concrete/symbolic) — this is what the LLM would otherwise have to
probe empirically with ``%1$p %2$p ...`` payloads.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip("angr")  # suite asserts real-angr behaviour


def _compile_pie_fmt(source: str, tmp_path: Path) -> Path:
    src = tmp_path / "t.c"
    src.write_text(source)
    binary = tmp_path / "t"
    r = subprocess.run(
        ["gcc", "-O0", "-g", "-pie", "-fPIE", "-fno-stack-protector",
         "-Wl,-z,norelro", "-U_FORTIFY_SOURCE",
         str(src), "-o", str(binary)],
        capture_output=True, text=True, timeout=15,
    )
    if r.returncode != 0:
        pytest.skip(f"gcc: {r.stderr[:120]}")
    return binary


def test_missing_binary_fails_cleanly(tmp_path: Path):
    from core.symbolic import discover_fmtstr_slots

    r = discover_fmtstr_slots(
        tmp_path / "nope", sink_addr=0x400000, timeout=1.0,
    )
    assert r.succeeded is False
    assert "not found" in r.reason


def test_out_of_range_fmt_arg_index_fails(tmp_path: Path):
    """The primitive supports fmt at register positions 1..6 only —
    args past the 6th spill onto the stack and slot mapping there
    isn't implemented."""
    from core.symbolic import discover_fmtstr_slots

    binary = _compile_pie_fmt(
        "int main(void){return 0;}", tmp_path,
    )
    r = discover_fmtstr_slots(
        binary, sink_addr=0x400000, fmt_arg_index=7, timeout=1.0,
    )
    assert r.succeeded is False
    assert "out of range" in r.reason


def test_unmapped_sink_addr_fails(tmp_path: Path):
    from core.symbolic import discover_fmtstr_slots

    binary = _compile_pie_fmt(
        "int main(void){return 0;}", tmp_path,
    )
    r = discover_fmtstr_slots(
        binary, sink_addr=0xFFFFFFF0, timeout=2.0,
    )
    assert r.succeeded is False
    assert "not in a mapped segment" in r.reason


def test_fmt_arg_index_registry_lookup():
    """The shared registry in core.function_taxonomy is what we
    consume; the helper here is a thin lookup."""
    from core.symbolic import fmt_arg_index_for

    assert fmt_arg_index_for("printf") == 1
    assert fmt_arg_index_for("fprintf") == 2
    assert fmt_arg_index_for("snprintf") == 3
    assert fmt_arg_index_for("syslog") == 2
    assert fmt_arg_index_for("not_a_fmt_sink") is None


def test_classifies_slots_on_printf_fmtstr_target(tmp_path: Path):
    """End-to-end: build a PIE + no-stack-protector target with a
    classic ``printf(buf)`` sink after a ``read(0, buf, ...)`` — the
    m2_fmtstr/m11_fmt_aslr shape — and verify slot classification
    matches the shape's known violation contract:

      * %1..%5$p come from registers rsi/rdx/rcx/r8/r9
      * The first stdin-controlled slot is around %6$p (from [rsp+8]
        onwards)
    """
    source = """
    #include <stdio.h>
    #include <unistd.h>
    int main(void) {
        char buf[128];
        int n = read(0, buf, sizeof buf - 1);
        if (n <= 0) return 1;
        buf[n] = 0;
        printf(buf);
        return 0;
    }
    """
    binary = _compile_pie_fmt(source, tmp_path)

    # Locate printf@plt via angr's loader (mirrors what a router
    # would do at dispatch time).
    import angr
    proj = angr.Project(str(binary), auto_load_libs=False)
    sink_addr = proj.loader.main_object.plt["printf"]

    from core.symbolic import discover_fmtstr_slots
    r = discover_fmtstr_slots(
        binary, sink_addr=sink_addr, fmt_arg_index=1,
        num_slots=10, timeout=30.0,
    )
    assert r.succeeded, r.reason
    slots = r.metadata["slots"]
    assert len(slots) == 10
    # Register-slot locations follow SysV amd64.
    reg_locs = [s["location"] for s in slots[:5]]
    assert reg_locs == ["rsi", "rdx", "rcx", "r8", "r9"]
    # Stack-slot locations follow [rsp+8], [rsp+16], ...
    for i, s in enumerate(slots[5:], start=6):
        assert s["location"] == f"[rsp+{8 * (i - 5)}]"
    # At least one slot in 6..10 must be stdin-controlled — this
    # target puts the stdin buf on the stack, so late slots see it.
    late_stdin = [s for s in slots[5:] if s["kind"] == "stdin"]
    assert late_stdin, (
        f"no stdin-controlled slot found in %6..%10$p — "
        f"stack layout may differ; got: {slots[5:]}"
    )


def test_snprintf_uses_fmt_arg_index_3(tmp_path: Path):
    """snprintf's fmt is arg 3 (rdx). Varargs shift right by two:
    first vararg is rcx, second is r8, third is r9, then stack."""
    source = """
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    int main(void) {
        char out[256];
        char buf[128];
        int n = read(0, buf, sizeof buf - 1);
        if (n <= 0) return 1;
        buf[n] = 0;
        snprintf(out, sizeof out, buf);  // sink
        write(1, out, strlen(out));
        return 0;
    }
    """
    binary = _compile_pie_fmt(source, tmp_path)

    import angr
    proj = angr.Project(str(binary), auto_load_libs=False)
    sink_addr = proj.loader.main_object.plt["snprintf"]

    from core.symbolic import discover_fmtstr_slots
    r = discover_fmtstr_slots(
        binary, sink_addr=sink_addr, fmt_arg_index=3,
        num_slots=6, timeout=30.0,
    )
    assert r.succeeded, r.reason
    slots = r.metadata["slots"]
    # First 3 vararg slots come from rcx, r8, r9 — not rsi/rdx as
    # they would for printf.
    assert [s["location"] for s in slots[:3]] == ["rcx", "r8", "r9"]
    # Then stack.
    assert slots[3]["location"] == "[rsp+8]"


def test_slot_dict_shape_is_stable():
    """Freeze the FmtstrSlot.as_dict() shape — LLM-facing JSON
    consumers depend on the keys being stable."""
    from core.symbolic import FmtstrSlot

    slot = FmtstrSlot(
        index=6, location="[rsp+8]", kind="stdin",
        stdin_variables=("file_0_stdin_0_1_1016",),
    )
    d = slot.as_dict()
    assert d["index"] == 6
    assert d["location"] == "[rsp+8]"
    assert d["kind"] == "stdin"
    assert d["stdin_variables"] == ["file_0_stdin_0_1_1016"]
    # No value_hex / section for symbolic slots.
    assert "value_hex" not in d
    assert "section" not in d
