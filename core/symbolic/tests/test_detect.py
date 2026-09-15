"""Tests for core.symbolic.detect_shape.

Fixture-verified: the overflow-marker target → pc_control_shape=True
+ suggested primitive is find_overflow_reaching_input. The UAF
fixture (heap bug, has a marker symbol incidentally) →
pc_control_shape=False because no unbounded-read pattern in source.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


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


def _compile_fixture_with_source(
    source: str, tmp_path: Path,
) -> tuple[Path, Path]:
    """Compile a conftest fixture; return (binary, source_path)."""
    from core.symbolic.tests.conftest import compile_fixture
    binary = compile_fixture(tmp_path, source)
    return binary, tmp_path / "fixture.c"


def test_detects_pc_control_shape_on_overflow_fixture(tmp_path: Path):
    """Overflow fixture: has an unbounded read + a `win` marker
    symbol → shape detected → suggested primitive is
    find_overflow_reaching_input."""
    from core.symbolic import detect_shape
    from core.symbolic.tests.conftest import OVERFLOW_MARKER_SOURCE

    binary, source = _compile_fixture_with_source(
        OVERFLOW_MARKER_SOURCE, tmp_path)
    d = detect_shape(binary, source_path=source)
    assert d.pc_control_shape is True
    assert "core.symbolic.find_overflow_reaching_input" in d.suggested_primitives
    assert "win" in d.evidence.get("win_symbols", [])


def test_declines_pc_control_shape_on_uaf(tmp_path: Path):
    """The UAF fixture has a `win` symbol INCIDENTALLY but its bug is
    heap use-after-free, not stack overflow. Detector correctly
    declines: without an unbounded-read pattern the pc_control_shape
    flag stays False."""
    from core.symbolic import detect_shape
    from core.symbolic.tests.conftest import UAF_MARKER_SOURCE

    binary, source = _compile_fixture_with_source(
        UAF_MARKER_SOURCE, tmp_path)
    d = detect_shape(binary, source_path=source)
    # The fixture has a `win` symbol so evidence records it; the
    # shape stays False because the source shows no unbounded read.
    assert d.pc_control_shape is False


def test_binary_only_scan_finds_win_but_declines_shape(tmp_path: Path):
    pytest.importorskip("elftools")
    """Without source, we can spot the win symbol but can't verify
    the unbounded-read pattern → pc_control_shape defaults to False.
    Prevents false positives on binaries where win exists but isn't
    reached via stack overflow."""
    from core.symbolic import detect_shape

    binary = _compile(
        """
        #include <stdio.h>
        void win(void) { puts("W"); }
        int main(void) { puts("hi"); return 0; }
        """, tmp_path,
    )
    d = detect_shape(binary, source_path=None)
    assert d.pc_control_shape is False
    assert d.evidence.get("win_symbols") == ["win"]


def test_detects_fmtstr_shape_on_user_controlled_format(tmp_path: Path):
    """User-controlled format string + a printf-family sink → fmtstr_shape=True.
    No matching primitive today (find_format_string_positions is
    planned), so suggested_primitives stays empty for now."""
    from core.symbolic import detect_shape

    binary = _compile(
        """
        #include <stdio.h>
        void log_msg(char *fmt) { printf(fmt); }
        int main(void) {
            char buf[128];
            fgets(buf, sizeof buf, stdin);
            log_msg(buf);
            return 0;
        }
        """, tmp_path,
    )
    src = tmp_path / "t.c"
    d = detect_shape(binary, source_path=src)
    assert d.fmtstr_shape is True
    # Primitive doesn't exist yet — suggested_primitives correctly empty
    # for fmtstr. When find_format_string_positions lands, this test
    # updates.
    assert "core.symbolic.find_format_string_positions" not in d.suggested_primitives


def test_literal_format_args_never_flag_fmtstr_shape(tmp_path: Path):
    """fprintf/snprintf take the format at positions 2/3 — a literal
    format there must not read as user-controlled just because the
    FIRST argument (stream/buffer) is a variable. This was a
    false-positive on nearly all real C."""
    from core.symbolic import detect_shape

    binary = _compile(
        """
        #include <stdio.h>
        int main(int argc, char **argv) {
            char name[32];
            fprintf(stderr, "usage: %s\\n", argv[0]);
            snprintf(name, sizeof name, "file-%d", argc);
            printf("%s\\n", name);
            return 0;
        }
        """, tmp_path,
    )
    src = tmp_path / "t.c"
    d = detect_shape(binary, source_path=src)
    assert d.fmtstr_shape is False


def test_missing_binary_returns_declined(tmp_path: Path):
    """Missing binary → all shapes False, evidence sparse. Doesn't
    raise; caller reads the flags."""
    from core.symbolic import detect_shape

    d = detect_shape(tmp_path / "does-not-exist", source_path=None)
    assert d.pc_control_shape is False
    assert d.fmtstr_shape is False
    assert d.intsize_shape is False
    assert d.suggested_primitives == ()


def test_source_scan_fifo_past_gate_degrades_promptly(
    tmp_path: Path, monkeypatch,
):
    """detect_shape is the pre-budget router gate over attacker-supplied
    targets.  The ``is_file()`` pre-gate filters a FIFO that is ALREADY
    a FIFO at check time, but the check is stat-then-open: a swap after
    the gate reaches the read itself, and a bare ``read_text`` there
    blocks forever (open() on a reader-less FIFO never returns).  The
    guarded read must degrade to a no-source scan on its OWN fd-level
    regularity check.  Simulated by pinning the gate open — the FIFO
    hits the read exactly as in the race."""
    import os
    from pathlib import Path as _P

    from core.symbolic import detect_shape

    if not hasattr(os, "mkfifo"):
        import pytest
        pytest.skip("no mkfifo on this platform")
    fifo = tmp_path / "t.c"
    os.mkfifo(fifo)
    monkeypatch.setattr(_P, "is_file", lambda self: True)
    d = detect_shape(tmp_path / "no-binary", source_path=fifo)
    assert d.fmtstr_shape is False
    assert d.pc_control_shape is False


def test_source_scan_oversized_source_degrades(tmp_path: Path):
    """Cap direction: a source_path past the 512 KiB read cap loads at
    most the cap (never the whole planted blob) and the scan still
    returns — no crash, no unbounded read."""
    from core.symbolic import detect_shape

    src = tmp_path / "t.c"
    src.write_text("// pad\n" * 100_000)  # ~700 KB, past the cap
    d = detect_shape(tmp_path / "no-binary", source_path=src)
    assert d.fmtstr_shape is False
    assert d.pc_control_shape is False


def test_source_scan_regular_file_still_detects(tmp_path: Path):
    """Two-direction: the guarded read keeps detecting on a regular
    source file (user-controlled format → fmtstr_shape, no binary
    needed for the source-side scan)."""
    from core.symbolic import detect_shape

    src = tmp_path / "t.c"
    src.write_text(
        "#include <stdio.h>\n"
        "void log_msg(char *fmt) { printf(fmt); }\n"
    )
    d = detect_shape(tmp_path / "no-binary", source_path=src)
    assert d.fmtstr_shape is True
