"""Tests for the traced-build failure stderr tail composition.

The tail is target-controlled text (traced builds execute the repo's
build scripts), so it must reach the operator's terminal escaped, and
a read-only-filesystem failure must carry the out-of-tree-build hint.
Pure message-composition tests — no codeql CLI, no sandbox.
"""

import sys
from pathlib import Path

# packages/codeql/tests/test_build_stderr_tail.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.codeql.database_manager import (
    _READONLY_TARGET_HINT,
    _build_stderr_tail,
)


class TestBuildStderrTail:
    def test_empty_and_none_yield_empty(self):
        assert _build_stderr_tail(None) == ""
        assert _build_stderr_tail("") == ""

    def test_escapes_control_characters(self):
        blob = "make: entering\n\x1b[31mcc1: fatal error\x1b[0m\nstop.\n"
        out = _build_stderr_tail(blob)
        assert "\x1b" not in out
        assert "\\x1b" in out
        assert "cc1: fatal error" in out

    def test_readonly_target_appends_hint(self):
        blob = (
            "\x07gcc -c foo.c\n"
            "foo.o: cannot create: Read-only file system\n"
        )
        out = _build_stderr_tail(blob)
        assert "\x07" not in out          # escaped, not raw
        assert "Read-only file system" in out
        assert _READONLY_TARGET_HINT in out
        assert "make O=" in out

    def test_no_hint_without_readonly_marker(self):
        out = _build_stderr_tail("make: *** [all] Error 2\n")
        assert _READONLY_TARGET_HINT not in out

    def test_tail_is_bounded_with_elision_marker(self):
        blob = "\n".join(f"line {i}" for i in range(100))
        out = _build_stderr_tail(blob)
        body = [
            line for line in out.splitlines()
            if not line.startswith("[...")
        ]
        assert len(body) <= 10
        assert out.startswith("[... earlier build output elided ...]")
        assert "line 99" in out
        assert "line 0\n" not in out

    def test_byte_bound_applies_before_line_bound(self):
        # A single enormous line must still be clipped to ~2KB.
        blob = "x" * 100_000 + "END"
        out = _build_stderr_tail(blob)
        assert len(out) < 4096
        assert out.endswith("END")

    def test_readonly_marker_outside_tail_window_gets_no_hint(self):
        # The hint keys off the SHOWN tail — a read-only error that
        # scrolled past the bounded window is not re-diagnosed.
        blob = "Read-only file system\n" + "\n".join(
            f"unrelated {i}" for i in range(50)
        )
        out = _build_stderr_tail(blob)
        assert _READONLY_TARGET_HINT not in out

    def test_short_output_carries_no_elision_marker(self):
        out = _build_stderr_tail("one\ntwo\n")
        assert not out.startswith("[...")
        assert out == "one\ntwo"
