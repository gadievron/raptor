"""Tests for core.source.lines — line-range slicing."""

from __future__ import annotations

from pathlib import Path

from core.source.lines import (
    number_lines,
    read_context,
    read_lines,
    slice_lines,
    slice_text,
)


class TestSliceLines:
    def test_basic(self):
        lines = ["a", "b", "c", "d"]
        assert slice_lines(lines, 2, 3) == ["b", "c"]

    def test_single_line(self):
        lines = ["a", "b", "c"]
        assert slice_lines(lines, 1, 1) == ["a"]

    def test_full_range(self):
        lines = ["a", "b", "c"]
        assert slice_lines(lines, 1, 3) == ["a", "b", "c"]

    def test_past_eof_clamps(self):
        lines = ["a", "b"]
        assert slice_lines(lines, 1, 999) == ["a", "b"]

    def test_zero_start(self):
        assert slice_lines(["a"], 0, 1) == []

    def test_reversed_range(self):
        assert slice_lines(["a", "b"], 3, 1) == []

    def test_empty_list(self):
        assert slice_lines([], 1, 1) == []

    def test_start_past_eof(self):
        assert slice_lines(["a"], 5, 10) == []


class TestSliceText:
    def test_basic(self):
        text = "line1\nline2\nline3\n"
        assert slice_text(text, 2, 2) == "line2"

    def test_multiline(self):
        text = "a\nb\nc\nd\n"
        assert slice_text(text, 2, 3) == "b\nc"

    def test_invalid_returns_empty(self):
        assert slice_text("a\nb\n", 0, 1) == ""

    def test_empty_text(self):
        assert slice_text("", 1, 1) == ""


class TestReadLines:
    def test_basic(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("int a;\nint b;\nint c;\n")
        assert read_lines(f, 2, 2) == "int b;"

    def test_full_file(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("line1\nline2\n")
        assert read_lines(f, 1, 2) == "line1\nline2"

    def test_missing_file(self, tmp_path: Path):
        assert read_lines(tmp_path / "gone.c", 1, 5) == ""

    def test_non_utf8(self, tmp_path: Path):
        f = tmp_path / "bin.c"
        f.write_bytes(b"line\xff one\nline two\n")
        result = read_lines(f, 1, 1)
        assert "line" in result

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.c"
        f.write_text("")
        assert read_lines(f, 1, 1) == ""

    def test_past_eof_clamps(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("only\n")
        assert read_lines(f, 1, 999) == "only"


class TestNumberLines:
    def test_basic(self):
        result = number_lines(["a", "b", "c"], 1)
        assert result == ["   1  a", "   2  b", "   3  c"]

    def test_offset_start(self):
        result = number_lines(["x", "y"], 10)
        assert result == ["  10  x", "  11  y"]

    def test_empty(self):
        assert number_lines([], 1) == []

    def test_custom_width(self):
        result = number_lines(["a"], 1, width=6)
        assert result == ["     1  a"]

    def test_single_line(self):
        result = number_lines(["only"], 42)
        assert result == ["  42  only"]


class TestReadContext:
    def test_basic(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("a\nb\nc\nd\ne\nf\ng\n")
        result = read_context(f, 4, 2)
        assert result == "b\nc\nd\ne\nf"

    def test_clamps_start(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("a\nb\nc\n")
        result = read_context(f, 1, 5)
        assert result == "a\nb\nc"

    def test_missing_file(self, tmp_path: Path):
        assert read_context(tmp_path / "gone.c", 5, 3) == ""

    def test_margin_zero(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("a\nb\nc\n")
        assert read_context(f, 2, 0) == "b"
