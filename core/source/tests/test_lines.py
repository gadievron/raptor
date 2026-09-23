"""Tests for core.source.lines — line-range slicing."""

from __future__ import annotations

from pathlib import Path

from core.source.lines import (
    _SPLITLINES_ONLY_TERMINATORS,
    number_lines,
    read_context,
    read_lines,
    slice_lines,
    slice_text,
    split_lines,
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


class TestSplitLines:
    """The \n-only line model (external line-number producers)."""

    def test_basic(self):
        assert split_lines("a\nb\nc") == ["a", "b", "c"]

    def test_trailing_newline_dropped(self):
        assert split_lines("a\nb\n") == ["a", "b"]

    def test_empty(self):
        assert split_lines("") == []

    def test_exotic_terminators_stay_in_line(self):
        # One form feed is legal code whitespace in C and Python and
        # legal in string literals/comments everywhere — it must NOT
        # open a new line, or every subsequent index desyncs from
        # semgrep/CodeQL/ast/tree-sitter line numbers.
        for term in _SPLITLINES_ONLY_TERMINATORS:
            assert split_lines(f"a{term}b\nc") == [f"a{term}b", "c"], repr(term)

    def test_crlf_trimmed_bare_cr_stays_in_line(self):
        # \r\n: byte-decoded callers get content parity with
        # universal-newline read_text (one trailing \r trimmed).
        # Bare \r: NOT a break — semgrep/tree-sitter/raw-byte
        # scanners keep it in-line, so one plantable 0x0D must not
        # shift the count (the \f attack with a different byte).
        assert split_lines("a\r\nb\rc\r\n") == ["a", "b\rc"]
        assert split_lines("x\ry\nz") == ["x\ry", "z"]
        # only ONE trailing \r is trimmed — a genuine \r\r\n keeps one
        assert split_lines("a\r\r\nb") == ["a\r", "b"]

    def test_terminator_table_closure(self):
        # Two-direction closure derived from the splitting authority
        # itself (house pattern: prefilter's normalisation-set test):
        # (1) every char str.splitlines splits on is \n or a member
        # of _NON_NL_BREAKERS (= bare \r + the exotics); (2) every
        # exotic member really splits.  A future Python widening the
        # terminator set fails here loudly instead of silently
        # reopening the desync.
        derived: set[str] = set()
        cps = [chr(cp) for cp in range(0x110000)
               if not 0xD800 <= cp <= 0xDFFF]
        for i in range(0, len(cps), 4096):
            chunk = cps[i:i + 4096]
            probe = "a".join(chunk)
            if len(probe.splitlines()) == 1:
                continue
            derived.update(c for c in chunk
                           if len(f"a{c}b".splitlines()) > 1)
        assert derived - {"\n", "\r"} == set(_SPLITLINES_ONLY_TERMINATORS)


class TestSliceTextLineModel:
    """slice_text must speak the \n model its callers' line numbers use."""

    def test_form_feed_does_not_shift_the_slice(self):
        # \n model: line 1 is 'a\x0cb', line 2 is 'sink()'.  The old
        # splitlines() view put 'b' on its own line and handed back
        # the wrong text for every subsequent line number.
        text = "a\x0cb\nsink()\n"
        assert slice_text(text, 1, 1) == "a\x0cb"
        assert slice_text(text, 2, 2) == "sink()"

    def test_read_lines_inherits_the_model(self, tmp_path):
        f = tmp_path / "a.c"
        f.write_bytes(b"x = '\x0c'\nstrcpy(d, s);\n")
        assert read_lines(f, 2, 2) == "strcpy(d, s);"


class TestReadTextCappedNewlinePassthrough:
    def test_newline_empty_preserves_bare_cr(self, tmp_path):
        from core.source import read_text_capped

        f = tmp_path / "a.py"
        f.write_bytes(b's = "a\rb"\nx = 1\n')
        # default: universal newlines translate the bare \r
        assert read_text_capped(f)[0] == 's = "a\nb"\nx = 1\n'
        # newline="": the plantable 0x0D survives to split_lines,
        # which keeps it in-line — matching the raw-byte scanners
        raw = read_text_capped(f, newline="")[0]
        assert raw == 's = "a\rb"\nx = 1\n'
        assert split_lines(raw) == ['s = "a\rb"', "x = 1"]
