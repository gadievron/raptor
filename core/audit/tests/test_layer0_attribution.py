"""Layer 0 source pre-sweep attribution: span-sliced reads.

The pre-sweep used to read the WHOLE FILE for every evidence record and
run the pattern checks over it, so a match anywhere in the file was
attributed to every item of that file — bare declarations included
(e.g. a TOCTOU access()/open() pair elsewhere in the file pinned to an
``int tty_flag = 0;`` line). The read is now sliced to the record's
line span, binding matches to the function that actually contains them.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.diagnostics import read_function_source

_SOURCE = """\
int tty_flag = 0;

static int
check_and_open(const char *path)
{
\tif (access(path, R_OK) != 0)
\t\treturn -1;
\treturn open(path, 0);
}

static int
unrelated(int x)
{
\treturn x + 1;
}
"""


def _target(tmp_path: Path) -> Path:
    (tmp_path / "f.c").write_text(_SOURCE, encoding="utf-8")
    return tmp_path


class TestSpanSlicedRead:
    def test_span_limits_read_to_the_function(self, tmp_path):
        src = read_function_source(
            _target(tmp_path), "f.c", "check_and_open",
            line_start=3, line_end=9,
        )
        assert "access(" in src
        assert "open(" in src
        assert "tty_flag" not in src
        assert "unrelated" not in src

    def test_declaration_span_sees_no_calls_from_elsewhere(self, tmp_path):
        # The whole-file read attributed the access()/open() TOCTOU
        # pair to the tty_flag declaration; its own one-line span
        # contains neither call.
        src = read_function_source(
            _target(tmp_path), "f.c", "tty_flag",
            line_start=1, line_end=1,
        )
        assert src == "int tty_flag = 0;"
        assert "access(" not in src

    def test_no_span_preserves_whole_file_read(self, tmp_path):
        src = read_function_source(_target(tmp_path), "f.c", "check_and_open")
        assert "tty_flag" in src
        assert "unrelated" in src

    def test_toctou_fires_only_on_the_containing_function(self, tmp_path):
        from core.audit.binary_layer0 import (
            callees_from_source,
            scan_function,
        )

        target = _target(tmp_path)

        def _findings(name, ls, le):
            src = read_function_source(
                target, "f.c", name, line_start=ls, line_end=le)
            return scan_function(
                name, callees_from_source(src), source=src,
                file="f.c", language="c",
            )

        toctou_in = [f for f in _findings("check_and_open", 3, 9)
                     if f.vuln_type == "toctou"]
        assert toctou_in, "TOCTOU pair inside the function must fire"
        toctou_decl = [f for f in _findings("tty_flag", 1, 1)
                       if f.vuln_type == "toctou"]
        assert toctou_decl == []
