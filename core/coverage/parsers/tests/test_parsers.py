"""Unit tests for the Phase 4 runtime-coverage parsers + dispatch."""

from __future__ import annotations

import json

from core.coverage.parsers import (
    available_formats,
    default_tool,
    detect_format,
    parse,
)
from core.coverage.parsers.coverage_py import parse_coverage_py
from core.coverage.parsers.gcov import parse_gcov, parse_lcov

_GCOV = """\
        -:    0:Source:foo.c
        -:    0:Graph:foo.gcno
        5:    1:int main(void) {
        5:    2:    return helper();
    #####:    3:    dead();
        -:    4:}
"""

_LCOV = """\
SF:src/bar.c
DA:1,3
DA:2,0
DA:5,1
end_of_record
SF:src/baz.c
DA:10,2
end_of_record
"""


# --- coverage.py ------------------------------------------------------------

def test_coverage_py_executed_lines(tmp_path):
    p = tmp_path / "coverage.json"
    p.write_text(json.dumps({"files": {
        "pkg/mod.py": {"executed_lines": [1, 2, 5, 6], "missing_lines": [3, 4]},
        "pkg/empty.py": {"executed_lines": []},
    }}))
    out = parse_coverage_py(p)
    assert out == {"pkg/mod.py": {1, 2, 5, 6}}      # empty file dropped


def test_coverage_py_accepts_directory(tmp_path):
    (tmp_path / "coverage.json").write_text(json.dumps(
        {"files": {"a.py": {"executed_lines": [1]}}}))
    assert parse_coverage_py(tmp_path) == {"a.py": {1}}


def test_coverage_py_tolerates_garbage(tmp_path):
    p = tmp_path / "coverage.json"
    p.write_text("{ not json")
    assert parse_coverage_py(p) == {}
    p.write_text(json.dumps({"files": "nope"}))
    assert parse_coverage_py(p) == {}


# --- gcov -------------------------------------------------------------------

def test_gcov_executed_lines_and_source_header(tmp_path):
    g = tmp_path / "foo.c.gcov"
    g.write_text(_GCOV)
    out = parse_gcov(g)
    assert out == {"foo.c": {1, 2}}             # line 3 never-run, 4 non-code


def test_gcov_human_readable_count_executed(tmp_path):
    # gcov -H emits counts like "1.2k"; treat any non-#####/=====/- count as run.
    g = tmp_path / "x.c.gcov"
    g.write_text("        -:    0:Source:x.c\n"
                 "     1.2k:    1:hot();\n"
                 "    #####:    2:cold();\n")
    assert parse_gcov(g) == {"x.c": {1}}


def test_gcov_directory_and_stem_fallback(tmp_path):
    # No Source: header -> fall back to the .gcov stem (foo.c.gcov -> foo.c).
    (tmp_path / "foo.c.gcov").write_text("        7:    1:x\n")
    out = parse_gcov(tmp_path)
    assert out == {"foo.c": {1}}


# --- lcov -------------------------------------------------------------------

def test_lcov_da_records(tmp_path):
    info = tmp_path / "cov.info"
    info.write_text(_LCOV)
    out = parse_lcov(info)
    assert out == {"src/bar.c": {1, 5}, "src/baz.c": {10}}   # DA count 0 dropped


# --- dispatch ---------------------------------------------------------------

def test_detect_format(tmp_path):
    (tmp_path / "coverage.json").write_text("{}")
    assert detect_format(tmp_path / "coverage.json") == "coverage.py"
    assert detect_format(tmp_path / "foo.c.gcov") == "gcov"
    assert detect_format(tmp_path / "x.info") == "lcov"
    assert detect_format(tmp_path) == "coverage.py"          # dir w/ coverage.json
    assert detect_format(tmp_path / "nope.txt") is None


def test_detect_format_dir_gcov(tmp_path):
    (tmp_path / "a.c.gcov").write_text("        1:    1:x\n")
    assert detect_format(tmp_path) == "gcov"


def test_parse_dispatch_and_default_tool():
    assert default_tool("gcov") == "gcov"
    assert default_tool("coverage.py") == "coverage.py"
    assert default_tool("lcov") == "lcov"
    assert default_tool(None) is None
    assert set(available_formats()) == {"coverage.py", "gcov", "lcov"}


def test_parse_unknown_format_empty(tmp_path):
    assert parse(tmp_path / "nope.txt") == {}
