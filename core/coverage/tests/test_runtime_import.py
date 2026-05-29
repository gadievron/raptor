"""import_runtime: external gcov/lcov/coverage.py coverage → store (Phase 4)."""

from __future__ import annotations

import json

from core.coverage.importer import import_runtime
from core.coverage.store import CoverageStore
from core.coverage.store_summary import store_view


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:x")


_C_CHECKLIST = {"files": [
    {"path": "src/foo.c", "lines": 10, "items": [
        {"name": "main", "kind": "function", "line_start": 1, "line_end": 6}]},
]}


def test_gcov_marks_runtime_coverage(tmp_path):
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    gdir = tmp_path / "gcov"
    gdir.mkdir()
    (gdir / "foo.c.gcov").write_text(
        "        -:    0:Source:src/foo.c\n"
        "        5:    1:int main(void){\n"
        "        5:    2:  return 0;\n"
        "    #####:    3:  dead();\n")
    n = import_runtime(s, gdir, _C_CHECKLIST)
    assert n >= 1
    assert s.who_checked("src/foo.c", 1) == ["gcov"]
    assert s.who_checked("src/foo.c", 3) == []                 # never-executed
    # Runtime category lights up; the function reads as runtime-covered.
    assert s.function_covered("src/foo.c", 1, 6, category="runtime") is True
    view = store_view(s, _C_CHECKLIST)
    assert view["functions_by_category"]["runtime"] == 1


def test_gcov_abs_path_normalised_to_inventory(tmp_path):
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    g = tmp_path / "foo.c.gcov"
    g.write_text(
        "        -:    0:Source:/abs/build/src/foo.c\n"   # absolute build path
        "        9:    1:int main(void){\n")
    import_runtime(s, g, _C_CHECKLIST)
    assert s.who_checked("src/foo.c", 1) == ["gcov"]           # matched to inventory


def test_coverage_py_marks_runtime(tmp_path):
    checklist = {"files": [{"path": "pkg/mod.py", "lines": 8, "items": [
        {"name": "f", "kind": "function", "line_start": 1, "line_end": 4}]}]}
    s = _store(tmp_path)
    s.import_inventory_meta(checklist)
    cov = tmp_path / "coverage.json"
    cov.write_text(json.dumps({"files": {
        "pkg/mod.py": {"executed_lines": [1, 2, 3]}}}))
    n = import_runtime(s, cov, checklist)
    assert n >= 1
    assert s.who_checked("pkg/mod.py", 2) == ["coverage.py"]
    assert s.function_covered("pkg/mod.py", 1, 4, category="runtime") is True


def test_lcov_info_marks_runtime(tmp_path):
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    info = tmp_path / "cov.info"
    info.write_text("SF:src/foo.c\nDA:1,4\nDA:2,0\nend_of_record\n")
    import_runtime(s, info, _C_CHECKLIST)
    assert s.who_checked("src/foo.c", 1) == ["lcov"]
    assert s.who_checked("src/foo.c", 2) == []                 # DA count 0


def test_runtime_marks_coalesce_into_runs(tmp_path):
    # Contiguous executed lines mark as one interval, not one per line.
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    info = tmp_path / "cov.info"
    info.write_text("SF:src/foo.c\n" + "".join(
        f"DA:{i},1\n" for i in range(1, 7)) + "end_of_record\n")
    n = import_runtime(s, info, _C_CHECKLIST)
    assert n == 1                                              # 1..6 -> one run
    assert s.covered_lines("src/foo.c") == [[1, 6]]


def test_import_runtime_unknown_format_noop(tmp_path):
    s = _store(tmp_path)
    assert import_runtime(s, tmp_path / "nope.txt", _C_CHECKLIST) == 0


def test_import_runtime_skips_non_inventory_files(tmp_path):
    # Source paths that don't resolve to an inventory file are skipped — the
    # store stays inventory-anchored (no system-header / non-target pollution).
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)              # only src/foo.c
    g = tmp_path / "sys.h.gcov"
    g.write_text("        -:    0:Source:/usr/include/sys.h\n"
                 "        3:    1:x\n")
    assert import_runtime(s, g, _C_CHECKLIST) == 0
    assert "/usr/include/sys.h" not in s.files()      # non-inventory file not added
    assert s.who_checked("src/foo.c", 1) == []        # nothing mis-attributed
