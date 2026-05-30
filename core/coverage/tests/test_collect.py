"""Tests for the runtime-coverage collection layer (collect.py)."""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from core.coverage import collect as collect_mod
from core.coverage.collect import collect_gcov, import_gcov_build, import_llvm
from core.coverage.store import CoverageStore
from core.coverage.store_summary import store_view

_HAVE_GCOV = shutil.which("gcc") is not None and shutil.which("gcov") is not None
_HAVE_A2L = all(shutil.which(t) for t in ("gcc", "addr2line", "nm"))

_C_CHECKLIST = {"files": [
    {"path": "prog.c", "lines": 12, "items": [
        {"name": "main", "kind": "function", "line_start": 1, "line_end": 12}]},
]}


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:x")


# --- unit / wiring (no toolchain) ------------------------------------------

def test_collect_gcov_empty_dir(tmp_path):
    assert collect_gcov(tmp_path) == {}          # no .gcda → {}


def test_import_gcov_build_marks_store(tmp_path, monkeypatch):
    # Wiring: collector output → mark_runtime → store (no real gcov needed).
    monkeypatch.setattr(collect_mod, "collect_gcov",
                        lambda *a, **k: {"prog.c": {1, 2, 5}})
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    n = import_gcov_build(s, tmp_path, _C_CHECKLIST)
    assert n >= 1
    assert s.who_checked("prog.c", 1) == ["gcov"]
    assert s.who_checked("prog.c", 3) == []
    assert store_view(s, _C_CHECKLIST)["functions_by_category"]["runtime"] == 1


def test_import_gcov_build_inventory_anchored(tmp_path, monkeypatch):
    # A source path not in the inventory is skipped (no pollution).
    monkeypatch.setattr(collect_mod, "collect_gcov",
                        lambda *a, **k: {"/usr/include/x.h": {1}})
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    assert import_gcov_build(s, tmp_path, _C_CHECKLIST) == 0
    assert "/usr/include/x.h" not in s.files()


def test_collect_llvm_missing_or_failing_is_graceful(tmp_path):
    # Non-existent binary/profdata → tool fails → {} (never raises).
    assert collect_mod.collect_llvm(tmp_path / "nope.bin", tmp_path / "nope.profdata") == {}


def test_import_llvm_wiring(tmp_path, monkeypatch):
    monkeypatch.setattr(collect_mod, "collect_llvm",
                        lambda *a, **k: {"prog.c": {1, 2, 3, 4}})
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    n = import_llvm(s, "bin", "prof", _C_CHECKLIST)
    assert n >= 1
    assert s.who_checked("prog.c", 2) == ["llvm-cov"]


# --- live (gcc/gcov) -------------------------------------------------------

def test_import_addresses_wiring(tmp_path, monkeypatch):
    monkeypatch.setattr(collect_mod, "collect_addr2line",
                        lambda *a, **k: {"prog.c": {2, 3}})
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    from core.coverage.collect import import_addresses
    n = import_addresses(s, "prog", [0x1149], _C_CHECKLIST)
    assert n >= 1
    assert s.who_checked("prog.c", 2) == ["bincov"]
    assert store_view(s, _C_CHECKLIST)["functions_by_category"]["runtime"] == 1


def test_collect_addr2line_empty(tmp_path):
    assert collect_mod.collect_addr2line(tmp_path / "x", []) == {}


def test_collect_addr2line_filters_no_line_info(monkeypatch):
    # ?? / :0 / :? are "no line info" — only positive line numbers are kept.
    class _R:
        returncode = 0
        stdout = ("??:0\n/x/a.c:0\n/x/a.c:5\n"
                  "/x/a.c:7 (discriminator 1)\n/x/b.c:?\n")
    monkeypatch.setattr(collect_mod.subprocess, "run", lambda *a, **k: _R())
    out = collect_mod.collect_addr2line("bin", [1, 2, 3, 4, 5])
    assert out == {"/x/a.c": {5, 7}}


def _make_drcov(path, modpath, base, bbs):
    """Write a minimal drcov v2 file: text header + module table + packed BBs.
    bbs: list of (start_offset, size)."""
    header = (b"DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n"
              b"Module Table: 1\n"
              + f"0, {base}, 0, 0, {modpath}\n".encode()
              + f"BB Table: {len(bbs)} bbs\n".encode())
    body = b"".join(struct.pack("<IHH", s, sz, 0) for s, sz in bbs)
    Path(path).write_bytes(header + body)


def test_parse_drcov_fixture(tmp_path):
    dr = tmp_path / "cov.drcov"
    _make_drcov(dr, "/x/prog", 4096, [(16, 8), (32, 4)])
    mods = collect_mod.parse_drcov(dr)
    assert mods == {"/x/prog": {"base": 4096, "offsets": {16, 32}}}


def test_import_drcov_wiring(tmp_path, monkeypatch):
    monkeypatch.setattr(collect_mod, "collect_drcov",
                        lambda *a, **k: {"prog.c": {1, 2}})
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    from core.coverage.collect import import_drcov
    n = import_drcov(s, tmp_path / "x.drcov", "prog", _C_CHECKLIST)
    assert n >= 1
    assert s.who_checked("prog.c", 1) == ["drcov"]


def _make_sancov(path, pcs, magic=0xC0BFFFFFFFFFFF64):
    import struct as _s
    data = _s.pack("<Q", magic) + b"".join(_s.pack("<Q", p) for p in pcs)
    Path(path).write_bytes(data)


def test_parse_sancov_fixture(tmp_path):
    sc = tmp_path / "cov.sancov"
    _make_sancov(sc, [0x1149, 0x1170])
    assert collect_mod.parse_sancov(sc) == {0x1149, 0x1170}


def test_parse_sancov_bad_magic(tmp_path):
    sc = tmp_path / "bad.sancov"
    sc.write_bytes(struct.pack("<Q", 0xDEADBEEF) + struct.pack("<Q", 1))
    assert collect_mod.parse_sancov(sc) == set()


def test_import_sancov_wiring(tmp_path, monkeypatch):
    monkeypatch.setattr(collect_mod, "collect_sancov",
                        lambda *a, **k: {"prog.c": {2}})
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    from core.coverage.collect import import_sancov
    assert import_sancov(s, tmp_path / "x.sancov", "prog", _C_CHECKLIST) >= 1
    assert s.who_checked("prog.c", 2) == ["sancov"]


@pytest.fixture(scope="session")
def _a2l_prog(tmp_path_factory):
    # Compile a tiny non-PIE C program ONCE per session — the three _live
    # tests below all need the same ELF + main's PC. Cold-CI gcc dominates
    # this test class; sharing the compile cuts ~2/3 of wall.
    d = tmp_path_factory.mktemp("a2l_prog")
    (d / "prog.c").write_text("int helper(int n){ return n+1; }\n"
                              "int main(void){ return helper(2); }\n")
    subprocess.run(["gcc", "-g", "-O0", "-no-pie", "-o", "prog", "prog.c"],
                   cwd=d, check=True, capture_output=True)
    nm = subprocess.run(["nm", "prog"], cwd=d, check=True,
                        capture_output=True, text=True)
    main_addr = next(int(ln.split()[0], 16) for ln in nm.stdout.splitlines()
                     if ln.split()[-1] == "main" and ln.split()[1] in ("T", "t"))
    return d / "prog", main_addr


@pytest.mark.skipif(not _HAVE_A2L, reason="gcc/addr2line/nm not available")
def test_collect_sancov_live(_a2l_prog, tmp_path):
    prog, main_v = _a2l_prog
    sc = tmp_path / "cov.sancov"
    _make_sancov(sc, [main_v])                 # non-PIE → PC == file vaddr
    data = collect_mod.collect_sancov(sc, prog)
    assert any(p.endswith("prog.c") for p in data)
    assert 2 in next(v for p, v in data.items() if p.endswith("prog.c"))


@pytest.mark.skipif(not _HAVE_A2L, reason="gcc/addr2line/nm not available")
def test_collect_drcov_live(_a2l_prog, tmp_path):
    prog, main_v = _a2l_prog
    dr = tmp_path / "cov.drcov"
    # base 0 → the offset itself is the file vaddr (try-both also yields it).
    _make_drcov(dr, str(prog), 0, [(main_v, 8)])
    data = collect_mod.collect_drcov(dr, prog)
    assert any(p.endswith("prog.c") for p in data)
    assert 2 in next(v for p, v in data.items() if p.endswith("prog.c"))


@pytest.mark.skipif(not _HAVE_A2L, reason="gcc/addr2line/nm not available")
def test_collect_addr2line_live(_a2l_prog):
    prog, main_addr = _a2l_prog
    data = collect_mod.collect_addr2line(prog, [main_addr])
    # Resolves to prog.c at main's line (line 2).
    assert any(p.endswith("prog.c") for p in data)
    lines = next(v for p, v in data.items() if p.endswith("prog.c"))
    assert 2 in lines


@pytest.mark.skipif(not _HAVE_GCOV, reason="gcc/gcov not available")
def test_collect_gcov_live(tmp_path):
    src = tmp_path / "prog.c"
    src.write_text(
        "int dead(void){ return -1; }\n"
        "int main(void){ return 0; }\n")
    subprocess.run(["gcc", "--coverage", "-O0", "-o", "prog", "prog.c"],
                   cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["./prog"], cwd=tmp_path, check=True, capture_output=True)
    data = collect_gcov(tmp_path)
    assert "prog.c" in data
    assert 2 in data["prog.c"]          # main() executed
    assert 1 not in data["prog.c"]      # dead() never called
    # And it cleaned up the .gcov it produced.
    assert not list(tmp_path.glob("*.gcov"))
