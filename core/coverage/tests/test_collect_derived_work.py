"""Derived-work budgets for the runtime-coverage collectors.

Byte budgets bound the artifact FILE; these tests pin the caps on the
WORK derived from it — sandboxed spawn counts driven by
attacker-writable address sets (drcov/sancov → addr2line) and
build-tree file counts (.gcda → gcov). No real tool runs: the
sandboxed runner is stubbed to count invocations.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from core.coverage import collect
from core.coverage.collect import (
    _MAX_ADDR2LINE_ADDRS,
    _MAX_GCDA_FILES,
    collect_addr2line,
    collect_drcov,
    collect_gcov,
)


@pytest.fixture
def spawn_counter(monkeypatch):
    calls: list[list[str]] = []

    def _stub(argv: list[str], **_kw: Any):
        calls.append(argv)

        class _R:
            returncode = 0
            stdout = b""

        return _R()

    monkeypatch.setattr(collect, "_sandboxed_run", _stub)
    return calls


class TestAddr2lineBudget:
    def test_over_budget_address_set_refused(self, tmp_path,
                                             spawn_counter):
        binary = tmp_path / "bin"
        binary.write_bytes(b"\x7fELF")
        addrs = range(0x1000, 0x1000 + _MAX_ADDR2LINE_ADDRS + 1)
        assert collect_addr2line(binary, addrs) == {}
        assert spawn_counter == [], (
            f"{len(spawn_counter)} sandboxed spawns for an "
            "over-budget address set"
        )

    def test_in_budget_addresses_still_resolve(self, tmp_path,
                                               spawn_counter):
        binary = tmp_path / "bin"
        binary.write_bytes(b"\x7fELF")
        collect_addr2line(binary, [0x1000, 0x2000])
        assert len(spawn_counter) == 1
        assert spawn_counter[0][0] == "addr2line"

    def test_drcov_lane_inherits_the_budget(self, tmp_path,
                                            spawn_counter, monkeypatch):
        # The drcov path doubles every offset (PIE + non-PIE) before
        # resolving — the chokepoint budget must bound the DOUBLED
        # set with zero spawns on refusal.
        binary = tmp_path / "bin"
        binary.write_bytes(b"\x7fELF")
        offsets = set(range(_MAX_ADDR2LINE_ADDRS // 2 + 1))
        monkeypatch.setattr(
            collect, "parse_drcov",
            lambda _p: {str(binary): {"base": 0x400000,
                                      "offsets": offsets}})
        assert collect_drcov(tmp_path / "cov.drcov", binary) == {}
        assert spawn_counter == []


class TestGcdaCountCap:
    def test_gcda_glob_is_capped(self, tmp_path, spawn_counter,
                                 monkeypatch):
        monkeypatch.setattr(collect, "_MAX_GCDA_FILES", 5)
        build = tmp_path / "build"
        build.mkdir()
        for i in range(9):
            (build / f"obj{i:02d}.gcda").write_bytes(b"")
        collect_gcov(build)
        assert len(spawn_counter) == 5, (
            f"{len(spawn_counter)} gcov spawns for 9 planted .gcda "
            "under a cap of 5"
        )

    def test_under_cap_processes_every_gcda(self, tmp_path,
                                            spawn_counter):
        build = tmp_path / "build"
        build.mkdir()
        for i in range(3):
            (build / f"obj{i}.gcda").write_bytes(b"")
        collect_gcov(build)
        assert len(spawn_counter) == 3
        assert _MAX_GCDA_FILES >= 1000  # legitimate builds fit

    def test_cap_prefix_is_deterministic(self, tmp_path, spawn_counter,
                                         monkeypatch):
        monkeypatch.setattr(collect, "_MAX_GCDA_FILES", 2)
        build = tmp_path / "build"
        build.mkdir()
        for name in ("c.gcda", "a.gcda", "b.gcda"):
            (build / name).write_bytes(b"")
        collect_gcov(build)
        picked = sorted(os.path.basename(argv[-1])
                        for argv in spawn_counter)
        assert picked == ["a.gcda", "b.gcda"]
