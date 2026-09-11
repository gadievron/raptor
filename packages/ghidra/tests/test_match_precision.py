"""Tests for packages.ghidra.match_precision — real-build harness."""

from __future__ import annotations

import shutil

import pytest

from packages.ghidra.match_precision import Report, main


def _toolchain_ready() -> bool:
    if not ((shutil.which("cc") or shutil.which("gcc"))
            and shutil.which("strip")):
        return False
    try:
        from packages.ghidra.r2_import import r2_available
        return r2_available()
    except ImportError:
        return False


class TestReportMath:
    def test_rates(self):
        r = Report(matched=4, correct=3, wrong_pairs=[{}],
                   truth_pairs=6, per_tier={}, toolchain={})
        assert r.precision == 0.75
        assert r.recall == 0.5
        d = r.to_dict()
        assert d["precision"] == 0.75 and d["recall"] == 0.5

    def test_empty_run_has_no_rates(self):
        r = Report(matched=0, correct=0, wrong_pairs=[],
                   truth_pairs=0, per_tier={}, toolchain={})
        assert r.precision is None and r.recall is None


@pytest.mark.skipif(not _toolchain_ready(),
                    reason="needs cc, strip, and radare2")
class TestLiveMeasurement:
    def test_zero_wrong_pairs_on_stripped_cross_opt_build(self,
                                                          tmp_path):
        import json

        rc = main(["--out", str(tmp_path)])
        # exit 0 = no wrong pairs; a wrong pair means the matcher
        # would transplant triage onto an unrelated function
        assert rc == 0
        report = json.loads((tmp_path / "report.json").read_text())
        # a degenerate empty match must not read as a pass
        assert report["matched"] > 0
        assert report["precision"] == 1.0
        assert report["wrong_pairs"] == []
