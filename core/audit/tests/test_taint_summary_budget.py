"""Bounded taint-summary walk (core.audit.codeql_backend).

build_taint_summary walks the target-controlled source tree; the
admission gate must refuse symlinked files (lstat, never follows),
enforce the per-file byte cap before any read, and stop at the
aggregate budget.
"""

from __future__ import annotations

from pathlib import Path

import core.audit.codeql_backend as backend
from core.audit.codeql_backend import _admit_taint_file, build_taint_summary

TAINTED = "import os\n\ndef f(x):\n    os.system(x)\n"


def _fresh_budget(remaining: int = 1 << 20) -> dict:
    return {"remaining": remaining, "warned": False}


class TestAdmitTaintFile:
    def test_regular_file_admitted_and_budget_decremented(self, tmp_path):
        p = tmp_path / "a.py"
        p.write_text(TAINTED)
        budget = _fresh_budget()
        assert _admit_taint_file(p, budget)
        assert budget["remaining"] == (1 << 20) - p.stat().st_size

    def test_symlink_refused(self, tmp_path):
        real = tmp_path / "real.py"
        real.write_text(TAINTED)
        link = tmp_path / "link.py"
        link.symlink_to(real)
        assert not _admit_taint_file(link, _fresh_budget())

    def test_directory_refused(self, tmp_path):
        d = tmp_path / "pkg.py"
        d.mkdir()
        assert not _admit_taint_file(d, _fresh_budget())

    def test_missing_refused(self, tmp_path):
        assert not _admit_taint_file(tmp_path / "absent.py", _fresh_budget())

    def test_over_per_file_cap_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(backend, "_TAINT_PER_FILE_CAP", 8)
        p = tmp_path / "big.py"
        p.write_text(TAINTED)
        assert not _admit_taint_file(p, _fresh_budget())

    def test_over_aggregate_budget_refused_and_warned_once(self, tmp_path):
        p = tmp_path / "a.py"
        p.write_text(TAINTED)
        budget = _fresh_budget(remaining=4)
        assert not _admit_taint_file(p, budget)
        assert budget["warned"]
        assert budget["remaining"] == 4


class TestBuildTaintSummaryBounds:
    def test_symlinked_py_not_analysed(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "evil.py").write_text(TAINTED)
        target = tmp_path / "target"
        target.mkdir()
        (target / "m.py").symlink_to(outside / "evil.py")
        result = build_taint_summary(target)
        assert not result or not any("m.py" in k for k in result)

    def test_oversize_py_skipped_small_still_analysed(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "small.py").write_text(TAINTED)
        pad = "# " + "x" * (backend._TAINT_PER_FILE_CAP + 1) + "\n"
        (target / "big.py").write_text(TAINTED + pad)
        result = build_taint_summary(target)
        assert result and "small.py:f" in result
        assert not any("big.py" in k for k in result)

    def test_aggregate_budget_admits_nothing_when_exhausted(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr(backend, "_TAINT_AGGREGATE_CAP", 4)
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text(TAINTED)
        (target / "b.py").write_text(TAINTED)
        assert build_taint_summary(target) is None

    def test_regular_small_file_still_analysed(self, tmp_path):
        (tmp_path / "m.py").write_text(TAINTED)
        result = build_taint_summary(tmp_path)
        assert result and "m.py:f" in result

    def test_scope_filter_precedes_budget(self, tmp_path, monkeypatch):
        # A file outside the requested scope must not consume budget.
        target = tmp_path / "target"
        (target / "in").mkdir(parents=True)
        (target / "out").mkdir()
        (target / "in" / "a.py").write_text(TAINTED)
        big = Path(target / "out" / "big.py")
        big.write_text(TAINTED * 100)
        monkeypatch.setattr(
            backend, "_TAINT_AGGREGATE_CAP", len(TAINTED) + 8,
        )
        result = build_taint_summary(target, scope=["in"])
        assert result and "in/a.py:f" in result
