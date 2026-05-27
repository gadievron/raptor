"""Coverage-aware /project clean wiring (_classify_clean_coverage /
_apply_clean_coverage in core.project.cli)."""

from __future__ import annotations

import json

from core.coverage.store import CoverageStore
from core.project.cli import _apply_clean_coverage, _classify_clean_coverage


class _FakeProject:
    def __init__(self, output_dir, run_dirs, by_type=None):
        self.output_dir = str(output_dir)
        self._run_dirs = run_dirs
        self._by_type = by_type or {}

    def get_run_dirs(self, sweep=False):
        return list(self._run_dirs)

    def get_run_dirs_by_type(self):
        return {k: list(v) for k, v in self._by_type.items()}


def _proj(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "checklist.json").write_text(json.dumps({"files": [
        {"path": "a.c", "total_lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60},
        ]}]}))
    return proj


def _run(proj, name, files, findings=None):
    d = proj / name
    d.mkdir()
    (d / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": files, "timestamp": "t"}))
    if findings is not None:
        (d / "findings.json").write_text(json.dumps(findings))
    return d


def test_clean_snapshots_coverage_and_flips_sole_source_finding(tmp_path):
    proj = _proj(tmp_path)
    victim = _run(proj, "scan-old", ["a.c"],
                  findings=[{"id": "F1", "file": "a.c", "line": 42}])  # in f2
    fp = _FakeProject(proj, [victim])
    plan = {"delete_dirs": [victim]}

    cons = _classify_clean_coverage(fp, plan)
    assert len(cons) == 1 and cons[0].lossy is True       # F1 is sole-source

    _apply_clean_coverage(fp, plan, cons)                 # snapshot + flip + save

    store = CoverageStore(proj / "coverage.json")          # persisted at project level
    assert store.function_verdict("a.c", 0, 20) == "clean"            # examined, no finding
    assert store.function_verdict("a.c", 30, 60) == "found_then_lost"  # finding detail going away


def test_clean_duplicate_run_loses_nothing(tmp_path):
    proj = _proj(tmp_path)
    victim = _run(proj, "scan-old", ["a.c"], findings=[])
    survivor = _run(proj, "scan-new", ["a.c"], findings=[])
    fp = _FakeProject(proj, [victim, survivor])
    plan = {"delete_dirs": [victim]}

    cons = _classify_clean_coverage(fp, plan)
    assert cons[0].duplicate is True and cons[0].lossy is False


def test_plan_dedup_selects_only_subsumed_runs(tmp_path):
    from core.project.clean import plan_dedup

    proj = _proj(tmp_path)
    old = _run(proj, "scan-01", ["a.c"], findings=[])
    new = _run(proj, "scan-02", ["a.c"], findings=[])     # subsumes old (same a.c)
    uniq = _run(proj, "scan-03", ["b.c"], findings=[])    # disjoint -> unique
    fp = _FakeProject(proj, [old, new, uniq],
                      by_type={"scan": [old, new, uniq]})
    plan = plan_dedup(fp)
    # scan-01 subsumed by scan-02; scan-02/03 each carry coverage not elsewhere.
    assert plan["deleted"] == ["scan-01"]
    assert set(plan["kept"]) == {"scan-02", "scan-03"}
    assert plan["by_type"]["scan"]["delete"] == 1


def test_no_checklist_is_a_safe_noop(tmp_path):
    proj = tmp_path / "bare"
    proj.mkdir()
    fp = _FakeProject(proj, [])
    assert _classify_clean_coverage(fp, {"delete_dirs": []}) == []
    _apply_clean_coverage(fp, {"delete_dirs": []}, [])     # no crash, no file
    assert not (proj / "coverage.json").exists()
