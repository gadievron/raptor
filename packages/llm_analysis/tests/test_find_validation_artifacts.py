"""find_validation_artifacts run-directory discovery.

The agent's artifact discovery must see every layout /validate can
produce: the legacy ``exploitability-validation-*`` orchestrator dirs
AND both modern run-lifecycle layouts (``validate_<target>_<ts>``
standalone under out/, ``validate-<ts>`` under a project's output
dir). Recency is decided by mtime — directory-name sort only orders
correctly within one naming family.

Every search base is redirected under tmp_path so the tests never see
real runs on the host (out/, .out/, ~/.out/, project registry).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import packages.llm_analysis.agent as agent_mod  # noqa: E402
from packages.llm_analysis.agent import find_validation_artifacts  # noqa: E402


def _stub_projects(monkeypatch: pytest.MonkeyPatch, projects: list) -> None:
    import core.project.project as project_mod

    class _Manager:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def list_projects(self) -> list:
            return projects

    monkeypatch.setattr(project_mod, "ProjectManager", _Manager)


@pytest.fixture
def iso(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    """Hermetic discovery environment: all bases live under tmp_path."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    home = tmp_path / "home"
    (home / ".out").mkdir(parents=True)

    monkeypatch.setattr(
        agent_mod.RaptorConfig, "get_out_dir", staticmethod(lambda: out_dir),
    )
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(tmp_path)  # relative .out resolves under tmp_path
    _stub_projects(monkeypatch, [])
    return SimpleNamespace(out=out_dir, home_out=home / ".out", tmp=tmp_path)


def _run(base: Path, name: str, mtime: float) -> Path:
    """Create a run dir with a findings.json pinned to *mtime*."""
    run_dir = base / name
    run_dir.mkdir(parents=True)
    findings = run_dir / "findings.json"
    findings.write_text("[]", encoding="utf-8")
    os.utime(findings, (mtime, mtime))
    return findings


class TestLayoutDiscovery:

    def test_legacy_layout_in_dot_out_still_found(self, iso):
        # Pre-fix behaviour preserved: legacy dirs under relative .out/
        dot_out = iso.tmp / ".out"
        f = _run(dot_out, "exploitability-validation-20260101-120000", 1e6)
        assert find_validation_artifacts() == f

    def test_modern_standalone_layout_found(self, iso):
        f = _run(iso.out, "validate_myapp_20260830_120000_pid1", 1e6)
        assert find_validation_artifacts() == f

    def test_modern_project_layout_found(self, iso, monkeypatch):
        proj_dir = iso.tmp / "projects" / "myapp"
        proj_dir.mkdir(parents=True)
        _stub_projects(
            monkeypatch, [SimpleNamespace(output_dir=str(proj_dir))],
        )
        f = _run(proj_dir, "validate-20260830-120000-pid1", 1e6)
        assert find_validation_artifacts() == f

    def test_unrelated_dirs_ignored(self, iso):
        _run(iso.out, "scan_myapp_20260830_120000_pid1", 1e6)
        _run(iso.out, "validated-notes", 1e6)
        assert find_validation_artifacts() is None

    def test_run_dir_without_findings_ignored(self, iso):
        (iso.out / "validate-20260830-120000-pid1").mkdir()
        assert find_validation_artifacts() is None


class TestRecency:

    def test_newest_across_families_wins_both_directions(self, iso):
        legacy = _run(
            iso.out, "exploitability-validation-20260101-120000", 1_000_000,
        )
        modern = _run(iso.out, "validate-20260830-120000-pid1", 2_000_000)
        assert find_validation_artifacts() == modern
        # Other direction: ordering is age, not naming family.
        os.utime(legacy, (3_000_000, 3_000_000))
        assert find_validation_artifacts() == legacy

    def test_workdir_validation_beats_older_runs(self, iso):
        _run(iso.out, "validate_myapp_20260830_120000_pid1", 1_000_000)
        workdir = iso.tmp / "work"
        agentic = _run(workdir, "validation", 2_000_000)
        assert find_validation_artifacts(workdir) == agentic


class TestDegradation:

    def test_registry_failure_degrades_gracefully(self, iso, monkeypatch):
        import core.project.project as project_mod

        class _Broken:
            def __init__(self, *args, **kwargs) -> None:
                raise OSError("registry unavailable")

        monkeypatch.setattr(project_mod, "ProjectManager", _Broken)
        f = _run(iso.out, "validate_myapp_20260830_120000_pid1", 1e6)
        assert find_validation_artifacts() == f

    def test_no_runs_anywhere_returns_none(self, iso):
        assert find_validation_artifacts() is None
