"""Tests for packages/cve_env/scripts/raptor-cvefix-envs (S5.2 driver).

Entry-level env verification only: sidecars record that the corpus
BOUNDARY builds/deploys/serves; span-level manifest ``review`` fields
are a different axis and are never touched. Runs are hermetic here —
the cve-env subprocess is faked at the ``runner`` seam.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPT = (REPO_ROOT / "packages" / "cve_env" / "scripts"
          / "raptor-cvefix-envs")

CVE = "CVE-2018-7600"
FIX = "a" * 40


def _load():
    loader = SourceFileLoader("raptor_cvefix_envs", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod():
    return _load()


def _spec_dict(tmp_path: Path, cve: str = CVE, fix: str = FIX) -> dict:
    return {
        "cve_id": cve, "repo_url": "https://github.com/drupal/drupal",
        "fix_commit": fix, "local_clone": str(tmp_path / "clone"),
        "language": "php", "cwe": "CWE-94",
    }


def _write_spec(tmp_path: Path, name: str = "spec.json", **over) -> Path:
    d = _spec_dict(tmp_path)
    d.update(over)
    p = tmp_path / name
    p.write_text(json.dumps(d))
    return p


def _git_clone_with_fix(tmp_path: Path) -> tuple[Path, str, str]:
    """A real two-commit repo; returns (clone, fix_sha, parent_sha)."""
    clone = tmp_path / "clone"
    clone.mkdir()

    def g(*a):
        return subprocess.run(
            ["git", "-C", str(clone), *a], capture_output=True,
            text=True, check=True,
            env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                 "PATH": "/usr/bin:/bin"},
        ).stdout.strip()

    g("init", "-q")
    (clone / "f").write_text("vulnerable")
    g("add", "f"), g("commit", "-qm", "vulnerable")
    parent = g("rev-parse", "HEAD")
    (clone / "f").write_text("fixed")
    g("add", "f"), g("commit", "-qm", "fix")
    fix = g("rev-parse", "HEAD")
    return clone, fix, parent


class TestSpecsAndStaging:
    def test_load_specs_validates_provenance_gate(self, mod, tmp_path):
        _write_spec(tmp_path, fix_commit="deadbeef")  # not 40-hex
        with pytest.raises(Exception, match="provenance"):
            mod.load_specs(tmp_path / "spec.json")

    def test_load_specs_dir(self, mod, tmp_path):
        _write_spec(tmp_path, "a.json")
        _write_spec(tmp_path, "b.json", cve_id="CVE-2019-11043")
        specs = mod.load_specs(tmp_path)
        assert [e["spec"].cve_id for e in specs] == [
            CVE, "CVE-2019-11043"]

    def test_resolve_parent_from_local_clone(self, mod, tmp_path):
        clone, fix, parent = _git_clone_with_fix(tmp_path)
        from core.recall.cvefix_manifest import CvefixSpec
        spec = CvefixSpec.from_dict(
            dict(_spec_dict(tmp_path), fix_commit=fix,
                 local_clone=str(clone)))
        assert mod.resolve_parent(spec) == parent

    def test_staged_artifact_reads_back_through_bridge(
            self, mod, tmp_path):
        from core.orchestration.cvediff_bridge import find_fix_pointer
        from core.recall.cvefix_manifest import CvefixSpec
        spec = CvefixSpec.from_dict(_spec_dict(tmp_path))
        entry = tmp_path / "entry"
        entry.mkdir()
        mod.stage_entry(spec, "b" * 40, entry)
        ptr = find_fix_pointer(CVE, out_dir=entry)
        assert ptr is not None
        assert ptr.fix_commit == FIX
        assert ptr.commit_before == "b" * 40


_REAL_RUN = subprocess.run  # captured before any monkeypatching


def _fake_runner_factory(outcome: dict):
    """A ``runner`` that plants the outcome sidecar like the real
    build would (and an environment-spec.json on success). Non-build
    commands (the driver's internal ``git rev-parse``) pass through to
    the real subprocess.run so staging keeps working under a
    module-level monkeypatch."""
    def runner(cmd, **kw):
        if "cve_env" not in cmd:
            return _REAL_RUN(cmd, **kw)
        entry = Path(cmd[cmd.index("--audit-root") + 1])
        cve = cmd[cmd.index("build") + 1]
        (entry / f"{cve}.outcome.json").write_text(json.dumps(outcome))
        if outcome.get("status") == "success":
            (entry / "environment-spec.json").write_text("{}")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return runner


_SUCCESS = {"status": "success", "verify_passed": True,
            "method": "vulhub-image", "total_cost_usd": 1.03,
            "stop_reason": "end_turn"}
_MISS = {"status": "unresolvable", "verify_passed": False,
         "method": "researching", "total_cost_usd": 0.55,
         "give_up_reason": "arch_incompatible", "stop_reason": "give_up"}


class TestRunEntryAndSidecar:
    def _spec(self, mod, tmp_path):
        clone, fix, parent = _git_clone_with_fix(tmp_path)
        from core.recall.cvefix_manifest import CvefixSpec
        return CvefixSpec.from_dict(
            dict(_spec_dict(tmp_path), fix_commit=fix,
                 local_clone=str(clone))), parent

    def _args(self, mod, tmp_path, **over):
        base = ["--specs", str(tmp_path), "--out", str(tmp_path / "out")]
        for k, v in over.items():
            base += [k, str(v)]
        return mod.parse_args(base)

    def test_success_row_and_env_verified_sidecar(self, mod, tmp_path):
        spec, parent = self._spec(mod, tmp_path)
        args = self._args(mod, tmp_path)
        entry = tmp_path / "out" / spec.cve_id
        row = mod.run_entry(spec, entry, args,
                            runner=_fake_runner_factory(_SUCCESS))
        assert row["status"] == "success"
        assert row["verify_passed"] is True
        assert row["boundary_commit"] == parent
        assert row["replayable"] is True
        assert row["profile"] == "deployed-infrastructure"
        overlay = tmp_path / "overlay"
        mod.write_sidecar(row, entry, overlay)
        sidecar = json.loads((entry / mod.SIDECAR).read_text())
        assert sidecar["verification"] == "env-verified"
        assert sidecar["boundary_commit"] == parent
        assert (overlay / f"{spec.cve_id}.{mod.SIDECAR}").is_file()

    def test_typed_miss_records_no_verification(self, mod, tmp_path):
        spec, _parent = self._spec(mod, tmp_path)
        args = self._args(mod, tmp_path)
        entry = tmp_path / "out" / spec.cve_id
        row = mod.run_entry(spec, entry, args,
                            runner=_fake_runner_factory(_MISS))
        mod.write_sidecar(row, entry, None)
        sidecar = json.loads((entry / mod.SIDECAR).read_text())
        assert "verification" not in sidecar
        assert sidecar["give_up_reason"] == "arch_incompatible"

    def test_stage_failure_is_a_row_not_a_crash(self, mod, tmp_path):
        from core.recall.cvefix_manifest import CvefixSpec
        spec = CvefixSpec.from_dict(dict(
            _spec_dict(tmp_path),
            repo_url="https://example.invalid/repo",  # no clone, no GH
        ))
        args = self._args(mod, tmp_path)
        row = mod.run_entry(spec, tmp_path / "out" / CVE, args)
        assert row["status"] == "stage_failed"
        assert row["cost_usd"] == 0.0


class TestMainLoop:
    def _setup(self, mod, tmp_path, n=3, budget=50.0):
        specs_dir = tmp_path / "specs"
        specs_dir.mkdir()
        clone, fix, _ = _git_clone_with_fix(tmp_path)
        for i in range(n):
            cve = f"CVE-2020-{10000 + i}"
            (specs_dir / f"{cve}.json").write_text(json.dumps(dict(
                _spec_dict(tmp_path), cve_id=cve, fix_commit=fix,
                local_clone=str(clone))))
        return specs_dir

    def test_budget_ceiling_stops_before_next_entry(
            self, mod, tmp_path, monkeypatch, capsys):
        specs_dir = self._setup(mod, tmp_path, n=3)
        monkeypatch.setattr(
            mod.subprocess, "run",
            _fake_runner_factory(dict(_SUCCESS, total_cost_usd=1.0)))
        rc = mod.main(["--specs", str(specs_dir),
                       "--out", str(tmp_path / "out"),
                       "--budget-usd", "1.5"])
        assert rc == 3  # ceiling hit
        rows = (tmp_path / "out" / mod.LEDGER).read_text().splitlines()
        assert len(rows) == 2  # third entry never launched
        assert "BUDGET CEILING" in capsys.readouterr().err

    def test_resume_skips_recorded_entries(self, mod, tmp_path,
                                           monkeypatch):
        specs_dir = self._setup(mod, tmp_path, n=2)
        calls = []

        def counting_runner(cmd, **kw):
            calls.append(cmd)
            return _fake_runner_factory(_SUCCESS)(cmd, **kw)

        monkeypatch.setattr(mod.subprocess, "run", counting_runner)
        out = tmp_path / "out"

        def builds():
            return [c for c in calls if "cve_env" in c]

        assert mod.main(["--specs", str(specs_dir),
                         "--out", str(out)]) == 0
        assert len(builds()) == 2
        # second invocation: everything already in the ledger
        assert mod.main(["--specs", str(specs_dir),
                         "--out", str(out)]) == 0
        assert len(builds()) == 2, "resume must not re-run recorded entries"

    def test_report_written_with_counts(self, mod, tmp_path,
                                        monkeypatch):
        specs_dir = self._setup(mod, tmp_path, n=1)
        monkeypatch.setattr(mod.subprocess, "run",
                            _fake_runner_factory(_SUCCESS))
        out = tmp_path / "out"
        mod.main(["--specs", str(specs_dir), "--out", str(out)])
        report = (out / "report.md").read_text()
        assert "env-verified: 1 (1 replayable)" in report

    def test_dry_run_runs_nothing(self, mod, tmp_path, monkeypatch):
        specs_dir = self._setup(mod, tmp_path, n=1)

        def boom(cmd, **kw):  # pragma: no cover — must not be reached
            raise AssertionError("dry-run must not spawn builds")

        monkeypatch.setattr(mod.subprocess, "run", boom)
        assert mod.main(["--specs", str(specs_dir),
                         "--out", str(tmp_path / "out"),
                         "--dry-run"]) == 0
