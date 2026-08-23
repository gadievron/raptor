"""The caller-declared CPG exclusion channel must be WIRED, not dormant.

An in-target run output dir (self-analysis with ``out/`` under the
analysed repo) changes at every segment: left in the CPG content key it
flaps the key and re-buys a full CPG rebuild per resume. The audit
callers know the run dir — these tests pin that knowledge flowing into
``build_cpg_cached(exclude_dirs=...)`` through every production path.
"""

from pathlib import Path
from types import SimpleNamespace

import core.audit.joern_backend as jb


class TestRunExcludeDirs:
    def test_in_target_out_dir_is_declared(self, tmp_path):
        out_dir = tmp_path / "out" / "audit_1"
        out_dir.mkdir(parents=True)
        assert jb.run_exclude_dirs(out_dir, tmp_path) == (
            str(out_dir.resolve()),
        )

    def test_external_out_dir_is_not_declared(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        assert jb.run_exclude_dirs(out_dir, target) == ()


class TestPreSweepExclusionWiring:
    def _fake_cpg_build(self, captured):
        def fake_build_cached(target, cache_dir, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(exists=lambda: False)
        return fake_build_cached

    def test_pre_sweep_forwards_exclusions_to_cpg_build(
        self, tmp_path, monkeypatch,
    ):
        import packages.joern.prereqs as prereqs
        import packages.joern.runner as runner

        from core.audit.sweep import run_joern_pre_sweep

        (tmp_path / "a.c").write_text(
            "int main(void) { return 0; }\n", encoding="utf-8",
        )
        monkeypatch.setattr(prereqs, "is_available", lambda: True)
        captured: dict = {}
        monkeypatch.setattr(
            runner, "build_cpg_cached", self._fake_cpg_build(captured),
        )

        flows = run_joern_pre_sweep(
            tmp_path, {},
            cache_dir=tmp_path / "cache",
            exclude_dirs=("/declared/run-dir",),
        )
        assert flows == {}
        assert captured.get("exclude_dirs") == ("/declared/run-dir",)

    def test_build_joern_evidence_declares_in_target_out_dir(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.sweep as sweep_mod

        target = tmp_path / "repo"
        target.mkdir()
        (target / "a.c").write_text(
            "int main(void) { return 0; }\n", encoding="utf-8",
        )
        out_dir = target / "out" / "audit_1"
        out_dir.mkdir(parents=True)

        captured: dict = {}

        def fake_pre_sweep(target_path, checklist, **kwargs):
            captured.update(kwargs)
            return {}

        monkeypatch.setattr(sweep_mod, "run_joern_pre_sweep", fake_pre_sweep)
        monkeypatch.setattr(
            jb, "joern_tunables",
            lambda overrides=None: SimpleNamespace(
                cpg_timeout_s=1, query_timeout_s=1, heap_mb=None,
            ),
        )

        jb.build_joern_evidence(target, out_dir)
        assert captured.get("exclude_dirs") == (str(out_dir.resolve()),)


class TestServerCpgExclusionWiring:
    def test_ensure_cpg_loaded_forwards_exclusions(
        self, tmp_path, monkeypatch,
    ):
        import packages.joern.runner as runner

        captured: dict = {}

        def fake_build_cached(target, cache_dir, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                exists=lambda: True, path=Path(tmp_path) / "cpg.bin",
            )

        monkeypatch.setattr(runner, "build_cpg_cached", fake_build_cached)
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=0: None,
        )
        assert jb._ensure_cpg_loaded(
            srv, tmp_path, None, exclude_dirs=("/declared/run-dir",),
        ) is True
        assert captured.get("exclude_dirs") == ("/declared/run-dir",)
