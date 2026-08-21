"""Accumulated-knowledge gates (cold-profile corpus runs).

Each gate defaults ON (production behaviour) and, when turned off,
must actually stop its seam from reading accumulated knowledge:
IRIS synthesis/refinement/assumptions, SAGE recall, graduated-rule
library replay, cross-run journal import, prior domain-model import,
and annotation reads. Seams are exercised with stubs — no LLM, no
network, no persistent stores.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.audit.orchestrator import (
    OrchestratorConfig,
    _annotations_dir,
    _apply_profile_gates,
    _iris_prep_specs,
    _iris_refine_and_bypass,
    _load_domain_model,
    _seed_observations_from_sage,
)
from core.audit.pipeline import AuditPipelineOpts, _build_orchestrator_config

GATES = (
    "iris",
    "sage_recall",
    "library_replay",
    "cross_run_import",
    "domain_model_import",
    "annotations_read",
)


def _config(tmp_path: Path, **kw) -> OrchestratorConfig:
    kw.setdefault("target_path", tmp_path / "src")
    kw.setdefault("out_dir", tmp_path / "out")
    cfg = OrchestratorConfig(**kw)
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    return cfg


class _StubClient:
    """LLM-client stand-in for _build_orchestrator_config."""

    class config:  # noqa: D106 — attribute bag
        max_cost_per_scan = 10.0


class TestGateThreading:
    """AuditPipelineOpts → OrchestratorConfig, both directions."""

    def _build(self, opts):
        from core.audit.pipeline import ReviewMode

        return _build_orchestrator_config(
            opts, _StubClient(), ["default"], ReviewMode.SECURITY,
        )

    def test_defaults_thread_deployed(self, tmp_path):
        opts = AuditPipelineOpts(target_path=tmp_path, out_dir=tmp_path)
        config = self._build(opts)
        assert config.profile == "deployed"
        for gate in GATES:
            assert getattr(config, gate) is True, gate

    def test_cold_gates_thread_off(self, tmp_path):
        opts = AuditPipelineOpts(
            target_path=tmp_path,
            out_dir=tmp_path,
            profile="cold",
            iris=False,
            sage_recall=False,
            library_replay=False,
            cross_run_import=False,
            domain_model_import=False,
            annotations_read=False,
        )
        config = self._build(opts)
        assert config.profile == "cold"
        for gate in GATES:
            assert getattr(config, gate) is False, gate


class TestApplyProfileGates:
    def test_disabled_gates_log_one_info_line_each(self, tmp_path, caplog):
        config = _config(
            tmp_path,
            profile="cold",
            **{gate: False for gate in GATES},
        )
        with caplog.at_level(logging.INFO, logger="core.audit.orchestrator"):
            _apply_profile_gates(config)
        lines = [
            r.message for r in caplog.records
            if r.message.startswith("profile=cold: ")
        ]
        assert len(lines) == len(GATES)
        for label in (
            "iris",
            "sage recall",
            "graduated-rule library replay",
            "cross-run journal import",
            "prior domain-model import",
            "annotations read",
        ):
            assert f"profile=cold: {label} disabled" in lines

    def test_deployed_defaults_log_nothing(self, tmp_path, caplog):
        config = _config(tmp_path)
        with caplog.at_level(logging.INFO, logger="core.audit.orchestrator"):
            _apply_profile_gates(config)
        assert not [
            r for r in caplog.records if "disabled" in r.message
        ]

    def test_annotations_dir_cleared_when_gate_off(self, tmp_path):
        config = _config(
            tmp_path, annotations_read=False, annotations_dir=tmp_path,
        )
        _apply_profile_gates(config)
        assert config.annotations_dir is None

    def test_annotations_dir_kept_when_gate_on(self, tmp_path):
        config = _config(tmp_path, annotations_dir=tmp_path)
        _apply_profile_gates(config)
        assert config.annotations_dir == tmp_path


class TestDomainModelGate:
    def _model(self, path: Path, name: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"concepts": [name], "invariants": []}))

    def test_prior_project_model_invisible_when_gate_off(self, tmp_path):
        config = _config(tmp_path, domain_model_import=False)
        # A prior /understand --study left a project-level model.
        self._model(
            config.out_dir.parent / "concepts" / "domain-model.json",
            "prior",
        )
        assert _load_domain_model(config) is None

    def test_prior_project_model_imported_when_gate_on(self, tmp_path):
        config = _config(tmp_path)
        self._model(
            config.out_dir.parent / "concepts" / "domain-model.json",
            "prior",
        )
        model = _load_domain_model(config)
        assert model and model["concepts"] == ["prior"]

    def test_in_run_study_output_read_in_both_profiles(self, tmp_path):
        for gate in (True, False):
            config = _config(tmp_path, domain_model_import=gate)
            self._model(config.out_dir / "domain-model.json", "fresh")
            model = _load_domain_model(config)
            assert model and model["concepts"] == ["fresh"], gate


class TestAnnotationsGate:
    def test_gate_off_suppresses_explicit_and_resolved_dirs(self, tmp_path):
        config = _config(
            tmp_path, annotations_read=False, annotations_dir=tmp_path,
        )
        with patch(
            "core.audit.orchestrator._resolve_ann_dir",
        ) as resolve:
            assert _annotations_dir(config) is None
        resolve.assert_not_called()

    def test_gate_on_prefers_explicit_dir(self, tmp_path):
        config = _config(tmp_path, annotations_dir=tmp_path)
        assert _annotations_dir(config) == tmp_path

    def test_gate_on_falls_back_to_resolver(self, tmp_path):
        config = _config(tmp_path)
        with patch(
            "core.audit.orchestrator._resolve_ann_dir",
            return_value=tmp_path / "ann",
        ) as resolve:
            assert _annotations_dir(config) == tmp_path / "ann"
        resolve.assert_called_once_with(config.out_dir)


class TestIrisGates:
    def test_prep_specs_skipped_when_gate_off(self, tmp_path):
        config = _config(tmp_path, iris=False, profile="cold")
        with patch(
            "core.audit.iris_specs.identify_candidates",
        ) as identify:
            specs, sinks = _iris_prep_specs(config, [], None)
        assert (specs, sinks) == ([], None)
        identify.assert_not_called()

    def test_prep_specs_run_when_gate_on(self, tmp_path):
        config = _config(tmp_path)
        with patch(
            "core.audit.iris_specs.identify_candidates", return_value=[],
        ) as identify, patch(
            "core.iris.api.get_project_sinks", return_value=None,
        ) as sinks_read:
            specs, sinks = _iris_prep_specs(config, [], None)
        assert (specs, sinks) == ([], None)
        identify.assert_called_once()
        sinks_read.assert_called_once()

    def test_refine_and_bypass_skipped_when_gate_off(self, tmp_path):
        config = _config(tmp_path, iris=False, profile="cold")
        with patch(
            "core.audit.iris_specs.identify_candidates",
        ) as identify:
            runner, findings = _iris_refine_and_bypass(
                config, [], None, None, {}, [],
            )
        assert (runner, findings) == (None, [])
        identify.assert_not_called()

    def test_refine_and_bypass_runs_when_gate_on(self, tmp_path):
        config = _config(tmp_path)
        with patch(
            "core.audit.iris_specs.identify_candidates", return_value=[],
        ) as identify:
            runner, findings = _iris_refine_and_bypass(
                config, [], None, None, {}, [],
            )
        assert (runner, findings) == (None, [])
        identify.assert_called_once()


class TestSageRecallGate:
    def test_observation_seeding_skipped_when_gate_off(self, tmp_path):
        config = _config(tmp_path, sage_recall=False, profile="cold")
        with patch(
            "core.sage.hooks.recall_audit_observations",
        ) as recall:
            assert _seed_observations_from_sage(config) == []
        recall.assert_not_called()

    def test_observation_seeding_runs_when_gate_on(self, tmp_path):
        config = _config(tmp_path)
        with patch(
            "core.sage.hooks.recall_audit_observations", return_value=[],
        ) as recall:
            assert _seed_observations_from_sage(config) == []
        recall.assert_called_once()

    def test_rule_replay_skipped_when_gate_off(self, tmp_path):
        """checker_synthesis must not consult SAGE-recalled rules."""
        from core.audit.checker_synthesis import synthesize_and_sweep

        outcome, config = _synthesis_stubs(tmp_path, sage_recall=False)
        with _synthesis_patches() as seams:
            synthesize_and_sweep(outcome, config, set())
        seams["sage_replay"].assert_not_called()

    def test_rule_replay_consulted_when_gate_on(self, tmp_path):
        from core.audit.checker_synthesis import synthesize_and_sweep

        outcome, config = _synthesis_stubs(tmp_path, sage_recall=True)
        with _synthesis_patches() as seams:
            synthesize_and_sweep(outcome, config, set())
        seams["sage_replay"].assert_called_once()


class TestLibraryReplayGate:
    def test_find_replayable_skipped_when_gate_off(self, tmp_path):
        from core.audit.checker_synthesis import synthesize_and_sweep

        outcome, config = _synthesis_stubs(tmp_path, library_replay=False)
        with _synthesis_patches() as seams:
            synthesize_and_sweep(outcome, config, set())
        seams["library"].find_replayable.assert_not_called()
        # The fresh in-run synthesis path must still run.
        seams["synthesise"].assert_called_once()

    def test_find_replayable_consulted_when_gate_on(self, tmp_path):
        from core.audit.checker_synthesis import synthesize_and_sweep

        outcome, config = _synthesis_stubs(tmp_path, library_replay=True)
        with _synthesis_patches() as seams:
            synthesize_and_sweep(outcome, config, set())
        seams["library"].find_replayable.assert_called_once()


class TestCrossRunImportGate:
    def _config(self, tmp_path, cross_run_import):
        out = tmp_path / "out"
        out.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            out_dir=out,
            target_path=tmp_path / "src",
            cross_run_import=cross_run_import,
            cvefix_corpus_dir=None,
        )

    def _collect(self, config):
        import core.audit.synthesis_seeds as seeds_mod

        calls = {}

        def fake_journal(out_dir, project_dir, target_path, **kw):
            calls["project_dir"] = project_dir
            return []

        def fake_crash(run_dirs, target_path, **kw):
            calls["run_dirs"] = list(run_dirs)
            return []

        with patch.object(
            seeds_mod, "seeds_from_journal", side_effect=fake_journal,
        ), patch.object(
            seeds_mod, "seeds_from_crash_contexts", side_effect=fake_crash,
        ), patch(
            "core.audit.joern_backend.sibling_run_dirs",
            return_value=[Path("/prior/run")],
        ) as siblings:
            seeds_mod.collect_external_seeds(config)
        calls["siblings"] = siblings
        return calls

    def test_gate_off_restricts_to_own_run_dir(self, tmp_path):
        config = self._config(tmp_path, cross_run_import=False)
        # Even inside a project (marker present), nothing cross-run.
        (config.out_dir / ".raptor-run.json").write_text("{}")
        calls = self._collect(config)
        calls["siblings"].assert_not_called()
        assert calls["project_dir"] is None
        assert calls["run_dirs"] == [config.out_dir]

    def test_gate_on_folds_project_and_siblings(self, tmp_path):
        config = self._config(tmp_path, cross_run_import=True)
        (config.out_dir / ".raptor-run.json").write_text("{}")
        calls = self._collect(config)
        calls["siblings"].assert_called_once()
        assert calls["project_dir"] == config.out_dir.parent
        assert Path("/prior/run") in calls["run_dirs"]


# ---------------------------------------------------------------------------
# Shared checker-synthesis scaffolding
# ---------------------------------------------------------------------------


def _synthesis_stubs(tmp_path, **gates):
    """(outcome, config) pair that reaches the replay seams."""
    outcome = SimpleNamespace(
        file="src/auth.c",
        function="check_pw",
        line=42,
        hypothesis="",
        status="finding",
        evidence_tool="semgrep",
        review_result={
            "hypothesis": "missing bounds check on len",
            "cwe_class": "CWE-120",
            "source_snippet": "memcpy(dst, buf, len);",
        },
    )
    config = SimpleNamespace(
        target_path=str(tmp_path),
        out_dir=str(tmp_path),
        codeql_db_path=None,
        **gates,
    )
    return outcome, config


class _RecordingLibrary:
    """RuleLibrary stand-in recording find_replayable consultation."""

    def __init__(self):
        from unittest.mock import Mock

        self.find_replayable = Mock(return_value=[])


def _synthesis_patches():
    """Patch every LLM/store seam behind synthesize_and_sweep."""
    from contextlib import ExitStack, contextmanager

    @contextmanager
    def _ctx():
        import packages.checker_synthesis as pkg

        library = _RecordingLibrary()

        def fake_llm(_config):
            client = SimpleNamespace(total_cost=0.0, model_name="stub")
            return (lambda p, s, sp: {"rule": "r"}), client

        with ExitStack() as stack:
            stack.enter_context(patch(
                "core.audit.checker_synthesis._build_llm_callable",
                side_effect=fake_llm,
            ))
            stack.enter_context(patch(
                "packages.checker_synthesis.RuleLibrary",
                return_value=library,
            ))
            sage_replay = stack.enter_context(patch(
                "core.audit.checker_synthesis._sage_replay_rule",
                return_value=None,
            ))
            synthesise = stack.enter_context(patch.object(
                pkg, "synthesise_with_refinement",
                return_value=SimpleNamespace(rule=None, errors=[]),
            ))
            stack.enter_context(patch(
                "core.audit.checker_synthesis._synthesis_class_cost",
                return_value=0.0,
            ))
            yield {
                "library": library,
                "sage_replay": sage_replay,
                "synthesise": synthesise,
            }

    return _ctx()


class _ReserveClient:
    """Budget-client stand-in recording reserve traffic."""

    def __init__(self, cap):
        self.config = SimpleNamespace(max_cost_per_scan=cap)
        self.held = 0.0
        self.hold_calls = []
        self.release_calls = 0

    def hold_budget_reserve(self, amount):
        self.hold_calls.append(amount)
        self.held = amount
        return amount

    def release_budget_reserve(self):
        self.release_calls += 1
        released, self.held = self.held, 0.0
        return released


class TestReviewReserve:
    def test_hold_takes_fraction_of_cap(self, tmp_path, caplog):
        from core.audit.orchestrator import _hold_review_reserve

        client = _ReserveClient(cap=100.0)
        config = _config(
            tmp_path, review_reserve_fraction=0.35,
            llm_budget_client=client,
        )
        with caplog.at_level(logging.INFO, logger="core.audit.orchestrator"):
            held = _hold_review_reserve(config)
        assert held == 35.0
        assert client.hold_calls == [35.0]
        assert any("review: holding" in r.message for r in caplog.records)

    def test_zero_fraction_is_default_off(self, tmp_path):
        from core.audit.orchestrator import _hold_review_reserve

        client = _ReserveClient(cap=100.0)
        config = _config(tmp_path, llm_budget_client=client)
        assert _hold_review_reserve(config) == 0.0
        assert client.hold_calls == []

    def test_infinite_or_missing_cap_holds_nothing(self, tmp_path):
        from core.audit.orchestrator import _hold_review_reserve

        client = _ReserveClient(cap=float("inf"))
        config = _config(
            tmp_path, review_reserve_fraction=0.35,
            llm_budget_client=client,
        )
        assert _hold_review_reserve(config) == 0.0
        config.llm_budget_client = None
        assert _hold_review_reserve(config) == 0.0

    def test_release_returns_reserve(self, tmp_path, caplog):
        from core.audit.orchestrator import (
            _hold_review_reserve,
            _release_review_reserve,
        )

        client = _ReserveClient(cap=200.0)
        config = _config(
            tmp_path, review_reserve_fraction=0.5,
            llm_budget_client=client,
        )
        _hold_review_reserve(config)
        with caplog.at_level(logging.INFO, logger="core.audit.orchestrator"):
            _release_review_reserve(config)
        assert client.release_calls == 1
        assert client.held == 0.0
        assert any("review: released" in r.message for r in caplog.records)

    def test_fraction_clamped_below_whole_cap(self, tmp_path):
        from core.audit.orchestrator import _hold_review_reserve

        client = _ReserveClient(cap=100.0)
        config = _config(
            tmp_path, review_reserve_fraction=1.5,
            llm_budget_client=client,
        )
        assert _hold_review_reserve(config) == 90.0

    def test_opts_thread_review_reserve_fraction(self, tmp_path):
        from core.audit.pipeline import ReviewMode

        opts = AuditPipelineOpts(
            target_path=tmp_path, out_dir=tmp_path,
            review_reserve_fraction=0.35,
        )
        config = _build_orchestrator_config(
            opts, _StubClient(), ["default"], ReviewMode.SECURITY,
        )
        assert config.review_reserve_fraction == 0.35
        # None (default) leaves the orchestrator default (off).
        opts = AuditPipelineOpts(target_path=tmp_path, out_dir=tmp_path)
        config = _build_orchestrator_config(
            opts, _StubClient(), ["default"], ReviewMode.SECURITY,
        )
        assert config.review_reserve_fraction == 0.0


class TestGroupBudgetFormula:
    def test_scales_with_label_weight(self):
        from core.audit.corpus.run_corpus import (
            GROUP_BUDGET_BASE_USD,
            GROUP_BUDGET_PER_LABEL_USD,
            _group_max_cost,
        )

        assert _group_max_cost(1) == (
            GROUP_BUDGET_BASE_USD + GROUP_BUDGET_PER_LABEL_USD
        )
        assert _group_max_cost(2) > _group_max_cost(1)

    def test_fifteen_label_anchor_matches_old_flat_cap(self):
        """30 + 8 * 15 = 150 — the historical flat per-group cap."""
        from core.audit.corpus.run_corpus import _group_max_cost

        assert _group_max_cost(15) == 150.0

    def test_cap_bounds_large_groups(self):
        from core.audit.corpus.run_corpus import (
            GROUP_BUDGET_CAP_USD,
            _group_max_cost,
        )

        assert _group_max_cost(80) == GROUP_BUDGET_CAP_USD
        assert _group_max_cost(10_000) == GROUP_BUDGET_CAP_USD

    def test_target_opts_use_formula_and_reserve(self, tmp_path, monkeypatch):
        import core.audit.corpus.run_corpus as run_corpus
        import core.audit.pipeline as pipeline

        captured = []
        monkeypatch.setattr(
            pipeline, "run_audit_pipeline", captured.append,
        )
        monkeypatch.setattr(
            run_corpus, "_build_checklist", lambda t, o: True,
        )
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        labels = [
            SimpleNamespace(
                function_id=f"a.c:f{i}",
                bug_class="auth",
                expected_status="clean",
                expected_mechanism="",
                expected_mode_results={},
                source=SimpleNamespace(
                    repo="test", sha="x", file="a.c",
                    line_start=1, line_end=6,
                ),
            )
            for i in range(3)
        ]
        run_corpus._run_audit_on_target(
            src, labels, out_dir=tmp_path / "out", mode="security",
        )
        opts = captured[0]
        assert opts.max_cost_usd == run_corpus._group_max_cost(3)
        assert opts.review_reserve_fraction == (
            run_corpus.GROUP_REVIEW_RESERVE_FRACTION
        )
