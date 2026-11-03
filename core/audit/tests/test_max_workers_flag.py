"""--max-workers CLI surface: parse-time validation and the plumbing
into OrchestratorConfig.max_workers (which _resolve_max_workers
honours over the transport-derived default)."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch

import pytest


def _load_cli():
    cli_path = str(
        Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit",
    )
    loader = SourceFileLoader("raptor_audit_maxworkers_test", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_audit_maxworkers_test", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(mod)
    return mod


def _parser(mod) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-workers", type=mod._max_workers_arg,
                        default=0)
    return parser


class TestParse:
    def test_valid_value_parses(self):
        mod = _load_cli()
        args = _parser(mod).parse_args(["--max-workers", "8"])
        assert args.max_workers == 8

    def test_above_cap_clamped(self):
        from core.llm.concurrency import MAX_WORKERS_CAP
        mod = _load_cli()
        args = _parser(mod).parse_args(["--max-workers", "64"])
        assert args.max_workers == MAX_WORKERS_CAP

    def test_invalid_values_rejected_at_parse(self):
        mod = _load_cli()
        parser = _parser(mod)
        for bad in ("0", "-3", "abc", "2.5"):
            with pytest.raises(SystemExit):
                parser.parse_args(["--max-workers", bad])

    def test_default_is_transport_derived_auto(self):
        mod = _load_cli()
        assert _parser(mod).parse_args([]).max_workers == 0


class TestReachesOrchestratorConfig:
    def test_value_lands_on_config_and_wins_resolution(self, tmp_path):
        from core.audit.orchestrator import _resolve_max_workers
        from core.audit.pipeline import (
            AuditPipelineOpts,
            ReviewMode,
            _build_orchestrator_config,
        )
        opts = AuditPipelineOpts(
            target_path=tmp_path, out_dir=tmp_path, max_workers=7,
        )
        config = _build_orchestrator_config(
            opts, client=None, models=["some-model"],
            mode=ReviewMode.ENSEMBLE,
        )
        assert config.max_workers == 7
        assert _resolve_max_workers(config) == 7

    def test_zero_defers_to_derived_default(self, tmp_path):
        from core.audit.pipeline import (
            AuditPipelineOpts,
            ReviewMode,
            _build_orchestrator_config,
        )
        opts = AuditPipelineOpts(target_path=tmp_path, out_dir=tmp_path)
        config = _build_orchestrator_config(
            opts, client=None, models=["some-model"],
            mode=ReviewMode.ENSEMBLE,
        )
        assert config.max_workers == 0


class TestResumeResolution:
    def test_cli_override_wins_for_segment(self):
        mod = _load_cli()
        assert mod._resume_max_workers(4, {"max_workers": 12}) == 4

    def test_persisted_value_applies_without_override(self):
        mod = _load_cli()
        assert mod._resume_max_workers(None, {"max_workers": 12}) == 12

    def test_defaults_to_auto_when_unpersisted(self):
        mod = _load_cli()
        assert mod._resume_max_workers(None, {}) == 0
        assert mod._resume_max_workers(None, {"max_workers": None}) == 0
        assert mod._resume_max_workers(None, {"max_workers": "bogus"}) == 0


class TestRunConfigPersistence:
    def test_run_config_carries_max_workers(self, tmp_path):
        from types import SimpleNamespace
        mod = _load_cli()
        args = SimpleNamespace(
            scope=None, scope_floor=True, pin=None, strategy=None,
            budget=None, model=None, max_cost=None, max_time=None,
            review_passes=1, batch_sloc_threshold=None,
            include_kinds=None, adversarial=False, rank_gaps=False,
            edges=False, max_propagation_depth=None, subsystem_depth=0,
            no_validate=False, no_binary_oracle=False,
            annotations_dir=None, codeql_db=None, dynamic=False,
            no_dynamic=False, no_verdict_reuse=False, pre_scan=False,
            no_caller_contract_context=False,
            no_caller_contract_demotion=False, schedule="cost",
            no_on_demand_synthesis=False, no_immediate_verify=False,
            no_vendored_triage=False,
            probe_determine_value=False, no_environment_breaker=False,
            deepen_reserve=None, prior_journal=None, prior_claims=3,
            max_workers=6,
        )
        cfg = mod._run_config_from_args(args, tmp_path)
        assert cfg["max_workers"] == 6
        # Round trip through the resume resolution: the persisted
        # value drives the next segment unless overridden.
        assert mod._resume_max_workers(None, cfg) == 6
        assert mod._resume_max_workers(2, cfg) == 2
