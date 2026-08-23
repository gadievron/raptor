"""Tests for the build evidence feeds (``cve_env/infra/scorecard.py``
and ``cve_env/infra/verified_outcomes.py``) plus their wiring through
the raptor shim."""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_env.infra.scorecard import DECISION_CLASS, record_build_outcome
from cve_env.infra.verified_outcomes import write_build_outcome

CVE = "CVE-2018-7600"


def _outcome(status="success", **kw):
    base = {
        "cve_id": CVE,
        "status": status,
        "verify_passed": status in ("success", "verified_partial"),
        "method": "vulhub-image",
        "num_turns": 12,
        "total_cost_usd": 0.42,
        "tool_names_called": ["nvd_lookup", "image_resolve", "docker_run",
                              "verify"],
    }
    base.update(kw)
    return base


# ── scorecard adjudication ────────────────────────────────────────────


class TestScorecardAdjudication:
    def _record(self, status, tmp_path):
        from core.llm.scorecard.scorecard import ModelScorecard

        path = tmp_path / "llm_scorecard.json"
        sc = ModelScorecard(path)
        wrote = record_build_outcome("claude-opus-4-7", CVE, status,
                                     scorecard=sc)
        return wrote, path

    @pytest.mark.parametrize("status", ["success", "verified_partial",
                                        "success_partial"])
    def test_verify_pass_records_correct(self, tmp_path, status):
        wrote, path = self._record(status, tmp_path)
        assert wrote
        raw = path.read_text()
        assert DECISION_CLASS in raw
        assert '"correct": 1' in raw

    @pytest.mark.parametrize("status", ["verify_failed", "no_verify_pass"])
    def test_verify_refutation_records_incorrect(self, tmp_path, status):
        wrote, path = self._record(status, tmp_path)
        assert wrote
        assert '"incorrect": 1' in path.read_text()

    @pytest.mark.parametrize("status", [
        "unresolvable", "budget_exhausted", "turn_cap", "interrupted",
        "rate_limited", "launched_no_verify", "error", "",
    ])
    def test_non_verdict_statuses_record_nothing(self, tmp_path, status):
        wrote, path = self._record(status, tmp_path)
        assert wrote is False
        assert not path.exists()

    def test_missing_model_skips(self, tmp_path):
        assert record_build_outcome("", CVE, "success") is False

    def test_scorecard_errors_swallowed(self):
        class _Broken:
            def record_event(self, *a, **k):
                raise OSError("disk full")

        assert record_build_outcome("m", CVE, "success",
                                    scorecard=_Broken()) is False


# ── verified outcomes ─────────────────────────────────────────────────


class TestVerifiedOutcomes:
    def test_success_writes_runtime_record(self, tmp_path):
        assert write_build_outcome(tmp_path, _outcome())
        from core.labeled_attempts.view import (
            VERIFIED_OUTCOMES_FILENAME,
            Oracle,
            OutcomeStatus,
            VerifiedOutcome,
        )

        lines = (tmp_path / VERIFIED_OUTCOMES_FILENAME).read_text().splitlines()
        assert len(lines) == 1
        vo = VerifiedOutcome.from_dict(json.loads(lines[0]))
        assert vo.finding_id == CVE
        assert vo.oracle is Oracle.RUNTIME
        assert vo.status is OutcomeStatus.VERIFIED
        assert vo.reproducible is False
        assert vo.produced_by == "cve-env"
        assert vo.evidence["tier"] == "docker"
        assert vo.evidence["method"] == "vulhub-image"

    @pytest.mark.parametrize("status", [
        "verified_partial", "verify_failed", "unresolvable",
        "budget_exhausted", "interrupted",
    ])
    def test_non_success_writes_nothing(self, tmp_path, status):
        assert not write_build_outcome(tmp_path, _outcome(status=status))
        assert not list(tmp_path.iterdir())

    def test_missing_cve_id_skips(self, tmp_path):
        assert not write_build_outcome(tmp_path, {"status": "success"})

    def test_io_trouble_never_raises(self, tmp_path):
        blocked = tmp_path / "file"
        blocked.write_text("occupied")
        assert not write_build_outcome(blocked / "sub", _outcome())


# ── shim wiring ───────────────────────────────────────────────────────


REPO_ROOT = Path(__file__).resolve().parents[4]
LIBEXEC = REPO_ROOT / "libexec" / "raptor-cve-env"


def _load_shim():
    loader = SourceFileLoader("raptor_cve_env_evidence", str(LIBEXEC))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_shim_records_evidence_from_sidecar(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    recorded = {}

    def cli_main(argv):
        # Simulate the build writing its sidecar into the injected
        # audit root (the run dir).
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{CVE}.outcome.json").write_text(json.dumps(_outcome()))
        return 0

    def fake_record(model, cve, status, **kw):
        recorded["scorecard"] = (model, cve, status)
        return True

    def fake_write(output_dir, outcome, **kw):
        recorded["verified"] = (str(output_dir), outcome["status"])
        return True

    mod = _load_shim()
    with (
        patch("core.run.output.get_output_dir",
              lambda *a, **k: run_dir),
        patch("core.run.output.resolve_default_target", lambda: None),
        patch("core.run.metadata.start_run",
              lambda d, c, **k: Path(d).mkdir(parents=True, exist_ok=True) or Path(d)),
        patch("core.run.metadata.complete_run", lambda *a, **k: None),
        patch("core.run.metadata.fail_run", lambda *a, **k: None),
        patch("core.run.metadata.interrupt_run", lambda *a, **k: None),
        patch("cve_env.cli.main", cli_main),
        patch("cve_env.infra.scorecard.record_build_outcome", fake_record),
        patch("cve_env.infra.verified_outcomes.write_build_outcome",
              fake_write),
    ):
        rc = mod.main(["build", CVE])

    assert rc == 0
    from cve_env.config import MODEL
    assert recorded["scorecard"] == (MODEL, CVE, "success")
    assert recorded["verified"] == (str(run_dir), "success")


def test_shim_missing_sidecar_records_nothing(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    recorded = {}

    mod = _load_shim()
    with (
        patch("core.run.output.get_output_dir", lambda *a, **k: run_dir),
        patch("core.run.output.resolve_default_target", lambda: None),
        patch("core.run.metadata.start_run",
              lambda d, c, **k: Path(d).mkdir(parents=True, exist_ok=True) or Path(d)),
        patch("core.run.metadata.complete_run", lambda *a, **k: None),
        patch("core.run.metadata.fail_run", lambda *a, **k: None),
        patch("core.run.metadata.interrupt_run", lambda *a, **k: None),
        patch("cve_env.cli.main", lambda argv: 1),
        patch("cve_env.infra.scorecard.record_build_outcome",
              lambda *a, **k: recorded.setdefault("hit", True)),
    ):
        rc = mod.main(["build", CVE])
    assert rc == 1
    assert "hit" not in recorded
