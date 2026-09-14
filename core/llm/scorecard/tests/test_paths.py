"""Tests for the shared default-scorecard-path resolver.

The reliability ledger steers routing and short-circuit decisions, so
every consumer that resolves "the" sidecar without an explicit path
must land on the SAME file regardless of the invoking cwd. Pre-fix the
LLMConfig / CLI / audit defaults were cwd-relative while the producers
were RAPTOR_DIR-anchored — a bare-shell run from a scanned repo wrote
a stray ledger into the target tree and fragmented the history.
"""

from __future__ import annotations

from pathlib import Path

from core.llm.scorecard.paths import default_scorecard_path
from core.llm.scorecard.scorecard import ModelScorecard


class TestDefaultScorecardPath:
    def test_env_override_wins(self, monkeypatch, tmp_path):
        monkeypatch.setenv("RAPTOR_SCORECARD_PATH", str(tmp_path / "sc.json"))
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "install"))
        assert default_scorecard_path() == tmp_path / "sc.json"

    def test_raptor_dir_anchored(self, monkeypatch, tmp_path):
        monkeypatch.delenv("RAPTOR_SCORECARD_PATH", raising=False)
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        assert default_scorecard_path() == (
            tmp_path / "out" / "llm_scorecard.json"
        )

    def test_relative_fallback_without_raptor_dir(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_SCORECARD_PATH", raising=False)
        monkeypatch.delenv("RAPTOR_DIR", raising=False)
        assert default_scorecard_path() == Path("out/llm_scorecard.json")

    def test_existing_ledger_at_resolved_path_still_loads(
        self, monkeypatch, tmp_path,
    ):
        """Backward compat: only path RESOLUTION changed, not the file
        format — a ledger written pre-fix loads unchanged once the
        resolver points at it."""
        monkeypatch.delenv("RAPTOR_SCORECARD_PATH", raising=False)
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        path = default_scorecard_path()
        writer = ModelScorecard(path)
        writer.record_event(
            "verdict:test", "model-a", "cheap_short_circuit", "correct",
        )
        stats = ModelScorecard(path).get_stats()
        assert [(s.model, s.decision_class) for s in stats] == [
            ("model-a", "verdict:test"),
        ]
        assert stats[0].events["cheap_short_circuit"].correct == 1


class TestConsumerResolution:
    def test_llmconfig_default_uses_shared_resolver(
        self, monkeypatch, tmp_path,
    ):
        from core.llm.config import LLMConfig

        monkeypatch.delenv("RAPTOR_SCORECARD_PATH", raising=False)
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        cfg = LLMConfig(primary_model=None, fallback_models=[])
        assert cfg.scorecard_path == tmp_path / "out" / "llm_scorecard.json"

    def test_tool_evidence_default_uses_shared_resolver(
        self, monkeypatch, tmp_path,
    ):
        """The None-scorecard fallback in the tool-evidence producer
        resolves through the shared helper (and therefore now honours
        RAPTOR_SCORECARD_PATH like every other consumer)."""
        import json

        from core.llm.scorecard import tool_evidence

        sc_path = tmp_path / "isolated.json"
        monkeypatch.setenv("RAPTOR_SCORECARD_PATH", str(sc_path))
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "orchestrated_report.json").write_text(json.dumps({
            "results": [{
                "finding_id": "f1",
                "analysed_by": "model-a",
                "rule_id": "r1",
                "is_exploitable": True,
                "reasoning": "because",
            }],
        }))
        (run_dir / "findings.json").write_text(json.dumps({
            "findings": [{"finding_id": "f1", "is_exploitable": True}],
        }))
        n = tool_evidence.auto_back_prop_from_validate_run(run_dir)
        assert n == 1
        assert sc_path.is_file()

    def test_validate_feedback_default_uses_shared_resolver(
        self, monkeypatch, tmp_path,
    ):
        from core.llm.scorecard import validate_feedback

        sc_path = tmp_path / "isolated_vf.json"
        monkeypatch.setenv("RAPTOR_SCORECARD_PATH", str(sc_path))
        n = validate_feedback.record_validate_feedback_outcomes([
            {
                "model": "model-a",
                "cwe": "CWE-79",
                "prior_verdict": "finding",
                "validate_verdict": "disproven",
                "file": "a.py",
                "function": "f",
                "reason": "unreachable",
            },
        ])
        assert n == 1
        assert sc_path.is_file()


class TestLazyDefaults:
    def test_cli_and_audit_defaults_resolve_at_invocation(
        self, monkeypatch, tmp_path,
    ):
        """The CLI parser default and ``audit()``'s default must
        resolve through the shared resolver at CALL time — a
        module-level ``default_scorecard_path()`` froze the path at
        import, silently ignoring an env override set later
        (in-process callers, some test orders)."""
        iso = tmp_path / "iso.json"
        monkeypatch.setenv("RAPTOR_SCORECARD_PATH", str(iso))

        from core.llm.scorecard import audit as audit_mod
        from core.llm.scorecard import cli as cli_mod

        args = cli_mod._build_parser().parse_args(["list"])
        assert args.path == iso

        report = audit_mod.audit()
        assert report.scorecard_path == str(iso)
