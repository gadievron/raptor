"""Pre-flight chokepoint wiring + report retention in process_findings.

Covers, end-to-end through ``process_findings`` on a prep-mode agent
(no LLM):

* The reachability / SAGE / fixture pre-flights resolve the function
  name and line from the SARIF key shape actually flowing through the
  pipeline (``file`` + ``startLine`` + ``metadata["name"]``) — not
  the never-written ``function`` / ``line`` keys.
* Chokepoint-suppressed findings are RETAINED in the report's
  ``results`` with an explicit skip status and their synthesized
  analysis receipt (explicit disqualifier, never a silent drop), and
  counters agree.
* Non-suppressed findings still flow through untouched (two-direction).
* The report carries the ``dataflow_validation`` summary block the
  sequential-mode console telemetry renders from.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import packages.llm_analysis.agent as agent_mod  # noqa: E402


def _make_agent(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "src").mkdir(exist_ok=True)
    (repo / "src" / "auth.c").write_text(
        "".join(f"int line{i};\n" for i in range(1, 60))
    )
    mock_availability = MagicMock()
    mock_availability.external_llm = False
    mock_availability.claude_code = True
    with patch(
        "packages.llm_analysis.agent.detect_llm_availability",
        return_value=mock_availability,
    ):
        agent = agent_mod.AutonomousSecurityAgentV2(
            repo_path=repo,
            out_dir=tmp_path / "out",
            prep_only=True,
            synthesise_checkers=False,
        )
    return agent


def _finding(fid: str = "F1") -> dict:
    # Exact key shape parse_sarif_findings emits, plus the metadata
    # the inventory enrichment attaches (pre-populated so no
    # checklist lookup is needed).
    return {
        "finding_id": fid,
        "rule_id": "c.lang.security.strcpy",
        "message": "strcpy into fixed buffer",
        "file": "src/auth.c",
        "startLine": 42,
        "endLine": 42,
        "snippet": "strcpy(buf, input);",
        "level": "error",
        "cwe_id": "CWE-120",
        "tool": "semgrep",
        "has_dataflow": False,
        "dataflow_path": None,
        "metadata": {"name": "check_pw"},
    }


def _run(agent, findings, checklist=None, monkeypatch=None):
    monkeypatch.setattr(
        agent_mod, "parse_sarif_findings", lambda _p: list(findings),
    )
    monkeypatch.setattr(
        agent_mod, "deduplicate_findings", lambda fs: fs,
    )
    return agent.process_findings(
        sarif_paths=["fake.sarif"],
        checklist=checklist,
        emit_journal=False,
    )


class TestReachabilityChokepointWiring:

    def test_binding_uses_metadata_name_and_start_line(
        self, tmp_path, monkeypatch,
    ):
        agent = _make_agent(tmp_path)
        seen: dict = {}

        def fake_check_suppress(**kwargs):
            seen.update(kwargs)
            return ("binary_oracle_absent", "function absent from binary")

        import core.analysis.reach_chokepoint as rc
        monkeypatch.setattr(rc, "check_suppress", fake_check_suppress)

        report = _run(
            agent, [_finding()], checklist={"functions": []},
            monkeypatch=monkeypatch,
        )

        # The chokepoint received the SARIF-shaped coordinates.
        assert seen["function_name"] == "check_pw"
        assert seen["file_path"] == "src/auth.c"
        assert seen["line"] == 42

        # Suppressed finding is retained with an explicit skip status
        # and its synthesized refutation receipt.
        assert report["analyzed"] == 1
        results = report["results"]
        assert len(results) == 1
        rec = results[0]
        assert rec["status"] == "skipped_dead_code"
        assert rec["skip_reason"] == "binary_oracle_absent"
        assert rec["analysis"]["reachability_suppression"] is True
        assert rec["analysis"]["is_true_positive"] is False

    def test_non_suppressed_finding_not_stamped(
        self, tmp_path, monkeypatch,
    ):
        # Two-direction: when the chokepoint declines, the finding
        # flows through with no skip status stamped by the pre-flight.
        agent = _make_agent(tmp_path)

        import core.analysis.reach_chokepoint as rc
        monkeypatch.setattr(rc, "check_suppress", lambda **kw: None)

        report = _run(
            agent, [_finding()], checklist={"functions": []},
            monkeypatch=monkeypatch,
        )
        results = report["results"]
        assert len(results) == 1
        assert results[0].get("status") is None
        assert (results[0].get("analysis") or {}).get(
            "reachability_suppression"
        ) is None


class TestSagePriorVerdictWiring:

    def test_suppression_fires_on_sarif_shape(self, tmp_path, monkeypatch):
        agent = _make_agent(tmp_path)
        recall_args: dict = {}

        import core.sage.hooks as hooks
        monkeypatch.setattr(
            hooks, "compute_finding_source_hash", lambda _p, _l: "abc123",
        )

        def fake_recall(repo, rule, rel, fn, src_hash):
            recall_args.update(
                rule=rule, rel=rel, fn=fn, src_hash=src_hash,
            )
            return {"verdict": "false_positive", "confidence": 0.93}

        monkeypatch.setattr(
            hooks, "recall_prior_finding_verdict", fake_recall,
        )

        report = _run(agent, [_finding()], monkeypatch=monkeypatch)

        assert recall_args["fn"] == "check_pw"
        assert recall_args["rel"] == "src/auth.c"
        assert report["sage_fp_suppression"]["skipped_llm_calls"] == 1
        rec = report["results"][0]
        assert rec["status"] == "skipped"
        assert rec["skip_reason"] == "sage_prior_verdict"
        assert rec["analysis"]["sage_fp_suppression"] is True

    def test_no_prior_verdict_no_suppression(self, tmp_path, monkeypatch):
        # Two-direction: recall returning None must not suppress.
        agent = _make_agent(tmp_path)

        import core.sage.hooks as hooks
        monkeypatch.setattr(
            hooks, "compute_finding_source_hash", lambda _p, _l: "abc123",
        )
        monkeypatch.setattr(
            hooks, "recall_prior_finding_verdict",
            lambda *a, **kw: None,
        )

        report = _run(agent, [_finding()], monkeypatch=monkeypatch)
        assert report["sage_fp_suppression"]["skipped_llm_calls"] == 0
        assert report["results"][0].get("status") is None


class TestFixtureDetectionWiring:

    def test_function_resolved_from_metadata_name(
        self, tmp_path, monkeypatch,
    ):
        agent = _make_agent(tmp_path)
        seen: dict = {}

        def fake_detect_fixture(*, file_path, function, inventory):
            seen["file_path"] = file_path
            seen["function"] = function
            return SimpleNamespace(likely_test_harness="true", evidence=[])

        import core.inventory.fixture_detection as fx
        monkeypatch.setattr(fx, "detect_fixture", fake_detect_fixture)

        report = _run(
            agent, [_finding()], checklist={"functions": []},
            monkeypatch=monkeypatch,
        )

        assert seen["function"] == "check_pw"
        assert seen["file_path"] == "src/auth.c"
        assert report["fixture_detection_metrics"]["skipped_llm_calls"] == 1
        rec = report["results"][0]
        assert rec["status"] == "skipped"
        assert rec["skip_reason"] == "fixture_demotion"
        assert rec["analysis"]["fixture_demotion"] is True


class TestReportTelemetryBlock:

    def test_report_carries_dataflow_validation_summary(
        self, tmp_path, monkeypatch,
    ):
        agent = _make_agent(tmp_path)
        report = _run(agent, [_finding()], monkeypatch=monkeypatch)
        assert report["dataflow_validation"] == {"n_validated": 0}
