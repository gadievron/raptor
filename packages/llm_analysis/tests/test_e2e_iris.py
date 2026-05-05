"""End-to-end test for IRIS-style dataflow validation against a synthetic target.

The synthetic target lives at `tests/fixtures/iris_e2e/`. It contains:

  - `real_dataflow.py`: command injection where the user input flows
    cleanly to subprocess. Both Semgrep and CodeQL will (correctly)
    flag and confirm this. IRIS should leave is_exploitable=True.
  - `sanitized_no_dataflow.py`: surface-similar pattern that the LLM
    might claim has a dataflow, but a strict allowlist sanitizer
    (returning None on bad input) breaks the path. CodeQL dataflow
    correctly refutes. IRIS should downgrade is_exploitable.

This test exercises the full orchestration hook (run_validation_pass +
reconcile_dataflow_validation) end-to-end with a deterministic mock
LLM. The mock LLM returns "confirmed" for the real-dataflow finding
and "refuted" for the sanitized one — simulating a perfect IRIS run
without paying for real LLM calls.

A real-LLM smoke test that pays for tokens is documented separately
in the PR description; this CI-runnable test verifies the wiring.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.dataflow_validation import (
    reconcile_dataflow_validation,
    run_validation_pass,
)


# Synthetic target — created on demand in tmp_path so the test is
# self-contained. The semantics matter for the hypothesis (LLM sees
# the dataflow_summary; CodeQL is mocked so we control the verdict).
_REAL_DATAFLOW_SRC = """\
import subprocess
import sys


def get_user_input():
    return sys.argv[1]


def execute(cmd):
    return subprocess.call(cmd, shell=True)


def main():
    user_arg = get_user_input()
    return execute(user_arg)


if __name__ == "__main__":
    sys.exit(main())
"""

_SANITIZED_SRC = """\
import re
import subprocess
import sys


_SAFE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
_ALLOWLIST = {"ls", "pwd", "whoami", "uptime"}


def get_user_input():
    return sys.argv[1]


def sanitize(s):
    if not _SAFE_RE.match(s):
        return None
    if s not in _ALLOWLIST:
        return None
    return s


def execute_safe(cmd):
    if cmd is None:
        return 1
    return subprocess.call(cmd, shell=True)


def main():
    user_arg = get_user_input()
    return execute_safe(sanitize(user_arg))


if __name__ == "__main__":
    sys.exit(main())
"""


def _build_target_and_db(tmp_path: Path):
    """Create the target tree + a fake CodeQL database directory.

    The DB is just the marker file CodeQL writes; real query execution
    is mocked at the adapter level so we don't pay for a multi-minute
    real DB build in a unit test. The freshness check sees a DB that's
    newer than the source, so no stale warning.
    """
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "real_dataflow.py").write_text(_REAL_DATAFLOW_SRC)
    (src / "sanitized_no_dataflow.py").write_text(_SANITIZED_SRC)

    out_dir = tmp_path / "out"
    codeql_dir = out_dir / "codeql"
    codeql_dir.mkdir(parents=True)
    db = codeql_dir / "python-db"
    db.mkdir()
    (db / "codeql-database.yml").write_text("primaryLanguage: python\n")

    return repo, out_dir, db


def _findings_and_analyses():
    """Return (findings, results_by_id) representing what AnalysisTask
    produced for the two synthetic files.

    Both findings have is_exploitable=True and a dataflow_summary —
    they look identical at this layer. IRIS validation should
    distinguish them via the CodeQL-adapter mock returning matches
    for the real one and no matches for the sanitized one.
    """
    findings = [
        {
            "finding_id": "F-real",
            "tool": "semgrep",
            "rule_id": "raptor.injection.command-shell",
            "file_path": "src/real_dataflow.py",
            "start_line": 8,
            "language": "python",
            "message": "Tainted input passed to subprocess with shell=True",
            "has_dataflow": False,
        },
        {
            "finding_id": "F-fp",
            "tool": "semgrep",
            "rule_id": "raptor.injection.command-shell",
            "file_path": "src/sanitized_no_dataflow.py",
            "start_line": 26,
            "language": "python",
            "message": "Tainted input passed to subprocess with shell=True",
            "has_dataflow": False,
        },
    ]
    results_by_id = {
        "F-real": {
            "finding_id": "F-real",
            "is_exploitable": True,
            "exploitability_score": 0.85,
            "confidence": "high",
            "severity_assessment": "high",
            "ruling": "validated",
            "dataflow_summary": "argv[1] flows from get_user_input() to subprocess.call(shell=True) without sanitisation",
            "cwe_id": "CWE-78",
            "vuln_type": "command_injection",
        },
        "F-fp": {
            "finding_id": "F-fp",
            # The LLM analysed it as exploitable based on the
            # surface pattern — IRIS will refute.
            "is_exploitable": True,
            "exploitability_score": 0.75,
            "confidence": "medium",
            "severity_assessment": "high",
            "ruling": "validated",
            "dataflow_summary": "argv[1] flows from get_user_input() to subprocess.call(shell=True)",
            "cwe_id": "CWE-78",
            "vuln_type": "command_injection",
        },
    }
    return findings, results_by_id


class TestE2EIris:
    """End-to-end exercise of IRIS validation on the synthetic target."""

    def test_real_dataflow_confirmed_no_downgrade(self, tmp_path):
        """A real dataflow case: validation confirms, no downgrade."""
        from packages.hypothesis_validation.adapters.base import ToolEvidence

        repo, out_dir, db = _build_target_and_db(tmp_path)
        findings, results_by_id = _findings_and_analyses()
        # Only run on the real one to keep the test focused
        findings = [f for f in findings if f["finding_id"] == "F-real"]
        results_by_id = {"F-real": results_by_id["F-real"]}

        # Mock the CodeQL adapter to return matches (simulating a confirmed dataflow)
        evidence = ToolEvidence(
            tool="codeql", rule="<generated query>", success=True,
            matches=[{
                "file": "src/real_dataflow.py", "line": 8,
                "rule": "user-input-to-shell",
                "message": "tainted source flows to subprocess.call",
            }],
            summary="1 match",
        )

        # CWE-78 + python → Tier 1 fires; matches at finding location →
        # confirmed without ever calling the LLM. The mocked adapter
        # returns the evidence; the runner doesn't need an LLM at all
        # for the prebuilt path.
        with patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.is_available",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.run",
            return_value=evidence,
        ):
            metrics = run_validation_pass(
                findings=findings,
                results_by_id=results_by_id,
                out_dir=out_dir,
                repo_path=repo,
                dispatch_fn=MagicMock(),
                analysis_model=None,
                role_resolution={},
                dispatch_mode="external_llm",
                cost_tracker=None,
            )

        # Validation ran exactly once, confirmed
        assert metrics is not None
        assert metrics["n_validated"] == 1
        assert metrics["n_recommended_downgrades"] == 0

        # Reconciliation: no downgrade needed
        recon = reconcile_dataflow_validation(results_by_id)
        assert recon["n_hard_downgrades"] == 0
        assert recon["n_soft_downgrades"] == 0

        # is_exploitable preserved
        assert results_by_id["F-real"]["is_exploitable"] is True

    def test_false_positive_refuted_and_downgraded(self, tmp_path):
        """The sanitized case: CodeQL refutes via Tier 1 → Tier 2 fallthrough."""
        from packages.hypothesis_validation.adapters.base import ToolEvidence

        repo, out_dir, db = _build_target_and_db(tmp_path)
        findings, results_by_id = _findings_and_analyses()
        findings = [f for f in findings if f["finding_id"] == "F-fp"]
        results_by_id = {"F-fp": results_by_id["F-fp"]}

        # Both Tier 1 (prebuilt) and Tier 2 (template) return no matches.
        # Tier 2's no-match IS a refutation (LLM customised predicates).
        empty_evidence = ToolEvidence(
            tool="codeql", rule="<query>", success=True,
            matches=[], summary="no matches",
        )

        # LLM returns predicate bodies for Tier 2
        llm = MagicMock()
        llm.generate_structured.return_value = {
            "source_predicate_body": "n instanceof RemoteFlowSource",
            "sink_predicate_body": "exists(Call c)",
            "expected_evidence": "...", "reasoning": "test the claim",
        }

        with patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.is_available",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.run",
            return_value=empty_evidence,
        ), patch(
            "packages.llm_analysis.dataflow_validation.DispatchClient",
            return_value=llm,
        ):
            metrics = run_validation_pass(
                findings=findings,
                results_by_id=results_by_id,
                out_dir=out_dir,
                repo_path=repo,
                dispatch_fn=MagicMock(),
                analysis_model=None,
                role_resolution={},
                dispatch_mode="external_llm",
                cost_tracker=None,
            )

        # IRIS recommended a downgrade
        assert metrics["n_validated"] == 1
        assert metrics["n_recommended_downgrades"] == 1

        # Validation is non-destructive — is_exploitable still True
        assert results_by_id["F-fp"]["is_exploitable"] is True
        assert results_by_id["F-fp"]["dataflow_validation"]["recommends_downgrade"] is True

        # Reconciliation applies the hard downgrade (no consensus disagrees)
        recon = reconcile_dataflow_validation(results_by_id)
        assert recon["n_hard_downgrades"] == 1
        assert recon["n_soft_downgrades"] == 0

        # Final state: downgraded, original preserved
        assert results_by_id["F-fp"]["is_exploitable"] is False
        assert results_by_id["F-fp"]["is_exploitable_pre_validation"] is True
        assert "validation_downgrade_reason" in results_by_id["F-fp"]

    def test_mixed_findings_partial_downgrade(self, tmp_path):
        """Both findings together: real one stays, FP gets downgraded."""
        from packages.hypothesis_validation.adapters.base import ToolEvidence

        repo, out_dir, db = _build_target_and_db(tmp_path)
        findings, results_by_id = _findings_and_analyses()

        # Adapter returns different evidence depending on which finding
        # is being validated. We track call order: F-real validates first
        # (sorted findings_by_id) then F-fp.
        # Adapter behaviour:
        #   F-real: Tier 1 returns matches at the location → confirmed (no Tier 2)
        #   F-fp:   Tier 1 returns no matches → fall through to Tier 2,
        #           which also returns no matches → refuted
        match_for_real = ToolEvidence(
            tool="codeql", rule="<gen>", success=True,
            matches=[{"file": "src/real_dataflow.py", "line": 8,
                      "rule": "user-input-to-shell", "message": "taint path"}],
            summary="1 match",
        )
        no_match = ToolEvidence(
            tool="codeql", rule="<gen>", success=True,
            matches=[], summary="no matches",
        )
        # F-real: 1 call (Tier 1 confirms). F-fp: 2 calls (Tier 1 → Tier 2)
        adapter_runs = [match_for_real, no_match, no_match]

        # LLM gives predicate bodies for F-fp's Tier 2 generation.
        # F-real doesn't reach Tier 2 so its slot is unused.
        llm = MagicMock()
        llm.generate_structured.return_value = {
            "source_predicate_body": "n instanceof RemoteFlowSource",
            "sink_predicate_body": "exists(Call c)",
            "expected_evidence": "...", "reasoning": "...",
        }

        with patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.is_available",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.run",
            side_effect=lambda rule, target, **kwargs: adapter_runs.pop(0),
        ), patch(
            "packages.llm_analysis.dataflow_validation.DispatchClient",
            return_value=llm,
        ):
            metrics = run_validation_pass(
                findings=findings,
                results_by_id=results_by_id,
                out_dir=out_dir,
                repo_path=repo,
                dispatch_fn=MagicMock(),
                analysis_model=None,
                role_resolution={},
                dispatch_mode="external_llm",
                cost_tracker=None,
            )

        assert metrics["n_validated"] == 2
        assert metrics["n_recommended_downgrades"] == 1

        recon = reconcile_dataflow_validation(results_by_id)
        assert recon["n_hard_downgrades"] == 1
        assert recon["n_soft_downgrades"] == 0

        # Final state: real one preserved, FP downgraded
        assert results_by_id["F-real"]["is_exploitable"] is True
        assert results_by_id["F-fp"]["is_exploitable"] is False
        assert results_by_id["F-fp"]["is_exploitable_pre_validation"] is True

    def test_consensus_disagreement_triggers_soft_downgrade(self, tmp_path):
        """When consensus said agreed but validation refuted, soft path applies."""
        from packages.hypothesis_validation.adapters.base import ToolEvidence

        repo, out_dir, db = _build_target_and_db(tmp_path)
        findings, results_by_id = _findings_and_analyses()
        findings = [f for f in findings if f["finding_id"] == "F-fp"]
        # Simulate that consensus also said "agreed" — disputes the validation
        results_by_id = {"F-fp": dict(results_by_id["F-fp"])}
        results_by_id["F-fp"]["consensus"] = "agreed"

        # Tier 1 + Tier 2 both return no matches → Tier 2 refutes.
        empty_evidence = ToolEvidence(
            tool="codeql", rule="<gen>", success=True,
            matches=[], summary="no matches",
        )

        llm = MagicMock()
        llm.generate_structured.return_value = {
            "source_predicate_body": "n instanceof X",
            "sink_predicate_body": "exists(Call c)",
            "expected_evidence": "...", "reasoning": "...",
        }

        with patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.is_available",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.run",
            return_value=empty_evidence,
        ), patch(
            "packages.llm_analysis.dataflow_validation.DispatchClient",
            return_value=llm,
        ):
            run_validation_pass(
                findings=findings,
                results_by_id=results_by_id,
                out_dir=out_dir,
                repo_path=repo,
                dispatch_fn=MagicMock(),
                analysis_model=None,
                role_resolution={},
                dispatch_mode="external_llm",
                cost_tracker=None,
            )

        recon = reconcile_dataflow_validation(results_by_id)

        # Soft downgrade: keep is_exploitable=True, lower confidence
        assert recon["n_hard_downgrades"] == 0
        assert recon["n_soft_downgrades"] == 1
        assert results_by_id["F-fp"]["is_exploitable"] is True
        assert results_by_id["F-fp"]["confidence"] == "low"
        assert results_by_id["F-fp"]["validation_disputed"] is True
        assert "consensus" in results_by_id["F-fp"]["validation_disputed_by"]
