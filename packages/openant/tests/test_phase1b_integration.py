"""Tests for OpenAnt integration into the agentic pipeline.

Architecture: OpenAnt findings flow through the standard validation pipeline
via run_validation_phase(openant_findings_path=...) — the same path SCA uses.
The validation phase converts OpenAnt findings to the pipeline's finding format
via _convert_openant_findings() and merges them into the dedup pipeline.

These tests verify:
1. The converter produces the right schema (unit tests of _convert_openant_findings)
2. The agentic pipeline declares the OpenAnt flags and phase block (static checks)
3. The validation phase accepts and merges OpenAnt findings (integration tests)
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[4]))  # repo root


class TestOpenAntFindingsConverter(unittest.TestCase):
    """Unit tests for _convert_openant_findings in the validation pipeline."""

    def _write_findings(self, out_dir, findings):
        path = out_dir / "openant_findings.json"
        path.write_text(json.dumps(findings))
        return path

    def test_converts_basic_finding(self):
        from packages.exploitability_validation.agentic import (
            _convert_openant_findings,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_findings(Path(tmp), [
                {
                    "finding_id": "openant:VULN-001",
                    "rule_id": "openant/CWE-78",
                    "file": "src/app.py",
                    "startLine": None,
                    "level": "error",
                    "message": "OS command injection",
                    "snippet": "os.system(cmd)",
                    "cwe_id": "CWE-78",
                    "tool": "openant",
                    "has_dataflow": False,
                    "metadata": {
                        "function": "run_cmd",
                        "stage1_verdict": "vulnerable",
                        "stage2_verdict": "confirmed",
                        "openant_id": "VULN-001",
                        "vuln_name": "OS Command Injection",
                        "attack_vector": "user input",
                    },
                }
            ])
            result = _convert_openant_findings(path)
            self.assertEqual(len(result), 1)
            f = result[0]
            self.assertEqual(f["id"], "openant:VULN-001")
            self.assertEqual(f["source_type"], "semantic")
            self.assertEqual(f["severity"], "high")
            self.assertEqual(f["tool"], "openant")
            self.assertEqual(f["file"], "src/app.py")
            self.assertEqual(f["openant"]["function"], "run_cmd")
            self.assertEqual(f["openant"]["stage1_verdict"], "vulnerable")

    def test_converter_sets_toplevel_function_for_oracle(self):
        """The binary oracle and reachability chokepoint read
        ``finding["function"]``, not ``finding["openant"]["function"]``.
        The converter must set the top-level key so the oracle can
        suppress absent-function findings."""
        from packages.exploitability_validation.agentic import (
            _convert_openant_findings,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_findings(Path(tmp), [
                {
                    "finding_id": "openant:VULN-010",
                    "rule_id": "openant/CWE-89",
                    "file": "src/db.py",
                    "level": "warning",
                    "message": "SQL injection",
                    "metadata": {"function": "query_user"},
                }
            ])
            result = _convert_openant_findings(path)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["function"], "query_user")
            self.assertEqual(result[0]["rule_id"], "openant/CWE-89")

    def test_severity_mapping(self):
        from packages.exploitability_validation.agentic import (
            _openant_level_to_severity,
        )
        self.assertEqual(_openant_level_to_severity("error"), "high")
        self.assertEqual(_openant_level_to_severity("warning"), "medium")
        self.assertEqual(_openant_level_to_severity("note"), "low")
        self.assertEqual(_openant_level_to_severity("unknown"), "medium")

    def test_empty_file_returns_empty(self):
        from packages.exploitability_validation.agentic import (
            _convert_openant_findings,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_findings(Path(tmp), [])
            result = _convert_openant_findings(path)
            self.assertEqual(result, [])

    def test_dict_wrapper_format(self):
        """Handles both plain list and {"findings": [...]} format."""
        from packages.exploitability_validation.agentic import (
            _convert_openant_findings,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_findings(Path(tmp), {
                "findings": [
                    {"finding_id": "openant:V1", "file": "a.py",
                     "level": "warning", "metadata": {}},
                ],
            })
            result = _convert_openant_findings(path)
            self.assertEqual(len(result), 1)

    def test_missing_metadata_handled(self):
        from packages.exploitability_validation.agentic import (
            _convert_openant_findings,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_findings(Path(tmp), [
                {"finding_id": "openant:V1", "file": "a.py", "level": "note"},
            ])
            result = _convert_openant_findings(path)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["openant"]["function"], "")


class TestValidationPhaseMergesOpenant(unittest.TestCase):
    """Integration: run_validation_phase accepts openant_findings_path."""

    def test_openant_merged_count_in_result(self):
        from core.json import save_json
        from packages.exploitability_validation.agentic import (
            run_validation_phase,
        )
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            # Create a minimal SARIF file
            sarif = {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [{
                    "tool": {"driver": {"name": "test", "rules": []}},
                    "results": [{
                        "ruleId": "test/CWE-79",
                        "level": "error",
                        "message": {"text": "XSS"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app.py"},
                                "region": {"startLine": 10},
                            }
                        }],
                    }],
                }],
            }
            sarif_path = out_dir / "test.sarif"
            save_json(sarif_path, sarif)

            # Create OpenAnt findings
            openant_path = out_dir / "openant_findings.json"
            save_json(openant_path, [
                {
                    "finding_id": "openant:V1",
                    "file": "auth.py",
                    "level": "error",
                    "message": "Auth bypass",
                    "metadata": {"function": "login"},
                },
            ])

            result, count = run_validation_phase(
                repo_path="/tmp/test-repo",
                out_dir=out_dir,
                sarif_files=[sarif_path],
                total_findings=1,
                openant_findings_path=openant_path,
            )
            self.assertTrue(result.get("completed"))
            self.assertEqual(result.get("openant_merged"), 1)
            self.assertGreaterEqual(count, 2)  # 1 SARIF + 1 OpenAnt


class TestAgenticPipelineStaticChecks(unittest.TestCase):
    """Static checks that the agentic pipeline has the OpenAnt integration wired."""

    @classmethod
    def setUpClass(cls):
        cls.agentic_py = Path(__file__).parents[3] / "raptor_agentic.py"
        cls.src = cls.agentic_py.read_text()

    def test_phase1b_block_present(self):
        self.assertIn("PHASE 1b: OPENANT SEMANTIC SCAN", self.src)

    def test_openant_findings_variable(self):
        self.assertIn("openant_findings", self.src)

    def test_openant_findings_count_in_metrics(self):
        self.assertIn("openant_findings_count", self.src)

    def test_openant_in_scan_metrics(self):
        self.assertIn("'openant': openant_metrics", self.src)

    def test_openant_findings_path_passed_to_validation(self):
        self.assertIn("openant_findings_path", self.src)

    def test_no_post_validation_merge_hack(self):
        """The old post-validation merge of openant_extra_findings should be gone."""
        self.assertNotIn("openant_extra_findings", self.src)
        self.assertNotIn(
            "Merge OpenAnt findings into validation output",
            self.src,
        )


class TestAgenticOpeantonlySkipsSarif(unittest.TestCase):
    """--openant-only must not crash on missing SARIF files."""

    @classmethod
    def setUpClass(cls):
        cls.agentic_py = Path(__file__).parents[3] / "raptor_agentic.py"
        cls.src = cls.agentic_py.read_text()

    def test_sarif_exit_gate_checks_openant(self):
        """The 'no SARIF files' exit gate must also check openant_findings_count."""
        self.assertIn(
            "not openant_findings_count",
            self.src,
            "SARIF exit gate must be bypassed when OpenAnt produced findings",
        )


class TestCoverageTrackingIntegration(unittest.TestCase):
    """Phase 1b must register OpenAnt-analysed files with the coverage system."""

    @classmethod
    def setUpClass(cls):
        cls.agentic_py = Path(__file__).parents[3] / "raptor_agentic.py"
        cls.src = cls.agentic_py.read_text()

    def test_coverage_manifest_append_in_phase1b(self):
        self.assertIn(".reads-manifest", self.src)

    def test_coverage_resolves_to_absolute(self):
        self.assertIn("original_repo_path / rel", self.src)


class TestSageHandlesFunctionLevelFindings(unittest.TestCase):
    """SAGE verdict storage must work for line=0 (function-level) findings."""

    def test_line_zero_guard_relaxed(self):
        """The analysis agent must accept _line >= 0, not just > 0."""
        agent_py = Path(__file__).parents[3] / "packages" / "llm_analysis" / "agent.py"
        src = agent_py.read_text()
        self.assertIn("_line >= 0", src)

    def test_line_zero_uses_file_hash(self):
        agent_py = Path(__file__).parents[3] / "packages" / "llm_analysis" / "agent.py"
        src = agent_py.read_text()
        self.assertIn("sha256_string", src)


if __name__ == "__main__":
    unittest.main()
