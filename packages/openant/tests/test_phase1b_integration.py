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


class TestOpenantOnlyReachesPhase1b(unittest.TestCase):
    """--openant-only must count as an enabled scanner: the
    "no scanners enabled" guard used to exit 2 before the OpenAnt
    phase was ever reached (the flag only worked combined with
    --sarif)."""

    def test_guard_exempts_openant_only(self):
        src = (Path(__file__).parents[3] / "raptor_agentic.py").read_text()
        self.assertIn(
            "if not skip_scan and not _openant_only "
            "and not (run_semgrep or run_codeql):",
            src,
            "the no-scanners guard must exempt --openant-only",
        )

    def test_openant_only_invocation_reaches_openant_phase(self):
        """Real invocation shape: --repo <dir> --openant-only must get
        past the guard and print the OpenAnt phase banner (the fake
        core then fails the subprocess, which is fine — the guard bug
        exited 2 before the phase banner). The fake core is not the
        pinned checkout, so the flag surface needs the explicit
        --openant-core-unpinned consent."""
        import os
        import subprocess
        repo_root = Path(__file__).parents[3]
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "src"
            src_dir.mkdir()
            (src_dir / "app.py").write_text("import os\n")
            fake_core = Path(td) / "openant-core" / "core"
            fake_core.mkdir(parents=True)
            (fake_core / "scanner.py").touch()
            out_dir = Path(td) / "out"
            proc = subprocess.run(
                [sys.executable, str(repo_root / "raptor_agentic.py"),
                 "--repo", str(src_dir), "--openant-only",
                 "--openant-core", str(fake_core.parent),
                 "--openant-core-unpinned",
                 "--out", str(out_dir)],
                capture_output=True, text=True, timeout=300,
                cwd=str(repo_root),
                env={**os.environ, "_RAPTOR_TRUSTED": "1"},
            )
            combined = proc.stdout + proc.stderr
            self.assertNotIn("nothing to scan", combined)
            self.assertIn("OPENANT SEMANTIC SCAN", combined)


class TestOpenantCoreConsentGate(unittest.TestCase):
    """--openant-core is pre-approved launcher argv — without a gate
    it is prompt-free arbitrary code execution (the named directory's
    Python runs with network access and the API key). A non-pinned
    core passed by FLAG must refuse at startup unless consented; the
    env / auto-detect default keeps warn-not-refuse."""

    @staticmethod
    def _fake_core(td: Path) -> Path:
        fake_core = td / "openant-core" / "core"
        fake_core.mkdir(parents=True)
        (fake_core / "scanner.py").touch()
        return fake_core.parent

    def test_unconsented_unpinned_core_flag_refuses(self):
        import os
        import subprocess
        repo_root = Path(__file__).parents[3]
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "src"
            src_dir.mkdir()
            (src_dir / "app.py").write_text("import os\n")
            core = self._fake_core(Path(td))
            proc = subprocess.run(
                [sys.executable, str(repo_root / "raptor_agentic.py"),
                 "--repo", str(src_dir), "--openant-only",
                 "--openant-core", str(core),
                 "--out", str(Path(td) / "out")],
                capture_output=True, text=True, timeout=300,
                cwd=str(repo_root),
                env={**os.environ, "_RAPTOR_TRUSTED": "1"},
            )
            combined = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 2, combined)
            self.assertNotIn("OPENANT SEMANTIC SCAN", combined)
            # The refusal names the risk and every escape hatch.
            self.assertIn("refusing --openant-core", combined)
            self.assertIn("--openant-core-unpinned", combined)
            self.assertIn("/project trust config", combined)
            # Refused at startup: no run directory left behind.
            self.assertFalse((Path(td) / "out").exists())

    def test_standalone_surface_refuses_too(self):
        import os
        import subprocess
        repo_root = Path(__file__).parents[3]
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "src"
            src_dir.mkdir()
            (src_dir / "app.py").write_text("import os\n")
            core = self._fake_core(Path(td))
            proc = subprocess.run(
                [sys.executable, str(repo_root / "raptor_openant.py"),
                 "--repo", str(src_dir),
                 "--openant-core", str(core),
                 "--out", str(Path(td) / "out")],
                capture_output=True, text=True, timeout=300,
                cwd=str(repo_root),
                env={**os.environ, "_RAPTOR_TRUSTED": "1"},
            )
            self.assertEqual(proc.returncode, 2,
                             proc.stdout + proc.stderr)
            self.assertIn("refusing --openant-core",
                          proc.stdout + proc.stderr)

    def test_env_core_is_not_gated(self):
        """The env-var default keeps warn-not-refuse: only the argv
        flag is the consent-gated surface."""
        from packages.openant import scanner
        src = (Path(__file__).parents[3] / "raptor_openant.py").read_text()
        self.assertIn("openant_core_explicit", src)
        # Gate helper refuses without consent, passes with it.
        with tempfile.TemporaryDirectory() as td:
            core = self._fake_core(Path(td))
            with self.assertRaises(scanner.OpenAntCoreConsentError):
                with self.assertLogs("raptor", level="WARNING"):
                    scanner.enforce_core_consent(
                        core, consented=False, target_path=td)
            with self.assertLogs("raptor", level="WARNING"):
                prov = scanner.enforce_core_consent(
                    core, consented=True, target_path=td)
            self.assertIsNone(prov["matches"])

    def test_config_trust_marker_grants_standing_consent(self):
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            core = self._fake_core(Path(td))
            with mock.patch("core.project.trust.resolve_repo_trust",
                            return_value=True):
                with self.assertLogs("raptor", level="WARNING"):
                    prov = scanner.enforce_core_consent(
                        core, consented=False, target_path=td)
            self.assertIsNone(prov["matches"])

    # -- content truth: HEAD == pin alone is not consent -------------

    @staticmethod
    def _pinned_repo(td: Path) -> tuple[Path, Path, str]:
        """A real clone shape at the documented layout: returns
        (repo, core_path, head). Callers patch the pin to head."""
        import os
        import subprocess
        repo = td / "OpenAnt"
        core = repo / "libs" / "openant-core"
        (core / "core").mkdir(parents=True)
        (core / "core" / "scanner.py").write_text("legit = True\n")
        env = {**os.environ,
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"],
                    ["git", "commit", "-q", "-m", "x"]):
            subprocess.run(cmd, cwd=repo, env=env, check=True,
                           capture_output=True)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
            capture_output=True, text=True).stdout.strip().lower()
        return repo, core, head

    def test_tampered_tracked_file_at_pinned_head_refuses(self):
        """A vendored clone AT the pinned HEAD with a tampered tracked
        file must refuse unconsented (a matching HEAD is content-blind
        to on-disk edits) and run consented WITH the deviation
        warning."""
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            (core / "core" / "scanner.py").write_text("tampered = True\n")
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)
                with self.assertLogs("raptor", level="WARNING") as cm:
                    prov = scanner.enforce_core_consent(
                        core, consented=True, target_path=td)
            self.assertIs(prov["matches"], True)
            self.assertEqual(prov["worktree_deviations"],
                             {"modified": 1, "untracked": 0})
            self.assertTrue(any("DEVIATES" in m for m in cm.output))

    def test_untracked_shadow_at_pinned_head_refuses(self):
        """An untracked stdlib-shadow module in a pinned-HEAD clone
        must refuse unconsented — even when a hostile .gitignore hides
        it from default status listings (ignored files count)."""
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            (core / "core" / "json.py").write_text("shadow = True\n")
            (repo / ".gitignore").write_text("json.py\n.gitignore\n")
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)
                with self.assertLogs("raptor", level="WARNING") as cm:
                    prov = scanner.enforce_core_consent(
                        core, consented=True, target_path=td)
            self.assertIs(prov["matches"], True)
            self.assertEqual(prov["worktree_deviations"],
                             {"modified": 0, "untracked": 2})
            self.assertTrue(any("DEVIATES" in m for m in cm.output))

    def test_staged_shadow_at_pinned_head_refuses(self):
        """A hostile archive can ship .git/index with the shadow
        module pre-staged (`git add -f`): staged files are invisible
        to HEAD's tree AND to index-derived untracked listings, so an
        index-trusting survey reports 0/0. The index is not in the
        trust base — anything on disk that is not in HEAD's tree
        counts as untracked regardless of index state."""
        import subprocess
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            (core / "core" / "json.py").write_text("shadow = True\n")
            subprocess.run(
                ["git", "add", "-f", "libs/openant-core/core/json.py"],
                cwd=repo, check=True, capture_output=True)
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)
                with self.assertLogs("raptor", level="WARNING") as cm:
                    prov = scanner.enforce_core_consent(
                        core, consented=True, target_path=td)
            self.assertIs(prov["matches"], True)
            self.assertEqual(prov["worktree_deviations"],
                             {"modified": 0, "untracked": 1})
            self.assertTrue(any("DEVIATES" in m for m in cm.output))

    def test_clean_pinned_clone_is_quiet_and_runs(self):
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                with self.assertNoLogs("raptor", level="WARNING"):
                    prov = scanner.enforce_core_consent(
                        core, consented=False, target_path=td)
            self.assertIs(prov["matches"], True)
            self.assertIs(prov["worktree_clean"], True)

    def test_gate_never_executes_hostile_clone_config(self):
        """The dirty survey must not run content through git's
        status/diff machinery: on an attacker-written clone,
        filter.<name>.clean (armed via in-tree .gitattributes) and
        similar config-named commands would execute BEFORE the consent
        decision. The survey is listing plumbing + Python-side
        hashing, so the probe command must never run."""
        import subprocess
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            probe = Path(td) / "probe-executed"
            for k, v in (
                ("filter.hostile.clean", f"touch {probe}"),
                ("filter.hostile.required", "true"),
                ("core.fsmonitor", f"touch {probe}"),
            ):
                subprocess.run(["git", "config", k, v], cwd=repo,
                               check=True, capture_output=True)
            (repo / ".gitattributes").write_text("*.py filter=hostile\n")
            # .gitattributes is untracked -> the tree is dirty; both
            # gate outcomes must leave the probe untouched.
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)
                with self.assertLogs("raptor", level="WARNING"):
                    scanner.enforce_core_consent(
                        core, consented=True, target_path=td)
            self.assertFalse(probe.exists(),
                             "the gate executed a config-named command "
                             "from the hostile clone")
