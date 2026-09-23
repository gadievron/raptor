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
import os
import subprocess
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


class TestCoverageManifestContainment(unittest.TestCase):
    """OpenAnt ``location.file`` values are hostile-repo-derived: an
    absolute or ``..``-bearing entry must never register out-of-repo
    paths in the run's reads-manifest."""

    @staticmethod
    def _paths(findings, repo):
        import raptor_agentic
        return raptor_agentic._openant_coverage_paths(
            {"findings": findings}, repo)

    @staticmethod
    def _finding(path):
        return {"location": {"file": path}}

    def test_in_repo_path_registers(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / "src" / "a.py").write_text("x = 1\n")
            out = self._paths([self._finding("src/a.py")], repo)
            self.assertEqual(out, [str((repo / "src" / "a.py").resolve())])

    def test_dotdot_escape_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            (base / "escape").write_text("secret\n")
            out = self._paths([self._finding("../escape")], repo)
            self.assertEqual(out, [])

    def test_absolute_path_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            outside = base / "outside.py"
            outside.write_text("x = 1\n")
            out = self._paths([self._finding(str(outside))], repo)
            self.assertEqual(out, [])

    def test_mixed_entries_keep_only_contained(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            (repo / "ok.py").write_text("x = 1\n")
            (base / "evil.py").write_text("x = 1\n")
            out = self._paths(
                [self._finding("ok.py"),
                 self._finding("../evil.py"),
                 self._finding(str(base / "evil.py")),
                 self._finding("/etc/hostname")],
                repo,
            )
            self.assertEqual(out, [str((repo / "ok.py").resolve())])

    def test_malformed_entries_do_not_void_the_batch(self):
        """Tolerance is per-entry: one hostile null-byte path or
        shape-broken finding must not raise and cost the whole batch
        its coverage registration."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            (repo / "ok.py").write_text("x = 1\n")
            out = self._paths(
                [self._finding("bad\x00null.py"),
                 {"location": "not-a-dict"},
                 "not-a-dict-entry",
                 {"location": {"file": 7}},
                 self._finding("ok.py")],
                repo,
            )
            self.assertEqual(out, [str((repo / "ok.py").resolve())])


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
    """OpenAnt (--openant / --openant-only) must count as an enabled
    scanner: the "no scanners enabled" guard used to exit 2 before the
    OpenAnt phase was ever reached (the flag only worked combined with
    --sarif)."""

    _EMPTY_SARIF = (
        '{"version": "2.1.0", "runs": [{"tool": {"driver": '
        '{"name": "test", "rules": []}}, "results": []}]}'
    )

    def test_guard_exempts_openant(self):
        src = (Path(__file__).parents[3] / "raptor_agentic.py").read_text()
        self.assertIn(
            "if not skip_scan and not _openant_enabled "
            "and not (run_semgrep or run_codeql):",
            src,
            "the no-scanners guard must exempt --openant / --openant-only",
        )

    def test_guard_message_names_openant_remedies(self):
        """The nothing-to-scan message must offer the OpenAnt flags as
        remedies, not just the CodeQL flag permutations."""
        src = (Path(__file__).parents[3] / "raptor_agentic.py").read_text()
        guard_msg = src.split("nothing to scan")[1][:400]
        self.assertIn("--openant", guard_msg)

    def _run_agentic(self, td: str, extra_args: list) -> subprocess.CompletedProcess:
        """Invoke raptor_agentic.py against a tiny repo with a stub
        openant-core whose ``openant`` module exits 3 — a
        deterministic hard scanner failure, so these tests exercise
        the guard and phase banners without any LLM analysis ever
        starting (the empty findings set ends the run at the
        no-findings gates). The stub is nested INSIDE the scanned repo
        because the scanner subprocess runs sandboxed with only the
        target and output paths mounted. The stub is not the pinned
        checkout, so the flag surface needs the explicit
        --openant-core-unpinned consent."""
        repo_root = Path(__file__).parents[3]
        src_dir = Path(td) / "src"
        src_dir.mkdir(exist_ok=True)
        (src_dir / "app.py").write_text("import os\n")
        fake_core = src_dir / "openant-core"
        (fake_core / "core").mkdir(parents=True, exist_ok=True)
        (fake_core / "core" / "scanner.py").touch()
        pkg = fake_core / "openant"
        pkg.mkdir(exist_ok=True)
        (pkg / "__init__.py").write_text("")
        (pkg / "__main__.py").write_text("import sys\nsys.exit(3)\n")
        out_dir = Path(td) / "out"
        return subprocess.run(
            [sys.executable, str(repo_root / "raptor_agentic.py"),
             "--repo", str(src_dir),
             "--openant-core", str(fake_core),
             "--openant-core-unpinned",
             "--out", str(out_dir), *extra_args],
            capture_output=True, text=True, timeout=300,
            cwd=str(repo_root),
            env={**os.environ, "_RAPTOR_TRUSTED": "1"},
        )

    def test_openant_only_invocation_reaches_openant_phase(self):
        """Real invocation shape: --repo <dir> --openant-only must get
        past the guard and print the OpenAnt phase banner (the fake
        core then fails the subprocess, which is fine — the guard bug
        exited 2 before the phase banner)."""
        with tempfile.TemporaryDirectory() as td:
            proc = self._run_agentic(td, ["--openant-only"])
            combined = proc.stdout + proc.stderr
            self.assertNotIn("nothing to scan", combined)
            self.assertIn("OPENANT SEMANTIC SCAN", combined)

    def test_sarif_also_scan_openant_only(self):
        """--sarif + --also-scan + --openant-only: skip_scan is False,
        yet OpenAnt is the enabled scanner — the run must reach BOTH
        the OpenAnt phase and the SARIF import, never the guard."""
        with tempfile.TemporaryDirectory() as td:
            sarif = Path(td) / "imported.sarif"
            sarif.write_text(self._EMPTY_SARIF)
            proc = self._run_agentic(
                td, ["--sarif", str(sarif), "--also-scan", "--openant-only"])
            combined = proc.stdout + proc.stderr
            self.assertNotIn("nothing to scan", combined)
            self.assertIn("OPENANT SEMANTIC SCAN", combined)
            self.assertIn("SARIF IMPORT", combined)

    def test_sarif_openant_only(self):
        """--sarif + --openant-only (no --also-scan): the import
        replaces the pattern-scan step and OpenAnt still runs."""
        with tempfile.TemporaryDirectory() as td:
            sarif = Path(td) / "imported.sarif"
            sarif.write_text(self._EMPTY_SARIF)
            proc = self._run_agentic(
                td, ["--sarif", str(sarif), "--openant-only"])
            combined = proc.stdout + proc.stderr
            self.assertNotIn("nothing to scan", combined)
            self.assertIn("OPENANT SEMANTIC SCAN", combined)
            self.assertIn("SARIF IMPORT", combined)

    def test_openant_only_with_codeql_only_refused(self):
        """--openant-only + --codeql-only is contradictory (two
        mutually exclusive "only" claims) — refused loudly at parse
        time, naming both flags, instead of silently dropping CodeQL."""
        with tempfile.TemporaryDirectory() as td:
            proc = self._run_agentic(td, ["--openant-only", "--codeql-only"])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("--openant-only", proc.stderr)
            self.assertIn("--codeql-only", proc.stderr)
            self.assertNotIn("OPENANT SEMANTIC SCAN", proc.stdout)

    def test_openant_only_with_codeql_refused(self):
        """--openant-only + --codeql is the same contradiction with
        the additive CodeQL flag."""
        with tempfile.TemporaryDirectory() as td:
            proc = self._run_agentic(td, ["--openant-only", "--codeql"])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("--openant-only", proc.stderr)
            self.assertIn("--codeql", proc.stderr)


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


class TestConsentGateObjectStoreForgery(unittest.TestCase):
    """The object store of an attacker-shipped clone is NOT in the
    trust base: git serves a content-substituted loose object without
    re-hashing it on read, so a tree LISTING is forgeable even when
    the commit id matches the pin. The survey must self-hash every
    object on the pin's reachability path (commit, every tree, every
    worktree blob) before trusting it — no attacker-shipped byte
    participates in the verification chain unverified."""

    _pinned_repo = staticmethod(
        TestOpenantCoreConsentGate.__dict__["_pinned_repo"].__func__)

    @staticmethod
    def _git(repo: Path, *args: str, data: bytes | None = None) -> str:
        import subprocess
        proc = subprocess.run(
            ["git", "-C", str(repo), *args], input=data,
            capture_output=True, check=True)
        return proc.stdout.decode().strip()

    def _substitute_object(self, repo: Path, victim_oid: str,
                           forged_oid: str) -> None:
        """Overwrite the loose object stored under ``victim_oid`` with
        the CONTENT of ``forged_oid`` — the exact shape git's read
        path serves without complaint and ``git fsck`` flags as a
        hash-path mismatch."""
        import shutil
        objects = repo / ".git" / "objects"
        src = objects / forged_oid[:2] / forged_oid[2:]
        dst = objects / victim_oid[:2] / victim_oid[2:]
        dst.chmod(0o644)
        shutil.copyfile(src, dst)

    def _forge_listing(self, repo: Path, filename: str,
                       hostile: bytes) -> str:
        """Write a forged single-entry tree object (``filename`` →
        blob of ``hostile``) into the store; return its oid."""
        blob = self._git(repo, "hash-object", "-w", "--stdin",
                         data=hostile)
        return self._git(
            repo, "mktree",
            data=f"100644 blob {blob}\t{filename}\n".encode())

    def test_forged_subtree_object_refuses(self):
        """THE bypass shape: a genuine pinned commit with ONE
        substituted subtree object whose forged listing matches the
        hostile on-disk files. ls-tree serves the forgery (exit 0);
        the verified walk must fail it closed and the gate must
        refuse unconsented."""
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            hostile = b"hostile = True\n"
            victim = self._git(repo, "rev-parse",
                               "HEAD:libs/openant-core/core")
            forged = self._forge_listing(repo, "scanner.py", hostile)
            self._substitute_object(repo, victim, forged)
            (core / "core" / "scanner.py").write_bytes(hostile)
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                dev = scanner._pinned_tree_deviations(core)
                # The forged listing must never present as clean.
                self.assertNotEqual(dev, {"modified": 0, "untracked": 0})
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)

    def test_forged_root_tree_object_refuses(self):
        """Same mechanism one level up: the commit's ROOT tree object
        substituted with a forged listing."""
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            hostile = b"hostile = True\n"
            victim = self._git(repo, "rev-parse", "HEAD^{tree}")
            forged = self._forge_listing(repo, "evil.py", hostile)
            self._substitute_object(repo, victim, forged)
            (repo / "evil.py").write_bytes(hostile)
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                dev = scanner._pinned_tree_deviations(core)
                self.assertNotEqual(dev, {"modified": 0, "untracked": 0})
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)

    def test_forged_commit_object_refuses(self):
        """Negative control (fail-closed at BASE too): a substituted
        COMMIT object is caught — git verifies commits on parse, and
        the walk additionally self-hashes the payload against the
        pin."""
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            # A second, hostile commit provides the forged content.
            (core / "core" / "scanner.py").write_bytes(b"hostile = True\n")
            self._git(repo, "add", "-A")
            self._git(repo, "-c", "user.name=t", "-c", "user.email=t@t",
                      "commit", "-qm", "evil")
            evil = self._git(repo, "rev-parse", "HEAD")
            self._git(repo, "reset", "-q", "--hard", head)
            (core / "core" / "scanner.py").write_bytes(b"hostile = True\n")
            self._substitute_object(repo, head, evil)
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                dev = scanner._pinned_tree_deviations(core)
                self.assertNotEqual(dev, {"modified": 0, "untracked": 0})
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)

    def test_replace_ref_cannot_redirect_survey(self):
        """``git replace`` ships in the core: a hostile
        ``refs/replace/<pin>`` must not steer the survey at hostile
        content (``core.useReplaceRefs=false`` is pinned in the
        safe-git overrides, and the self-hash would catch redirected
        payloads regardless)."""
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            (core / "core" / "scanner.py").write_bytes(b"hostile = True\n")
            self._git(repo, "add", "-A")
            self._git(repo, "-c", "user.name=t", "-c", "user.email=t@t",
                      "commit", "-qm", "evil")
            evil = self._git(repo, "rev-parse", "HEAD")
            self._git(repo, "update-ref", "HEAD", head)
            self._git(repo, "replace", "-f", head, evil)
            # Disk carries the hostile content the replacement lists.
            (core / "core" / "scanner.py").write_bytes(b"hostile = True\n")
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                dev = scanner._pinned_tree_deviations(core)
                self.assertNotEqual(dev, {"modified": 0, "untracked": 0})
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)

    def test_alternates_supplied_forged_object_refuses(self):
        """``.git/objects/info/alternates`` ships in the core too: an
        alternate store serving forged content under a genuine name
        must fail the self-hash, never the gate."""
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            hostile = b"hostile = True\n"
            victim = self._git(repo, "rev-parse",
                               "HEAD:libs/openant-core/core")
            forged = self._forge_listing(repo, "scanner.py", hostile)
            objects = repo / ".git" / "objects"
            alt = Path(td) / "altstore"
            (alt / victim[:2]).mkdir(parents=True)
            import shutil
            shutil.copyfile(objects / forged[:2] / forged[2:],
                            alt / victim[:2] / victim[2:])
            # Remove the genuine object so the alternate serves it.
            (objects / victim[:2] / victim[2:]).chmod(0o644)
            (objects / victim[:2] / victim[2:]).unlink()
            (objects / "info").mkdir(exist_ok=True)
            (objects / "info" / "alternates").write_text(f"{alt}\n")
            (core / "core" / "scanner.py").write_bytes(hostile)
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                dev = scanner._pinned_tree_deviations(core)
                self.assertNotEqual(dev, {"modified": 0, "untracked": 0})
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)

    def test_forged_loose_beside_pack_is_inert_or_caught(self):
        """Pin of an observed git behavior: with the genuine object
        PACKED, a forged loose object under the same name is not
        preferred by the read path — and even if a future git
        preferred it, the self-hash catches it. Either way the gate
        must refuse this hostile-disk shape."""
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            hostile = b"hostile = True\n"
            victim = self._git(repo, "rev-parse",
                               "HEAD:libs/openant-core/core")
            self._git(repo, "repack", "-a", "-d", "-q")
            forged = self._forge_listing(repo, "scanner.py", hostile)
            objects = repo / ".git" / "objects"
            (objects / victim[:2]).mkdir(exist_ok=True)
            import shutil
            shutil.copyfile(objects / forged[:2] / forged[2:],
                            objects / victim[:2] / victim[2:])
            (core / "core" / "scanner.py").write_bytes(hostile)
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                with self.assertRaises(scanner.OpenAntCoreConsentError):
                    with self.assertLogs("raptor", level="WARNING"):
                        scanner.enforce_core_consent(
                            core, consented=False, target_path=td)

    def test_clean_pinned_clone_with_structure_passes(self):
        """Regression direction: the verified walk accepts a genuine
        clean checkout exercising nested trees, an executable bit and
        a symlink."""
        import os
        import subprocess
        from unittest import mock
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = self._pinned_repo(Path(td))
            (repo / "bin").mkdir()
            tool = repo / "bin" / "tool.sh"
            tool.write_text("#!/bin/sh\n")
            tool.chmod(0o755)
            os.symlink("bin/tool.sh", repo / "tool-link")
            env = {**os.environ,
                   "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
            for cmd in (["git", "add", "-A"],
                        ["git", "commit", "-qm", "structure"]):
                subprocess.run(cmd, cwd=repo, env=env, check=True,
                               capture_output=True)
            head2 = self._git(repo, "rev-parse", "HEAD")
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head2):
                self.assertEqual(scanner._pinned_tree_deviations(core),
                                 {"modified": 0, "untracked": 0})
                prov = scanner.enforce_core_consent(
                    core, consented=False, target_path=td)
            self.assertIs(prov["worktree_clean"], True)


class TestAgenticOpenantFailureRecordPersisted(unittest.TestCase):
    """Phase 1b failures must leave a PERSISTED record, not just a
    stderr line: a hard failure beside a successful pattern scan let
    the run complete with scan_metrics.openant carrying only
    core_provenance, and in-process (post-subprocess) failures never
    set openant_hard_error, so sole-scanner runs failed with the
    wrong reason ("no SARIF files generated from scanning")."""

    def setUp(self):
        self.src = (Path(__file__).parents[3]
                    / "raptor_agentic.py").read_text()

    def test_subprocess_failure_is_recorded_in_metrics(self):
        self.assertIn('openant_metrics["error"] = _oa_err', self.src)
        self.assertIn('openant_metrics["hard_error"] = True', self.src)

    def test_not_configured_skip_is_recorded(self):
        self.assertIn(
            'openant_metrics["error"] = f"not configured: {e}"', self.src)

    def test_in_process_failure_sets_hard_error_for_the_exit_gate(self):
        """The blanket except must set openant_hard_error so the
        sole-scanner gate names the OpenAnt failure."""
        blanket = self.src.split(
            "OpenAnt scan failed (continuing)")[0].rsplit(
            "except Exception as e:", 1)[1]
        self.assertIn("openant_hard_error = sanitise_for_terminal",
                      blanket)
        self.assertIn('openant_metrics["hard_error"] = True', blanket)


class TestAgenticOpenantHardFailure(unittest.TestCase):
    """Phase 1b distinguishes an attempted-and-failed OpenAnt scan
    (hard_error) from a not-configured skip, and a hard failure of the
    run's only possible finding source fails the run with the real
    reason instead of ending as if the target scanned clean."""

    _run_agentic = TestOpenantOnlyReachesPhase1b._run_agentic
    _EMPTY_SARIF = TestOpenantOnlyReachesPhase1b._EMPTY_SARIF

    def test_sole_scanner_hard_failure_fails_run_with_reason(self):
        with tempfile.TemporaryDirectory() as td:
            proc = self._run_agentic(td, ["--openant-only"])
            combined = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("OpenAnt scan failed", combined)
            self.assertNotIn("OpenAnt unavailable", combined)
            self.assertIn("no other scan results", combined)

    def test_hard_failure_beside_imported_sarif_continues(self):
        """Another finding source exists (--sarif import): the run
        continues past Phase 1b with the failed wording — the eventual
        no-findings exit is the import gate, not the OpenAnt one."""
        with tempfile.TemporaryDirectory() as td:
            sarif = Path(td) / "imported.sarif"
            sarif.write_text(self._EMPTY_SARIF)
            proc = self._run_agentic(
                td, ["--sarif", str(sarif), "--openant-only"])
            combined = proc.stdout + proc.stderr
            self.assertIn("OpenAnt scan failed", combined)
            self.assertNotIn("OpenAnt unavailable", combined)
            self.assertIn("SARIF IMPORT", combined)
            self.assertNotIn("no other scan results", combined)
