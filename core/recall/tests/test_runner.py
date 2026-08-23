"""Runner: argv construction, sentinel parsing, collection, sha gate."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.recall.manifest import (
    ExpectedFinding,
    Provenance,
    RecallManifest,
    Tolerance,
)
from core.recall.runner import (
    RunnerError,
    build_pipeline_argv,
    collect_findings,
    run_pipeline,
    verify_pinned_clone,
)

_PROV = Provenance(kind="benchmark", suite="s", case="c")


def _manifest(profile="scan", build_command=None) -> RecallManifest:
    return RecallManifest(
        name="fixture", repo_url="https://example.org/r",
        pinned_sha="b06d6efaebd577a327514364951916e7df3290b4",
        local_path="out/f", language="java", profile=profile,
        expected=[ExpectedFinding(id="e", file="a.java", cwe="CWE-78",
                                  provenance=_PROV)],
        build_command=build_command, tolerance=Tolerance(),
    )


def _sarif(results, tool="semgrep") -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "rules": []}},
            "results": results,
        }],
    }


def _result(file="src/A.java", line=10, rule="r1"):
    return {
        "ruleId": rule,
        "message": {"text": "m"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": file},
                "region": {"startLine": line},
            }
        }],
    }


class TestArgv:
    def test_scan_profile(self, tmp_path):
        argv = build_pipeline_argv(_manifest("scan"), tmp_path / "t",
                                   tmp_path)
        assert argv[0] == sys.executable
        assert argv[1].endswith("raptor.py")
        assert argv[2] == "scan"
        assert "--codeql" not in argv

    def test_scan_codeql_profile(self, tmp_path):
        argv = build_pipeline_argv(_manifest("scan-codeql"),
                                   tmp_path / "t", tmp_path)
        assert argv[2] == "scan" and "--codeql" in argv

    def test_agentic_profile(self, tmp_path):
        argv = build_pipeline_argv(_manifest("agentic"), tmp_path / "t",
                                   tmp_path)
        assert argv[2] == "agentic"

    def test_build_command_threaded(self, tmp_path):
        argv = build_pipeline_argv(
            _manifest("scan", build_command="make -j2"),
            tmp_path / "t", tmp_path)
        assert argv[argv.index("--build-command") + 1] == "make -j2"

    def test_codeql_build_command_carries_language(self, tmp_path):
        # The CodeQL agent errors on --build-command without exactly
        # one --languages (observed live on the OWASP baseline run).
        argv = build_pipeline_argv(
            _manifest("scan-codeql", build_command="mvn package"),
            tmp_path / "t", tmp_path)
        assert argv[argv.index("--languages") + 1] == "java"
        argv = build_pipeline_argv(
            _manifest("scan", build_command="mvn package"),
            tmp_path / "t", tmp_path)
        assert "--languages" not in argv

    def test_pipeline_out_pins_output_dir(self, tmp_path):
        # Hermeticity: without an explicit --out the lifecycle attaches
        # to the operator's active project when the target path matches
        # — a measurement run must never do that.
        out = tmp_path / "run" / "pipeline-run"
        argv = build_pipeline_argv(_manifest("scan"), tmp_path / "t",
                                   tmp_path, pipeline_out=out)
        assert argv[argv.index("--out") + 1] == str(out)


class TestRunPipeline:
    def _proc(self, stdout="", rc=0):
        return SimpleNamespace(stdout=stdout, stderr="", returncode=rc)

    def test_sentinel_parsed_and_log_written(self, tmp_path):
        out = tmp_path / "run_out"
        out.mkdir()
        log = tmp_path / "pipeline.log"
        with patch("core.recall.runner.subprocess.run",
                   return_value=self._proc(f"noise\nOUTPUT_DIR={out}\n")):
            got = run_pipeline(_manifest(), tmp_path / "t", tmp_path, log)
        assert got == out
        assert "OUTPUT_DIR" in log.read_text(encoding="utf-8")

    def test_missing_sentinel_errors(self, tmp_path):
        log = tmp_path / "pipeline.log"
        with patch("core.recall.runner.subprocess.run",
                   return_value=self._proc("no sentinel here", rc=3)), \
             pytest.raises(RunnerError, match="OUTPUT_DIR"):
            run_pipeline(_manifest(), tmp_path / "t", tmp_path, log)

    def test_pinned_dir_with_sarifs_beats_divergent_sentinel(
            self, tmp_path, caplog):
        # The lifecycle sentinel can point at a project dir even when
        # a forwarded --out carried the artifacts elsewhere; score the
        # dir that actually holds SARIFs.
        log = tmp_path / "pipeline.log"
        pinned = log.parent / "pipeline-run"
        pinned.mkdir()
        (pinned / "combined.sarif").write_text('{"runs": []}',
                                               encoding="utf-8")
        elsewhere = tmp_path / "project_dir"
        elsewhere.mkdir()
        with patch("core.recall.runner.subprocess.run",
                   return_value=self._proc(f"OUTPUT_DIR={elsewhere}\n")):
            got = run_pipeline(_manifest(), tmp_path / "t", tmp_path, log)
        assert got == pinned
        assert "diverges" in caplog.text

    def test_nonzero_exit_with_dir_still_scores(self, tmp_path, caplog):
        out = tmp_path / "run_out"
        out.mkdir()
        with patch("core.recall.runner.subprocess.run",
                   return_value=self._proc(f"OUTPUT_DIR={out}\n", rc=1)):
            got = run_pipeline(_manifest(), tmp_path / "t", tmp_path,
                               tmp_path / "l.log")
        assert got == out

    def test_llm_profile_warns(self, tmp_path, caplog):
        out = tmp_path / "run_out"
        out.mkdir()
        with patch("core.recall.runner.subprocess.run",
                   return_value=self._proc(f"OUTPUT_DIR={out}\n")), \
             caplog.at_level("WARNING"):
            run_pipeline(_manifest("agentic"), tmp_path / "t", tmp_path,
                         tmp_path / "l.log")
        assert any("LLM" in r.message for r in caplog.records)


class TestVerifyPinnedClone:
    def test_missing_clone_offline_friendly(self, tmp_path):
        with pytest.raises(RunnerError) as exc:
            verify_pinned_clone(_manifest(), tmp_path)
        assert "git clone" in str(exc.value)

    def test_wrong_sha_refused(self, tmp_path):
        clone = tmp_path / "out" / "f"
        clone.mkdir(parents=True)
        with patch("core.recall.runner.subprocess.run",
                   return_value=SimpleNamespace(
                       stdout="0000000000000000000000000000000000000000\n",
                       stderr="", returncode=0)), \
             pytest.raises(RunnerError, match="labels are invalid"):
            verify_pinned_clone(_manifest(), tmp_path)

    def test_pinned_sha_accepted(self, tmp_path):
        clone = tmp_path / "out" / "f"
        clone.mkdir(parents=True)
        with patch("core.recall.runner.subprocess.run",
                   return_value=SimpleNamespace(
                       stdout="b06d6efaebd577a327514364951916e7df3290b4\n",
                       stderr="", returncode=0)):
            assert verify_pinned_clone(_manifest(), tmp_path) == clone


class TestCollectFindings:
    def test_parses_all_sarifs(self, tmp_path):
        (tmp_path / "semgrep_x.sarif").write_text(
            json.dumps(_sarif([_result(line=10)])), encoding="utf-8")
        (tmp_path / "codeql_java.sarif").write_text(
            json.dumps(_sarif([_result(line=20, rule="r2")],
                              tool="codeql")), encoding="utf-8")
        got = collect_findings(tmp_path)
        assert len(got) == 2
        assert {f["tool"] for f in got} == {"semgrep", "codeql"}

    def test_combined_preferred_when_present(self, tmp_path):
        (tmp_path / "combined.sarif").write_text(
            json.dumps(_sarif([_result(line=10)])), encoding="utf-8")
        (tmp_path / "semgrep_x.sarif").write_text(
            json.dumps(_sarif([_result(line=10)])), encoding="utf-8")
        assert len(collect_findings(tmp_path)) == 1

    def test_dedup_on_tool_rule_file_line(self, tmp_path):
        dup = _sarif([_result(line=10), _result(line=10)])
        (tmp_path / "semgrep_x.sarif").write_text(json.dumps(dup),
                                                  encoding="utf-8")
        assert len(collect_findings(tmp_path)) == 1

    def test_empty_dir(self, tmp_path):
        assert collect_findings(tmp_path) == []
