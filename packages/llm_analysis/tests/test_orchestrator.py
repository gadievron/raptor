"""Tests for the orchestrator module (Phase 4 CC dispatch)."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.llm_analysis.orchestrator import (
    orchestrate,
    _invoke_cc,
    _build_finding_prompt,
    _build_schema,
    _parse_cc_result,
    _merge_results,
    _is_auth_error,
    _print_result,
    FINDING_RESULT_SCHEMA,
)


def _make_prep_report(findings=None, mode="prep_only"):
    """Create a minimal prep report dict."""
    if findings is None:
        findings = [_make_finding("finding-001", "py/sql-injection", "db.py", 42)]
    return {
        "mode": mode,
        "processed": len(findings),
        "analyzed": 0,
        "exploitable": 0,
        "results": findings,
    }


def _make_finding(finding_id, rule_id, file_path, start_line):
    """Create a minimal finding dict."""
    return {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": start_line + 3,
        "level": "error",
        "message": f"Potential {rule_id}",
        "code": "# code here",
        "surrounding_context": "# context here",
    }


def _make_cc_result(finding_id, exploitable=True, score=0.85):
    """Create a valid CC sub-agent result dict."""
    return {
        "finding_id": finding_id,
        "is_true_positive": True,
        "is_exploitable": exploitable,
        "exploitability_score": score,
        "severity_assessment": "high" if exploitable else "low",
        "reasoning": "Test reasoning",
        "attack_scenario": "Test scenario" if exploitable else None,
        "exploit_code": "# exploit" if exploitable else None,
        "patch_code": "# patch",
    }


def _mock_subprocess_ok(results_by_call):
    """Create a subprocess.run mock that returns results in order."""
    call_count = [0]

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = results_by_call[min(call_count[0], len(results_by_call) - 1)]
        result.stderr = ""
        call_count[0] += 1
        return result

    return mock_run


class TestOrchestrate:
    """Test the main orchestrate() function routing."""

    def test_full_report_passthrough(self, tmp_path):
        """mode:'full' returns None (Phase 3 already did analysis)."""
        report = _make_prep_report(mode="full")
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        result = orchestrate(
            prep_report_path=report_path,
            repo_path=tmp_path,
            out_dir=tmp_path / "orch",
        )
        assert result is None

    def test_inside_cc_still_dispatches(self, tmp_path):
        """Inside CC (CLAUDECODE=1), dispatches subprocesses like outside CC."""
        report = _make_prep_report()
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        cc_result = json.dumps(_make_cc_result("finding-001"))

        with patch.dict(os.environ, {"CLAUDECODE": "1"}), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value="/usr/bin/claude"), \
             patch("packages.llm_analysis.orchestrator.subprocess.run",
                   side_effect=_mock_subprocess_ok([cc_result])):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )

        assert result is not None
        assert result["mode"] == "orchestrated"

    def test_no_claude_binary(self, tmp_path):
        """No claude on PATH -> returns None with warning."""
        report = _make_prep_report()
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        with patch.dict(os.environ, {}, clear=True), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value=None):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )
        assert result is None

    def test_corrupt_report(self, tmp_path):
        """Corrupt JSON in Phase 3 report -> returns None."""
        report_path = tmp_path / "report.json"
        report_path.write_text("not json {{{")

        result = orchestrate(
            prep_report_path=report_path,
            repo_path=tmp_path,
            out_dir=tmp_path / "orch",
        )
        assert result is None

    def test_missing_report(self, tmp_path):
        """Missing Phase 3 report file -> returns None."""
        result = orchestrate(
            prep_report_path=tmp_path / "nonexistent.json",
            repo_path=tmp_path,
            out_dir=tmp_path / "orch",
        )
        assert result is None

    def test_dispatches_per_finding(self, tmp_path):
        """Dispatches one CC agent per finding and merges results."""
        findings = [
            _make_finding("f-001", "py/sql-injection", "db.py", 42),
            _make_finding("f-002", "js/xss", "template.js", 18),
        ]
        report = _make_prep_report(findings=findings)
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        cc_results = [
            json.dumps(_make_cc_result("f-001", exploitable=True)),
            json.dumps(_make_cc_result("f-002", exploitable=False, score=0.1)),
        ]

        with patch.dict(os.environ, {}, clear=True), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value="/usr/bin/claude"), \
             patch("packages.llm_analysis.orchestrator.subprocess.run",
                   side_effect=_mock_subprocess_ok(cc_results)):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )

        assert result is not None
        assert result["mode"] == "orchestrated"
        assert result["orchestration"]["findings_analysed"] == 2
        assert result["orchestration"]["findings_failed"] == 0
        assert result["exploitable"] == 1

        # Verify merged report was written
        out_file = tmp_path / "orch" / "orchestrated_report.json"
        assert out_file.exists()

    def test_empty_findings(self, tmp_path):
        """No findings in report -> returns None."""
        report = _make_prep_report(findings=[])
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        with patch.dict(os.environ, {}, clear=True), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value="/usr/bin/claude"):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )
        assert result is None

    def test_auth_failure_aborts_remaining(self, tmp_path):
        """Auth failure on first completed finding aborts remaining dispatch."""
        findings = [
            _make_finding("f-001", "py/sql-injection", "db.py", 42),
            _make_finding("f-002", "js/xss", "template.js", 18),
            _make_finding("f-003", "py/path-injection", "io.py", 10),
        ]
        report = _make_prep_report(findings=findings)
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        def mock_run(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            result.stderr = "Error 401 Unauthorized"
            return result

        with patch.dict(os.environ, {}, clear=True), \
             patch("packages.llm_analysis.orchestrator.shutil.which", return_value="/usr/bin/claude"), \
             patch("packages.llm_analysis.orchestrator.subprocess.run", side_effect=mock_run):
            result = orchestrate(
                prep_report_path=report_path,
                repo_path=tmp_path,
                out_dir=tmp_path / "orch",
            )

        # Should still produce a report, but with all findings failed/aborted
        assert result is not None
        assert result["orchestration"]["findings_analysed"] == 0
        assert result["orchestration"]["findings_failed"] > 0


class TestInvokeCC:
    """Test single CC sub-agent invocation."""

    def test_successful_invocation(self, tmp_path):
        """Valid JSON from claude -p is parsed correctly."""
        cc_result = _make_cc_result("f-001")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(cc_result)
        mock_proc.stderr = ""

        with patch("packages.llm_analysis.orchestrator.subprocess.run", return_value=mock_proc):
            result = _invoke_cc(
                finding=_make_finding("f-001", "py/sql-injection", "db.py", 42),
                repo_path=Path("/tmp/repo"),
                claude_bin="/usr/bin/claude",
                out_dir=tmp_path,
            )

        assert result["finding_id"] == "f-001"
        assert result["is_exploitable"] is True
        assert "error" not in result

    def test_timeout(self, tmp_path):
        """Timeout returns error dict."""
        with patch("packages.llm_analysis.orchestrator.subprocess.run",
                    side_effect=subprocess.TimeoutExpired(cmd="claude", timeout=300)):
            result = _invoke_cc(
                finding=_make_finding("f-001", "py/sql-injection", "db.py", 42),
                repo_path=Path("/tmp/repo"),
                claude_bin="/usr/bin/claude",
                out_dir=tmp_path,
            )

        assert result["finding_id"] == "f-001"
        assert "timeout" in result["error"]

    def test_nonzero_exit_writes_debug(self, tmp_path):
        """Non-zero exit returns error dict with stderr and writes debug file."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = "some partial output"
        mock_proc.stderr = "Something went wrong"

        with patch("packages.llm_analysis.orchestrator.subprocess.run", return_value=mock_proc):
            result = _invoke_cc(
                finding=_make_finding("f-001", "py/sql-injection", "db.py", 42),
                repo_path=Path("/tmp/repo"),
                claude_bin="/usr/bin/claude",
                out_dir=tmp_path,
            )

        assert "error" in result
        assert "exit code 1" in result["error"]
        assert "cc_debug_file" in result

        # Verify debug file was written
        debug_file = tmp_path / result["cc_debug_file"]
        assert debug_file.exists()
        content = debug_file.read_text()
        assert "some partial output" in content
        assert "Something went wrong" in content

    def test_command_flags(self, tmp_path):
        """Verify claude -p command includes all required flags."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(_make_cc_result("f-001"))
        mock_proc.stderr = ""

        with patch("packages.llm_analysis.orchestrator.subprocess.run", return_value=mock_proc) as mock_run:
            _invoke_cc(
                finding=_make_finding("f-001", "py/sql-injection", "db.py", 42),
                repo_path=Path("/tmp/repo"),
                claude_bin="/usr/bin/claude",
                out_dir=tmp_path,
            )

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/usr/bin/claude"
        assert "-p" in cmd
        assert "--output-format" in cmd
        assert "json" in cmd
        assert "--json-schema" in cmd
        assert "--no-session-persistence" in cmd
        assert "--allowed-tools" in cmd
        assert "--add-dir" in cmd
        assert "/tmp/repo" in cmd
        assert "--max-budget-usd" in cmd

    def test_stdin_prompt(self, tmp_path):
        """Prompt is passed via stdin, not as positional arg."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(_make_cc_result("f-001"))
        mock_proc.stderr = ""

        with patch("packages.llm_analysis.orchestrator.subprocess.run", return_value=mock_proc) as mock_run:
            _invoke_cc(
                finding=_make_finding("f-001", "py/sql-injection", "db.py", 42),
                repo_path=Path("/tmp/repo"),
                claude_bin="/usr/bin/claude",
                out_dir=tmp_path,
            )

        kwargs = mock_run.call_args[1]
        assert "input" in kwargs
        assert isinstance(kwargs["input"], str)
        assert len(kwargs["input"]) > 0


class TestBuildFindingPrompt:
    """Test prompt construction."""

    def test_includes_finding_metadata(self):
        """Prompt includes rule_id, file_path, line numbers."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        prompt = _build_finding_prompt(finding)

        assert "py/sql-injection" in prompt
        assert "db.py" in prompt
        assert "42" in prompt
        assert "f-001" in prompt

    def test_no_raw_code_in_prompt(self):
        """Prompt does NOT include raw code from the finding."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        finding["code"] = "cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
        finding["surrounding_context"] = "def get_user(uid):\n    cursor = db.cursor()\n    ..."

        prompt = _build_finding_prompt(finding)

        assert "cursor.execute" not in prompt
        assert "def get_user" not in prompt

    def test_includes_dataflow_summary(self):
        """Dataflow metadata is included (without code)."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        finding["dataflow"] = {
            "source": {"file": "routes.py", "line": 15, "label": "HTTP parameter"},
            "sink": {"file": "db.py", "line": 42, "label": "SQL query"},
            "steps": [{"file": "utils.py", "line": 20}],
            "sanitizers_found": [],
        }

        prompt = _build_finding_prompt(finding)
        assert "routes.py:15" in prompt
        assert "db.py:42" in prompt

    def test_no_exploits_flag(self):
        """--no-exploits suppresses exploit generation instructions."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)

        prompt_with = _build_finding_prompt(finding, no_exploits=False)
        prompt_without = _build_finding_prompt(finding, no_exploits=True)

        assert "proof-of-concept" in prompt_with.lower() or "exploit" in prompt_with.lower()
        assert "proof-of-concept" not in prompt_without.lower()

    def test_no_patches_flag(self):
        """--no-patches suppresses patch generation instructions."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)

        prompt_with = _build_finding_prompt(finding, no_patches=False)
        prompt_without = _build_finding_prompt(finding, no_patches=True)

        assert "secure fix" in prompt_with.lower() or "patch" in prompt_with.lower()
        assert "secure fix" not in prompt_without.lower()

    def test_includes_score_range(self):
        """Prompt mentions the 0.0-1.0 score range."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        prompt = _build_finding_prompt(finding)
        assert "0.0" in prompt and "1.0" in prompt

    def test_feasibility_framing(self):
        """Feasibility section tells agent to treat constraints as ground truth."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        finding["feasibility"] = {
            "verdict": "likely_exploitable",
            "chain_breaks": ["Full RELRO blocks GOT overwrite"],
            "what_would_help": ["Format string"],
        }

        prompt = _build_finding_prompt(finding)
        assert "ground truth" in prompt
        assert "upstream validation pipeline" in prompt
        assert "GOT overwrite" in prompt


class TestParseCCResult:
    """Test CC output parsing."""

    def test_valid_json(self):
        """Clean JSON is parsed directly."""
        result = _parse_cc_result(
            json.dumps({"finding_id": "f-001", "is_exploitable": True}),
            "", "f-001",
        )
        assert result["finding_id"] == "f-001"
        assert "error" not in result

    def test_markdown_fenced_json(self):
        """JSON wrapped in markdown fences is extracted."""
        content = "Here is the result:\n```json\n" + json.dumps({
            "finding_id": "f-001", "is_exploitable": False, "reasoning": "test"
        }) + "\n```\n"
        result = _parse_cc_result(content, "", "f-001")
        assert result["finding_id"] == "f-001"
        assert "error" not in result

    def test_empty_output(self):
        """Empty stdout returns error dict."""
        result = _parse_cc_result("", "some error", "f-001")
        assert result["finding_id"] == "f-001"
        assert "error" in result

    def test_invalid_json(self):
        """Unparseable output returns error dict."""
        result = _parse_cc_result("This is not JSON at all", "", "f-001")
        assert "error" in result

    def test_json_embedded_in_text(self):
        """JSON object embedded in surrounding text is extracted via raw_decode."""
        content = 'I found that {"finding_id": "f-001", "is_exploitable": true, "reasoning": "vuln"} is the result.'
        result = _parse_cc_result(content, "", "f-001")
        assert result["finding_id"] == "f-001"
        assert "error" not in result

    def test_multiple_json_fragments_takes_first(self):
        """With multiple JSON objects, raw_decode takes the first valid one."""
        content = 'prefix {"partial": true} and {"finding_id": "f-001", "is_exploitable": false, "reasoning": "safe"} end'
        result = _parse_cc_result(content, "", "f-001")
        # raw_decode takes the first complete JSON object from first {
        assert "error" not in result

    def test_claude_output_format_json_envelope(self):
        """claude -p --output-format json wraps result in metadata envelope."""
        envelope = json.dumps({
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": "",
            "session_id": "abc-123",
            "total_cost_usd": 0.15,
            "structured_output": {
                "finding_id": "f-001",
                "is_true_positive": True,
                "is_exploitable": True,
                "exploitability_score": 0.9,
                "reasoning": "Stack buffer overflow",
            }
        })
        result = _parse_cc_result(envelope, "", "f-001")
        assert result["finding_id"] == "f-001"
        assert result["is_exploitable"] is True
        assert result["exploitability_score"] == 0.9
        assert result["reasoning"] == "Stack buffer overflow"
        assert "session_id" not in result  # envelope fields stripped


class TestMergeResults:
    """Test merging CC results back into prep report."""

    def test_preserves_prep_data(self):
        """CC results are merged but prep data (code, dataflow) is preserved."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        finding["code"] = "original code"
        finding["has_dataflow"] = True

        report = _make_prep_report(findings=[finding])
        cc_results = [_make_cc_result("f-001")]

        merged = _merge_results(report, cc_results)

        result = merged["results"][0]
        assert result["code"] == "original code"
        assert result["has_dataflow"] is True
        assert result["exploitable"] is True
        assert result["analysis"]["reasoning"] == "Test reasoning"

    def test_does_not_mutate_original(self):
        """Merging does not mutate the original prep report."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        report = _make_prep_report(findings=[finding])
        original_mode = report["mode"]
        original_finding = report["results"][0].copy()

        cc_results = [_make_cc_result("f-001")]
        _merge_results(report, cc_results)

        # Original report should be unchanged
        assert report["mode"] == original_mode
        assert "analysis" not in report["results"][0] or report["results"][0] == original_finding

    def test_failed_finding_preserved(self):
        """Findings with CC errors keep prep data and get cc_error field."""
        report = _make_prep_report()
        cc_results = [{"finding_id": "finding-001", "error": "timeout"}]

        merged = _merge_results(report, cc_results)
        result = merged["results"][0]
        assert "cc_error" in result

    def test_failed_finding_includes_debug_path(self):
        """Failed findings with debug files include the path."""
        report = _make_prep_report()
        cc_results = [{"finding_id": "finding-001", "error": "parse error",
                       "cc_debug_file": "debug/cc_finding-001.txt"}]

        merged = _merge_results(report, cc_results)
        result = merged["results"][0]
        assert result["cc_debug_file"] == "debug/cc_finding-001.txt"

    def test_mode_set_to_orchestrated(self):
        """Merged report has mode 'orchestrated'."""
        report = _make_prep_report()
        cc_results = [_make_cc_result("finding-001")]

        merged = _merge_results(report, cc_results)
        assert merged["mode"] == "orchestrated"

    def test_no_exploits_flag_drops_exploit_code(self):
        """With no_exploits=True, exploit_code is not merged even if agent returned it."""
        finding = _make_finding("f-001", "py/sql-injection", "db.py", 42)
        report = _make_prep_report(findings=[finding])
        cc_results = [_make_cc_result("f-001", exploitable=True)]

        merged = _merge_results(report, cc_results, no_exploits=True)
        result = merged["results"][0]
        assert result["exploitable"] is True
        assert result.get("has_exploit") is not True
        assert "exploit_code" not in result
        assert merged["exploits_generated"] == 0

    def test_counters_updated(self):
        """Exploit/patch counters reflect CC results."""
        findings = [
            _make_finding("f-001", "py/sql-injection", "db.py", 42),
            _make_finding("f-002", "js/xss", "template.js", 18),
        ]
        report = _make_prep_report(findings=findings)
        cc_results = [
            _make_cc_result("f-001", exploitable=True),
            _make_cc_result("f-002", exploitable=False, score=0.1),
        ]

        merged = _merge_results(report, cc_results)
        assert merged["analyzed"] == 2
        assert merged["exploitable"] == 1
        assert merged["exploits_generated"] == 1  # Only f-001 has exploit_code
        assert merged["patches_generated"] == 2   # Both have patch_code


class TestPrintResult:
    """Test result display formatting."""

    def test_handles_float_score(self):
        """Normal float score formats correctly."""
        _print_result("f-001", {"is_exploitable": True, "exploitability_score": 0.85})

    def test_handles_none_score(self):
        """None score doesn't crash."""
        _print_result("f-001", {"is_exploitable": True, "exploitability_score": None})

    def test_handles_string_score(self):
        """String score doesn't crash."""
        _print_result("f-001", {"is_exploitable": True, "exploitability_score": "high"})

    def test_handles_missing_score(self):
        """Missing score doesn't crash."""
        _print_result("f-001", {"is_exploitable": False})


class TestIsAuthError:
    """Test auth error detection."""

    def test_detects_401(self):
        assert _is_auth_error("exit code 1: Error 401 Unauthorized") is True

    def test_detects_invalid_api_key(self):
        assert _is_auth_error("invalid api key provided") is True

    def test_detects_billing(self):
        assert _is_auth_error("billing issue: insufficient_quota") is True

    def test_ignores_normal_errors(self):
        assert _is_auth_error("timeout after 300s") is False
        assert _is_auth_error("json parse error") is False


class TestFindingResultSchema:
    """Test the output schema constant."""

    def test_schema_is_valid_json_schema(self):
        """FINDING_RESULT_SCHEMA is a valid JSON Schema object."""
        assert FINDING_RESULT_SCHEMA["type"] == "object"
        assert "properties" in FINDING_RESULT_SCHEMA
        assert "required" in FINDING_RESULT_SCHEMA
        assert "finding_id" in FINDING_RESULT_SCHEMA["required"]
        assert "reasoning" in FINDING_RESULT_SCHEMA["required"]

    def test_schema_serializable(self):
        """Schema can be serialized to JSON (for --json-schema flag)."""
        serialized = json.dumps(FINDING_RESULT_SCHEMA)
        parsed = json.loads(serialized)
        assert parsed == FINDING_RESULT_SCHEMA

    def test_score_has_range(self):
        """exploitability_score has min/max constraints."""
        score_schema = FINDING_RESULT_SCHEMA["properties"]["exploitability_score"]
        assert score_schema["minimum"] == 0
        assert score_schema["maximum"] == 1


class TestBuildSchema:
    """Test dynamic schema construction."""

    def test_default_includes_all_fields(self):
        """Default schema includes exploit_code and patch_code."""
        schema = _build_schema()
        assert "exploit_code" in schema["properties"]
        assert "patch_code" in schema["properties"]

    def test_no_exploits_removes_exploit_code(self):
        """--no-exploits removes exploit_code from schema."""
        schema = _build_schema(no_exploits=True)
        assert "exploit_code" not in schema["properties"]
        assert "patch_code" in schema["properties"]

    def test_no_patches_removes_patch_code(self):
        """--no-patches removes patch_code from schema."""
        schema = _build_schema(no_patches=True)
        assert "exploit_code" in schema["properties"]
        assert "patch_code" not in schema["properties"]

    def test_both_flags_removes_both(self):
        """Both flags remove both fields."""
        schema = _build_schema(no_exploits=True, no_patches=True)
        assert "exploit_code" not in schema["properties"]
        assert "patch_code" not in schema["properties"]

    def test_does_not_mutate_base_schema(self):
        """Building a schema doesn't mutate FINDING_RESULT_SCHEMA."""
        _build_schema(no_exploits=True, no_patches=True)
        assert "exploit_code" in FINDING_RESULT_SCHEMA["properties"]
        assert "patch_code" in FINDING_RESULT_SCHEMA["properties"]
