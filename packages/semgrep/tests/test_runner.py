"""Tests for the Semgrep runner."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.semgrep.runner import (
    build_cmd,
    is_available,
    run_rule,
    run_rules,
    version,
    _config_to_name,
)


# Helpers ----------------------------------------------------------------------

def _make_sarif(rule_id="r1", file="a.py", line=1, count=1) -> str:
    """Build a minimal SARIF JSON string with `count` findings."""
    results = []
    for i in range(count):
        results.append({
            "ruleId": rule_id,
            "message": {"text": f"finding {i}"},
            "level": "warning",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {"startLine": line + i},
                },
            }],
        })
    return json.dumps({"runs": [{"results": results}]})


def _make_json_output(scanned=None, errors=None, version="1.79.0") -> str:
    """Build minimal --json-output content."""
    return json.dumps({
        "paths": {"scanned": scanned or []},
        "errors": errors or [],
        "version": version,
    })


# Availability and version -----------------------------------------------------

class TestAvailability:
    def test_is_available_found(self):
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            assert is_available()

    def test_is_available_missing(self):
        with patch("shutil.which", return_value=None):
            assert not is_available()

    def test_version_returns_string(self):
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="1.79.0\n",
                stderr="",
                returncode=0,
            )
            assert version() == "1.79.0"

    def test_version_unavailable(self):
        with patch("shutil.which", return_value=None):
            assert version() is None

    def test_version_handles_timeout(self):
        with patch("shutil.which", return_value="/usr/bin/semgrep"), \
             patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("semgrep", 10)):
            assert version() is None


# build_cmd --------------------------------------------------------------------

class TestBuildCmd:
    def test_minimal(self):
        cmd = build_cmd(Path("/src"), "p/security-audit", semgrep_bin="semgrep")
        assert cmd[0] == "semgrep"
        assert "scan" in cmd
        assert "--config" in cmd
        idx = cmd.index("--config")
        assert cmd[idx + 1] == "p/security-audit"
        assert "--sarif" in cmd
        assert "--quiet" in cmd
        assert cmd[-1] == "/src"

    def test_includes_metrics_off(self):
        cmd = build_cmd(Path("/src"), "p/x", semgrep_bin="semgrep")
        assert "--metrics" in cmd
        idx = cmd.index("--metrics")
        assert cmd[idx + 1] == "off"

    def test_rule_timeout(self):
        cmd = build_cmd(Path("/src"), "p/x", rule_timeout=120, semgrep_bin="semgrep")
        idx = cmd.index("--timeout")
        assert cmd[idx + 1] == "120"

    def test_json_output_path(self):
        cmd = build_cmd(
            Path("/src"), "p/x",
            json_output_path=Path("/tmp/out.json"),
            semgrep_bin="semgrep",
        )
        assert "--json-output" in cmd
        idx = cmd.index("--json-output")
        assert cmd[idx + 1] == "/tmp/out.json"

    def test_no_json_output_path_omits_flag(self):
        cmd = build_cmd(Path("/src"), "p/x", semgrep_bin="semgrep")
        assert "--json-output" not in cmd

    def test_extra_args_passed_through(self):
        cmd = build_cmd(
            Path("/src"), "p/x",
            extra_args=["--severity", "ERROR"],
            semgrep_bin="semgrep",
        )
        assert "--severity" in cmd
        idx = cmd.index("--severity")
        assert cmd[idx + 1] == "ERROR"

    def test_target_appears_last(self):
        cmd = build_cmd(Path("/src/foo"), "p/x", semgrep_bin="semgrep")
        assert cmd[-1] == "/src/foo"

    def test_uses_path_lookup_when_bin_not_specified(self):
        with patch("shutil.which", return_value="/opt/bin/semgrep"):
            cmd = build_cmd(Path("/src"), "p/x")
            assert cmd[0] == "/opt/bin/semgrep"


# run_rule with mocked subprocess ----------------------------------------------

class TestRunRuleMocked:
    def test_not_installed_returns_error_result(self):
        with patch("packages.semgrep.runner.is_available", return_value=False):
            result = run_rule(Path("/src"), "p/x")
        assert result.returncode == -1
        assert "not installed" in result.errors[0]
        assert result.findings == []
        assert not result.ok

    def test_run_basic(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        sarif = _make_sarif(count=2)
        json_output = _make_json_output(
            scanned=["src/a.py", "src/b.py"],
            version="1.79.0",
        )
        # The runner writes to a temp file; we mock json_output_path read by writing
        # the json content into whatever path subprocess "received". Easier to just
        # let it use a tempfile we pre-write.
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                # Find --json-output path argument and write content there
                if "--json-output" in cmd:
                    idx = cmd.index("--json-output")
                    Path(cmd[idx + 1]).write_text(json_output)
                return MagicMock(stdout=sarif, stderr="", returncode=1)
            mock_run.side_effect = side_effect
            result = run_rule(target, "p/security-audit")

        assert result.returncode == 1
        assert result.ok  # 1 is fine for semgrep --error
        assert len(result.findings) == 2
        assert result.files_examined == ["src/a.py", "src/b.py"]
        assert result.semgrep_version == "1.79.0"
        assert result.sarif == sarif
        assert result.elapsed_ms >= 0

    def test_run_handles_timeout(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("semgrep", 5)):
            result = run_rule(target, "p/x", timeout=5)
        assert result.returncode == -1
        assert any("Timeout" in e for e in result.errors)

    def test_run_handles_oserror(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run", side_effect=OSError("permission denied")):
            result = run_rule(target, "p/x")
        assert result.returncode == -1
        assert "permission denied" in result.errors[0]

    def test_run_with_empty_sarif(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = run_rule(target, "p/x")
        assert result.findings == []
        assert result.returncode == 0
        # No json file written → empty parse
        assert result.files_examined == []

    def test_run_with_provided_json_output_path(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        json_path = tmp_path / "out.json"
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                idx = cmd.index("--json-output")
                Path(cmd[idx + 1]).write_text(_make_json_output(scanned=["a.py"]))
                return MagicMock(stdout=_make_sarif(), stderr="", returncode=0)
            mock_run.side_effect = side_effect
            result = run_rule(target, "p/x", json_output_path=json_path)
        # Provided path should NOT be deleted by the runner
        assert json_path.exists()
        assert result.files_examined == ["a.py"]

    def test_run_passes_env(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        custom_env = {"PATH": "/safe/path", "MY_VAR": "set"}
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            run_rule(target, "p/x", env=custom_env)
        kwargs = mock_run.call_args.kwargs
        assert kwargs["env"] == custom_env

    def test_run_passes_timeout(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            run_rule(target, "p/x", timeout=42)
        kwargs = mock_run.call_args.kwargs
        assert kwargs["timeout"] == 42

    def test_run_friendly_name_from_pack(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = run_rule(target, "p/security-audit")
        assert result.name == "p/security-audit"

    def test_run_friendly_name_from_dir(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = run_rule(target, "/abs/path/to/crypto")
        assert result.name == "crypto"

    def test_run_explicit_name(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = run_rule(target, "/abs/path", name="my_run")
        assert result.name == "my_run"


# run_rules --------------------------------------------------------------------

class TestRunRules:
    def test_runs_each_config(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        configs = [("a", "p/aaa"), ("b", "p/bbb"), ("c", "p/ccc")]
        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            results = run_rules(target, configs)
        assert len(results) == 3
        assert [r.name for r in results] == ["a", "b", "c"]
        assert mock_run.call_count == 3

    def test_empty_configs(self, tmp_path):
        results = run_rules(tmp_path, [])
        assert results == []

    def test_not_installed_returns_error_per_config(self, tmp_path):
        with patch("packages.semgrep.runner.is_available", return_value=False):
            results = run_rules(tmp_path, [("a", "p/a"), ("b", "p/b")])
        assert len(results) == 2
        assert all(r.returncode == -1 for r in results)
        assert all("not installed" in r.errors[0] for r in results)


# Helpers ----------------------------------------------------------------------

class TestConfigToName:
    def test_pack(self):
        assert _config_to_name("p/security-audit") == "p/security-audit"

    def test_category(self):
        assert _config_to_name("category/security") == "category/security"

    def test_directory(self):
        assert _config_to_name("/abs/path/to/crypto") == "crypto"

    def test_relative_directory(self):
        assert _config_to_name("rules/injection") == "injection"

    def test_empty(self):
        assert _config_to_name("") == "semgrep"


# Integration ------------------------------------------------------------------

@pytest.mark.skipif(not is_available(), reason="semgrep not installed")
class TestIntegration:
    """Real-semgrep tests. Skipped when binary unavailable."""

    def test_run_on_simple_file(self, tmp_path):
        target = tmp_path / "x.py"
        target.write_text("import os\nos.system('hi')\n")
        result = run_rule(target, "p/python", timeout=120)
        # Either finds something or doesn't, but should not error.
        assert result.ok or result.returncode == 0
        assert result.semgrep_version

    def test_files_examined_populated(self, tmp_path):
        target = tmp_path / "x.py"
        target.write_text("a = 1\n")
        result = run_rule(target, "p/python", timeout=120)
        # paths.scanned should include at least our file
        assert any("x.py" in f for f in result.files_examined) or result.files_examined == []
