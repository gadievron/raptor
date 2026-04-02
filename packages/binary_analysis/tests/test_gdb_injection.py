"""Tests that GDB scripts don't contain file paths (CWE-78 mitigation)."""

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
