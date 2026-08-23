"""Tests for core.binary.inspect — sandboxed binutils inspection.

Pin the consolidated contract: allowlist enforcement, full-sandbox
invocation shape (block_network + Landlock target scoped to the
binary's parent — the discipline binary_oracle proved and the other
inspection families lacked), never-raise failure semantics, and raw
byte-identical stream passthrough.
"""

from __future__ import annotations

import shutil
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from core.binary.inspect import InspectResult, inspect_binary, nm, readelf

HAVE_READELF = shutil.which("readelf") is not None


class TestAllowlist:
    def test_non_allowlisted_tool_rejected(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF")
        with pytest.raises(ValueError):
            inspect_binary("gdb", (), binary)
        with pytest.raises(ValueError):
            inspect_binary("bash", ("-c", "true"), binary)


class TestInvocationShape:
    def test_full_sandbox_with_scoped_target(self, tmp_path):
        binary = tmp_path / "sub" / "b"
        binary.parent.mkdir()
        binary.write_bytes(b"\x7fELF")
        with patch("core.sandbox.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="OUT", stderr="")
            result = readelf(binary, "-h", timeout=5)
            args, kwargs = mock_run.call_args
        assert args[0] == ["readelf", "-h", str(binary)]
        assert kwargs["block_network"] is True
        assert kwargs["target"] == str(binary.parent.resolve())
        assert kwargs["timeout"] == 5
        assert result == InspectResult(returncode=0, stdout="OUT", stderr="")

    def test_nm_flags_precede_binary(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF")
        with patch("core.sandbox.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr="")
            nm(binary, "-D", "-C")
            argv = mock_run.call_args[0][0]
        assert argv == ["nm", "-D", "-C", str(binary)]


class TestFailureSemantics:
    def test_execution_failure_never_raises(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF")
        with patch(
            "core.sandbox.run",
            side_effect=subprocess.TimeoutExpired("readelf", 10),
        ):
            result = readelf(binary, "-h")
        assert result.returncode is None
        assert result.stdout == ""

    def test_tool_rejecting_input_keeps_rc_and_streams(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"not elf")
        with patch("core.sandbox.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="Not an ELF file")
            result = readelf(binary, "-h")
        assert result.returncode == 1
        assert "Not an ELF" in result.stderr


@pytest.mark.skipif(not HAVE_READELF, reason="readelf not installed")
class TestRealBinary:
    def test_readelf_header_on_real_elf(self):
        # /bin/ls exists on every host this suite supports; the same
        # smoke target binary_oracle's tests use.
        result = readelf("/bin/ls", "-h", timeout=15)
        if result.returncode is None:
            pytest.skip("sandbox unavailable on this host")
        assert result.returncode == 0
        assert "ELF" in result.stdout
        assert "Class:" in result.stdout
