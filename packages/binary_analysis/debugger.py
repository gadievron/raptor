#!/usr/bin/env python3
"""
GDB Debugger Wrapper

Provides programmatic interface to GDB for crash analysis.

Security: Input files are passed via subprocess stdin, NOT via GDB's
`run < path` in-script redirection. This prevents CWE-78 command injection
through crafted filenames (GDB's parser interprets shell metacharacters).

Address/size validation: examine_memory() routes `address` and `num_bytes`
through packages.binary_analysis._validators before they land in a GDB
script. GDB scripts are newline-delimited, so a \n in either field injects
a second command. GDB has a `shell` builtin. That's the bug. The same
validators are reused by crash_analyser.py's addr2line path so the two
sinks can't drift apart.

Not an active issue in RAPTOR right now. CrashAnalyser validates upstream
and there's no call site that takes unvalidated input. But this is a public
export and doing it right costs nothing.
"""

import os
import subprocess
from pathlib import Path
from typing import List, Optional

from packages.binary_analysis._validators import (
    validate_byte_count,
    validate_hex_address,
)
from core.logging import get_logger

logger = get_logger()


class GDBDebugger:
    """Wrapper around GDB for automated debugging."""

    def __init__(self, binary_path: Path):
        self.binary = Path(binary_path)
        if not self.binary.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

    def run_commands(self, commands: List[str], input_file: Optional[Path] = None, timeout: int = 30) -> str:
        """
        Run GDB with a list of commands.

        Args:
            commands: List of GDB commands to execute
            input_file: Optional input file to redirect to stdin
            timeout: Command timeout in seconds

        Returns:
            GDB output as string
        """
        # Prepare GDB commands
        gdb_script = "\n".join(commands)

        # Write to temp file (random name to prevent symlink attacks on multi-user systems).
        # mkstemp creates the on-disk stub before write_text runs, so a failing
        # write (ENOSPC, I/O error, etc.) would leak /tmp/.raptor_gdb_*.txt
        # unless we unlink on failure. Guard with try/except that re-raises
        # after cleanup so the caller still sees the underlying error.
        import tempfile
        fd, script_name = tempfile.mkstemp(prefix=".raptor_gdb_", suffix=".txt")
        script_file = Path(script_name)
        os.close(fd)
        try:
            script_file.write_text(gdb_script)
        except BaseException:
            script_file.unlink(missing_ok=True)
            raise

        # Build GDB command
        cmd = ["gdb", "-batch", "-x", str(script_file), str(self.binary)]

        # Run with input redirection if provided
        try:
            if input_file:
                with open(input_file, "rb") as f:
                    result = subprocess.run(
                        cmd,
                        stdin=f,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )

            return result.stdout
        finally:
            try:
                script_file.unlink()
            except OSError:
                pass

    def get_backtrace(self, input_file: Path) -> str:
        """Get stack trace for a crash."""
        commands = [
            "set pagination off",
            "set confirm off",
            "run",
            "backtrace full",
            "quit",
        ]

        return self.run_commands(commands, input_file=input_file)

    def get_registers(self, input_file: Path) -> str:
        """Get register state at crash."""
        commands = [
            "set pagination off",
            "set confirm off",
            "run",
            "info registers",
            "quit",
        ]

        return self.run_commands(commands, input_file=input_file)

    def examine_memory(self, input_file: Path, address: str, num_bytes: int = 64) -> str:
        """Examine memory at address.

        Args:
            input_file: Crash input file fed to the binary via stdin.
            address: Hex address, 0x<1-16 hex digits>. See _validators for
                     the full threat model (GDB scripts are newline-delimited,
                     so \\n here injects a second command).
            num_bytes: Byte count, 1..4096. Embedded verbatim into the GDB
                     script; validated to block str-disguised-as-int inputs
                     like "64\\nshell id".

        Raises:
            ValueError: If address or num_bytes fails validation.
        """
        validate_hex_address(address)
        validate_byte_count(num_bytes)

        commands = [
            "set pagination off",
            "set confirm off",
            "run",
            f"x/{num_bytes}xb {address}",
            "quit",
        ]

        return self.run_commands(commands, input_file=input_file)
