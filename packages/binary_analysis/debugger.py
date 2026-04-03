#!/usr/bin/env python3
"""
GDB Debugger Wrapper

Provides programmatic interface to GDB for crash analysis.

Security: Input files are passed via subprocess stdin, NOT via GDB's
`run < path` in-script redirection. This prevents CWE-78 command injection
through crafted filenames (GDB's parser interprets shell metacharacters).
"""

import os
import subprocess
from pathlib import Path
from typing import List, Optional

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

        # Write to temp file (random name to prevent symlink attacks on multi-user systems)
        import tempfile
        fd, script_name = tempfile.mkstemp(prefix=".raptor_gdb_", suffix=".txt")
        script_file = Path(script_name)
        os.close(fd)
        script_file.write_text(gdb_script)

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
        """Examine memory at address."""
        commands = [
            "set pagination off",
            "set confirm off",
            "run",
            f"x/{num_bytes}xb {address}",
            "quit",
        ]

        return self.run_commands(commands, input_file=input_file)
