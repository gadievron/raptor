#!/usr/bin/env python3
"""
GDB Debugger Wrapper

Provides programmatic interface to GDB for crash analysis.
"""

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

        # Write to temp file
        script_file = Path("/tmp/raptor_gdb_script.txt")
        script_file.write_text(gdb_script)

        # Build GDB command
        cmd = ["gdb", "-batch", "-x", str(script_file), str(self.binary)]

        # Run with input redirection if provided
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

    def get_backtrace(self, input_file: Path) -> str:
        """Get stack trace for a crash."""
        commands = [
            "set pagination off",
            "set confirm off",
            f"run < {input_file}",
            "backtrace full",
            "quit",
        ]

        return self.run_commands(commands)

    def get_registers(self, input_file: Path) -> str:
        """Get register state at crash."""
        commands = [
            "set pagination off",
            "set confirm off",
            f"run < {input_file}",
            "info registers",
            "quit",
        ]

        return self.run_commands(commands)

    def examine_memory(self, input_file: Path, address: str, num_bytes: int = 64) -> str:
        """Examine memory at address."""
        commands = [
            "set pagination off",
            "set confirm off",
            f"run < {input_file}",
            f"x/{num_bytes}xb {address}",
            "quit",
        ]

        return self.run_commands(commands)
