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
import tempfile
from core.sandbox import run as _sandbox_run
# GDB needs ptrace(), which seccomp blocks in the `full` profile. Use
# profile='debug' — same filesystem/network isolation as full, but ptrace
# is permitted so gdb can trace its target. Landlock is engaged with
# target=output=<tempdir holding the gdb script + binary>.
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
        #
        # `dir=` to the binary's parent dir (RAPTOR-controlled
        # via the analyser's working area) instead of the
        # default `/tmp`. Pre-fix the script landed in
        # `tempfile.gettempdir()` which on Linux is shared
        # `/tmp`. Multi-user systems (CI runners, jump hosts,
        # shared dev VMs) had operators' GDB scripts visible
        # to OTHER users via `ls /tmp/.raptor_gdb_*` and (since
        # they're 0600 by mkstemp default) at least
        # enumerable. Worse: the GDB script contains the binary
        # path + commands; on systems with /tmp world-readable
        # for compatibility with old tools, the script content
        # leaks. Place the script next to the binary so it
        # inherits the binary's directory permissions, which
        # we control.
        # binary_dir resolves to the analyser's binary working
        # area — same dir we already pass to landlock as a
        # writable path (line 81 below).
        binary_dir = self.binary.parent
        try:
            binary_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        fd, script_name = tempfile.mkstemp(
            prefix=".raptor_gdb_", suffix=".txt", dir=str(binary_dir),
        )
        script_file = Path(script_name)
        os.close(fd)
        # mkstemp defaults to 0o600 on POSIX, but "defaults to" is a
        # platform contract that has shifted on edge cases (a custom
        # umask, a broken libc fallback, a future Python release that
        # changes the policy). The script may contain operator-supplied
        # GDB commands that we don't want world-readable on a shared
        # host even briefly. Set the mode explicitly so the protection
        # holds regardless of platform defaults.
        try:
            os.chmod(script_file, 0o600)
        except OSError:
            # Some non-Unix filesystems (FAT mounted /tmp on a USB,
            # Windows path under WSL) don't support POSIX modes;
            # the chmod failure isn't fatal.
            pass
        try:
            script_file.write_text(gdb_script)
        except BaseException:
            script_file.unlink(missing_ok=True)
            raise

        # Landlock needs a directory to engage — use the binary's parent
        # and the gdb-script tempdir. Both are the same /tmp in practice
        # when the binary was also placed in /tmp; we pass both for
        # coverage. Landlock allows reads everywhere (gcc includes etc.),
        # writes only to these.
        binary_dir = str(self.binary.parent.resolve())
        script_dir = str(script_file.parent.resolve())

        # Build GDB command
        cmd = ["gdb", "-batch", "-x", str(script_file), str(self.binary)]

        # Run with input redirection if provided.
        # profile='debug' permits ptrace while keeping all other seccomp
        # blocks, namespace net/pid isolation, and Landlock active.
        try:
            if input_file:
                with open(input_file, "rb") as f:
                    result = _sandbox_run(
                        cmd, profile="debug",
                        target=binary_dir, output=script_dir,
                        stdin=f,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        sanitise_host_fingerprint=True,
                    )
            else:
                result = _sandbox_run(
                    cmd, profile="debug",
                    target=binary_dir, output=script_dir,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    sanitise_host_fingerprint=True,
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
