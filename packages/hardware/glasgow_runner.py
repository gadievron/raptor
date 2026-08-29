#!/usr/bin/env python3
"""Glasgow Interface Explorer subprocess wrapper.

Wraps the glasgow CLI for the hardware enumeration pipeline.

Installation note: the 'glasgow' pip package (version 0.0.0) is a
placeholder. Install the real Glasgow software from source:
  https://glasgow-embedded.org/latest/install.html
"""

import os
import re
import shutil
import signal
import subprocess
from typing import Optional

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()

GLASGOW_INSTALL_URL = "https://glasgow-embedded.org/latest/install.html"


def _result(returncode: int, stdout_b: Optional[bytes],
            stderr_b: Optional[bytes], cmd: list[str]) -> dict:
    """Build the runner result dict from raw pipe bytes.

    Device output is arbitrary bytes (UART noise at a wrong baud rate is
    the designed common case), so pipes are opened in binary mode and
    decoded HERE with errors="replace" — a text-mode pipe would raise
    UnicodeDecodeError out of communicate() and abort the whole
    enumeration on the first noisy capture. ``stdout_bytes`` rides along
    for consumers that must score the raw bytes (UART printable-ratio),
    where a lossy decode→re-encode round trip would turn noise into
    printable '?' characters.
    """
    stdout_b = stdout_b or b""
    stderr_b = stderr_b or b""
    return {
        "returncode": returncode,
        "stdout": stdout_b.decode("utf-8", errors="replace"),
        "stderr": stderr_b.decode("utf-8", errors="replace"),
        "stdout_bytes": stdout_b,
        "command": " ".join(cmd),
    }


class GlasgowRunner:
    """Wrapper around the glasgow CLI tool."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._glasgow_path = self._find_glasgow()

    def _find_glasgow(self) -> Optional[str]:
        """Locate the glasgow binary."""
        path = shutil.which("glasgow")
        if path:
            logger.debug("Found glasgow at: %s", path)
        return path

    @property
    def available(self) -> bool:
        """True if glasgow binary is found on PATH."""
        return self._glasgow_path is not None

    def identify(self) -> dict:
        """Detect a connected Glasgow device using 'glasgow list'.

        Returns:
            dict with keys: found (bool), version (str), serial (str),
            raw (str), and error (str, only when found is False)
        """
        if not self.available:
            return {
                "found": False,
                "version": "",
                "serial": "",
                "raw": "",
                "error": (
                    f"glasgow binary not found on PATH. "
                    f"Install from: {GLASGOW_INSTALL_URL}"
                ),
            }

        result = self.run(["list"], timeout=10)
        raw = result["stdout"].strip()

        if result["returncode"] != 0 or not raw:
            return {
                "found": False,
                "version": "",
                "serial": "",
                "raw": raw,
                "error": result["stderr"].strip() or "No device found",
            }

        # 'glasgow list' outputs one serial per line, e.g. "C3-20240527T113341Z"
        # Parse revision from serial prefix (C3 = revC3, etc.)
        serials = [line.strip() for line in raw.splitlines() if line.strip()]
        serial = serials[0] if serials else ""
        version = ""
        if serial and "-" in serial:
            rev_part = serial.split("-")[0]   # e.g. "C3"
            version = f"rev{rev_part}"

        return {
            "found": True,
            "version": version,
            "serial": serial,
            "raw": raw,
        }

    def check_applet(self, applet: str, expected_flags: list[str]) -> Optional[str]:
        """Probe ``glasgow run <applet> --help`` and verify the flags this
        pipeline passes are present.

        The glasgow CLI has renamed applets and pin flags across releases
        (e.g. ``--pins-cs`` became ``--cs``/``--io``); without this probe a
        mismatch surfaces as a silent all-clear (every capture "fails
        gracefully" into a degraded mode) instead of an error.

        Flags are matched on word boundaries — a plain substring check
        would let ``--io`` in the help text satisfy an expected ``--i``,
        false-negativing on exactly the short flags that most need the
        guard.

        Returns None when compatible, else a human-readable problem string.
        """
        result = self.run(["run", applet, "--help"], timeout=20)
        help_text = result["stdout"] + result["stderr"]
        if result["returncode"] != 0:
            detail = result["stderr"].strip().splitlines()
            return (
                f"applet '{applet}' not available in this glasgow install: "
                f"{detail[-1] if detail else 'unknown error'}"
            )
        missing = [
            flag for flag in expected_flags
            if not re.search(
                rf"(?<![\w-]){re.escape(flag)}(?![\w-])", help_text,
            )
        ]
        if missing:
            return (
                f"applet '{applet}' does not accept {', '.join(missing)} — "
                f"glasgow CLI has likely changed; update packages/hardware/ "
                f"to match `glasgow run {applet} --help`"
            )
        return None

    @staticmethod
    def _signal_group(proc: subprocess.Popen, sig: int) -> None:
        """Signal the child's process group (falls back to the child
        alone). Glasgow spawns toolchain grandchildren (yosys/nextpnr
        during bitstream builds) that inherit the pipes; signalling only
        the direct child leaves them holding the write ends."""
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.send_signal(sig)
            except (ProcessLookupError, OSError):
                pass

    def run_timed(self, args: list[str], duration: int, grace: int = 5) -> dict:
        """Run a glasgow command that streams until interrupted (e.g. the
        ``analyzer`` capture applet, which has no duration option): let it
        run for ``duration`` seconds, then send SIGINT to its process
        group — the same clean stop a human's Ctrl-C performs, giving the
        applet a chance to flush and close its output file — escalating
        to SIGKILL after ``grace`` more seconds, and giving up on
        remaining pipe output after one more ``grace`` rather than
        blocking forever on an orphaned grandchild.

        Returns the same dict shape as :meth:`run`. ``returncode`` is
        whatever the interrupted process exits with — callers judge
        success by the output artifact, not the exit code.
        """
        cmd = [self._glasgow_path or "glasgow"] + args
        logger.debug("Running (timed %ss): %s", duration, " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                env=RaptorConfig.get_safe_env(),
            )
        except FileNotFoundError:
            return _result(
                -1, b"",
                f"glasgow binary not found. Install from: {GLASGOW_INSTALL_URL}".encode(),
                cmd,
            )
        except OSError as e:
            return _result(-1, b"", str(e).encode(), cmd)

        stdout_b = stderr_b = b""
        try:
            stdout_b, stderr_b = proc.communicate(timeout=duration)
        except subprocess.TimeoutExpired:
            # Expected path: the capture ran its full window.
            self._signal_group(proc, signal.SIGINT)
            try:
                stdout_b, stderr_b = proc.communicate(timeout=grace)
            except subprocess.TimeoutExpired:
                self._signal_group(proc, signal.SIGKILL)
                try:
                    stdout_b, stderr_b = proc.communicate(timeout=grace)
                except subprocess.TimeoutExpired:
                    # An orphaned grandchild still holds the pipe write
                    # ends; abandon the remaining output.
                    logger.warning(
                        "Glasgow child group did not release pipes after "
                        "SIGKILL; abandoning remaining output: %s",
                        " ".join(cmd),
                    )
                    if proc.stdout:
                        proc.stdout.close()
                    if proc.stderr:
                        proc.stderr.close()
                    try:
                        proc.wait(timeout=grace)
                    except subprocess.TimeoutExpired:
                        pass
        return _result(proc.returncode if proc.returncode is not None else -1,
                       stdout_b, stderr_b, cmd)

    def run(
        self,
        args: list[str],
        timeout: Optional[int] = None,
        capture_output: bool = True,
    ) -> dict:
        """Run a glasgow command.

        Args:
            args: Arguments to pass after 'glasgow'
            timeout: Override default timeout (seconds)
            capture_output: Capture stdout/stderr if True; else stream live

        Returns:
            dict with keys: returncode, stdout, stderr, stdout_bytes, command
        """
        cmd = [self._glasgow_path or "glasgow"] + args
        t = timeout if timeout is not None else self.timeout
        logger.debug("Running: %s", " ".join(cmd))

        try:
            if capture_output:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=t,
                    env=RaptorConfig.get_safe_env(),
                )
                return _result(proc.returncode, proc.stdout, proc.stderr, cmd)
            proc = subprocess.run(
                cmd, timeout=t, env=RaptorConfig.get_safe_env(),
            )
            return _result(proc.returncode, b"", b"", cmd)

        except subprocess.TimeoutExpired as e:
            logger.warning(
                "Glasgow command timed out after %ss: %s", t, " ".join(cmd),
            )
            # Partial output rides along; the timeout note goes on stderr.
            partial_err = e.stderr or b""
            note = f"\nTimed out after {t}s".encode()
            return _result(-1, e.stdout, partial_err + note, cmd)
        except FileNotFoundError:
            return _result(
                -1, b"",
                f"glasgow binary not found. Install from: {GLASGOW_INSTALL_URL}".encode(),
                cmd,
            )
        except OSError as e:
            return _result(-1, b"", str(e).encode(), cmd)
