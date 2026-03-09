#!/usr/bin/env python3
"""
Glasgow Interface Explorer subprocess wrapper.

Wraps the glasgow CLI for use in the hardware enumeration pipeline. There might be better ways to do this but for now it works ok. 

by Daniel Cuthbert (@danielcuthbert) 

Installation note: The 'glasgow' pip package (version 0.0.0) is a placeholder.
Install the real Glasgow software from source:
  https://glasgow-embedded.org/latest/install.html
"""

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logging import get_logger

logger = get_logger()

GLASGOW_INSTALL_URL = "https://glasgow-embedded.org/latest/install.html"


class GlasgowRunner:
    """Wrapper around the glasgow CLI tool."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self._glasgow_path = self._find_glasgow()

    def _find_glasgow(self) -> Optional[str]:
        """Locate the glasgow binary."""
        path = shutil.which("glasgow")
        if path:
            logger.debug(f"Found glasgow at: {path}")
        return path

    @property
    def available(self) -> bool:
        """True if glasgow binary is found on PATH."""
        return self._glasgow_path is not None

    def identify(self) -> dict:
        """
        Run 'glasgow identify' to detect a connected device.

        Returns:
            dict with keys: found (bool), version (str), serial (str), raw (str)
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

        result = self.run(["identify"], timeout=10)
        if result["returncode"] != 0 or not result["stdout"].strip():
            return {
                "found": False,
                "version": "",
                "serial": "",
                "raw": result["stdout"] + result["stderr"],
                "error": result["stderr"].strip() or "No device responded",
            }

        raw = result["stdout"]
        version = ""
        serial = ""
        for line in raw.splitlines():
            line_lower = line.lower()
            if "version" in line_lower or "rev" in line_lower:
                version = line.strip()
            if "serial" in line_lower:
                serial = line.strip()

        return {
            "found": True,
            "version": version,
            "serial": serial,
            "raw": raw,
        }

    def vsense(self, port: str = 'A') -> dict:
        """
        Read target Vsense voltage on the given port.

        Runs 'glasgow voltage <port>' and parses the Vsense column from the
        tabular output (Port Vio Vlimit Vsense Vsense(range)).

        Args:
            port: Glasgow port to check ('A' or 'B')

        Returns:
            dict with: powered (bool), vsense_v (float), port (str)
        """
        POWERED_THRESHOLD = 0.5  # V — below this is effectively unpowered

        result = self.run(['voltage', port], timeout=5)
        vsense_v = 0.0
        for line in result['stdout'].splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == port:
                try:
                    vsense_v = float(parts[3])
                except ValueError:
                    pass

        return {
            'powered': vsense_v >= POWERED_THRESHOLD,
            'vsense_v': vsense_v,
            'port': port,
        }

    def run(
        self,
        args: list,
        timeout: Optional[int] = None,
        capture_output: bool = True,
    ) -> dict:
        """
        Run a glasgow command.

        Args:
            args: Arguments to pass after 'glasgow'
            timeout: Override default timeout (seconds)
            capture_output: Capture stdout/stderr if True; else stream live

        Returns:
            dict with keys: returncode, stdout, stderr, command
        """
        cmd = [self._glasgow_path or "glasgow"] + args
        t = timeout if timeout is not None else self.timeout
        logger.debug(f"Running: {' '.join(cmd)}")

        try:
            if capture_output:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=t,
                )
            else:
                proc = subprocess.run(cmd, timeout=t)

            return {
                "returncode": proc.returncode,
                "stdout": proc.stdout if capture_output else "",
                "stderr": proc.stderr if capture_output else "",
                "command": " ".join(cmd),
            }

        except subprocess.TimeoutExpired:
            logger.warning(f"Glasgow command timed out after {t}s: {' '.join(cmd)}")
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"Timed out after {t}s",
                "command": " ".join(cmd),
            }
        except FileNotFoundError:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"glasgow binary not found. Install from: {GLASGOW_INSTALL_URL}",
                "command": " ".join(cmd),
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "command": " ".join(cmd),
            }
