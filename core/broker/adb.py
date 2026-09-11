"""ADB transport backend for Android devices.

Wraps the ``adb`` CLI to provide the same Transport interface used by
SSH and WinRM.  Supports both USB-connected and network-connected
(``adb connect host:port``) devices.

Prerequisites:
    - ``adb`` in PATH (Android SDK Platform Tools)
    - Device authorised (USB debugging enabled, RSA key accepted)
    - For rooted operations: ``adb root`` or ``su`` on the device

File transfer uses ``adb push`` / ``adb pull`` which handle
directories recursively.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Mapping, Optional

from core.broker.transport import (
    CommandResult,
    RemoteSystemEntry,
    Transport,
    TransportError,
)

logger = logging.getLogger(__name__)


class ADBTransport(Transport):
    """ADB-based transport for rooted Android devices."""

    def __init__(self, entry: RemoteSystemEntry) -> None:
        self._entry = entry
        self._serial: Optional[str] = None
        self._connected = False

    def _adb_base(self) -> list[str]:
        """Build the base adb command with serial targeting."""
        cmd = ["adb"]
        if self._serial:
            cmd.extend(["-s", self._serial])
        return cmd

    def connect(self) -> None:
        if not shutil.which("adb"):
            raise TransportError(
                "adb not found in PATH — install Android SDK Platform Tools"
            )

        host = self._entry.host
        port = self._entry.port

        if host not in ("localhost", "127.0.0.1", ""):
            serial = f"{host}:{port}"
            result = subprocess.run(
                ["adb", "connect", serial],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0 or "cannot connect" in result.stdout.lower():
                raise TransportError(
                    f"adb connect to {serial} failed: "
                    f"{result.stdout.strip()} {result.stderr.strip()}"
                )
            self._serial = serial
            logger.info("ADB connected to %s (network)", serial)
        else:
            devices = subprocess.run(
                ["adb", "devices"],
                capture_output=True, text=True, timeout=10,
            )
            lines = [
                l for l in devices.stdout.strip().splitlines()[1:]
                if l.strip() and "device" in l
            ]
            if not lines:
                raise TransportError(
                    "no ADB devices attached — "
                    "enable USB debugging and connect the device"
                )
            self._serial = lines[0].split()[0]
            logger.info("ADB connected to %s (USB)", self._serial)

        self._connected = True

    def disconnect(self) -> None:
        host = self._entry.host
        if host not in ("localhost", "127.0.0.1", "") and self._serial:
            subprocess.run(
                ["adb", "disconnect", self._serial],
                capture_output=True, text=True, timeout=10,
            )
        self._connected = False
        logger.info("ADB disconnected from %s", self._serial)

    def run(
        self,
        command: str,
        *,
        timeout: int = 300,
        env: Optional[Mapping[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        if not self._connected:
            raise TransportError("not connected")

        full_cmd = command
        if cwd:
            full_cmd = f"cd {_sh_quote(cwd)} && {command}"
        if env:
            prefix = " ".join(
                f"{_validated_env_key(k)}={_sh_quote(v)}"
                for k, v in env.items()
            )
            full_cmd = f"{prefix} {full_cmd}"

        adb_cmd = self._adb_base() + ["shell", full_cmd]

        try:
            proc = subprocess.run(
                adb_cmd,
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransportError(f"adb shell timed out after {timeout}s") from exc
        except Exception as exc:
            raise TransportError(f"adb shell failed: {exc}") from exc

        return CommandResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def upload(self, local_path: str, remote_path: str) -> None:
        if not self._connected:
            raise TransportError("not connected")

        local = Path(local_path)
        if not local.exists():
            raise TransportError(f"local path does not exist: {local_path}")

        cmd = self._adb_base() + ["push", str(local), remote_path]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
        if proc.returncode != 0:
            raise TransportError(f"adb push failed: {proc.stderr}")

    def download(self, remote_path: str, local_path: str) -> None:
        if not self._connected:
            raise TransportError("not connected")

        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)

        cmd = self._adb_base() + ["pull", remote_path, str(local)]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
        if proc.returncode != 0:
            raise TransportError(f"adb pull failed: {proc.stderr}")

    def path_exists(self, remote_path: str) -> bool:
        result = self.run(
            f"[ -e {_sh_quote(remote_path)} ] && echo yes || echo no"
        )
        return result.ok and "yes" in result.stdout

    def mkdir(self, remote_path: str) -> None:
        result = self.run(f"mkdir -p {_sh_quote(remote_path)}")
        if not result.ok:
            raise TransportError(
                f"failed to create remote directory {remote_path}: "
                f"{result.stderr}"
            )


_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validated_env_key(key: str) -> str:
    """Reject env keys that could inject shell metacharacters."""
    if not _ENV_KEY_RE.match(key):
        raise TransportError(
            f"invalid environment variable name: {key!r}"
        )
    return key


def _sh_quote(s: str) -> str:
    """POSIX shell-safe quoting."""
    if not s:
        return "''"
    return "'" + s.replace("'", "'\"'\"'") + "'"
