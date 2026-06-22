"""WinRM transport backend.

Uses pywinrm for PowerShell-based remote execution on Windows hosts.
File transfer uses the WinRM PSRP copy mechanism (base64-encoded
chunks over the session) since WinRM has no native file transfer.

Credential resolution is delegated to ``core.broker.creds`` —
supports env-var passwords, OS keyring, Kerberos tickets, and
interactive prompts.
"""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path, PureWindowsPath
from typing import Mapping, Optional

from core.broker.creds import (
    AuthMethod,
    ResolvedCredential,
    resolve_winrm_credential,
)
from core.broker.transport import (
    CommandResult,
    RemoteSystemEntry,
    Transport,
    TransportError,
)

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 1024 * 1024  # 1 MiB base64-encoded chunks


class WinRMTransport(Transport):
    """WinRM-based transport for Windows hosts."""

    def __init__(self, entry: RemoteSystemEntry) -> None:
        self._entry = entry
        self._session: Optional[object] = None  # winrm.Session
        self._credential: Optional[ResolvedCredential] = None

    def connect(self) -> None:
        try:
            import winrm
        except ImportError as exc:
            raise TransportError(
                "pywinrm is required for WinRM transport — "
                "pip install pywinrm"
            ) from exc

        self._credential = resolve_winrm_credential(
            self._entry.alias,
            self._entry.winrm_auth,
        )
        logger.info(
            "WinRM auth method for %s: %s",
            self._entry.alias,
            self._credential.method.value,
        )

        scheme = "https" if self._entry.winrm_use_ssl else "http"
        port = self._entry.port if self._entry.port != 22 else 5986
        endpoint = f"{scheme}://{self._entry.host}:{port}/wsman"

        password = self._credential.password or ""

        try:
            self._session = winrm.Session(
                endpoint,
                auth=(self._entry.user, password),
                transport=self._entry.winrm_auth,
                server_cert_validation="ignore",
            )
            test = self._session.run_ps("$env:COMPUTERNAME")
            if test.status_code != 0:
                raise TransportError(
                    f"WinRM connection test failed: {test.std_err.decode()}"
                )
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(
                f"WinRM connection to {endpoint} failed "
                f"({self._credential.method.value}): {exc}"
            ) from exc

        logger.info(
            "WinRM connected to %s@%s:%d via %s",
            self._entry.user,
            self._entry.host,
            port,
            self._credential.method.value,
        )

    def disconnect(self) -> None:
        self._session = None
        logger.info("WinRM session released for %s", self._entry.host)

    def run(
        self,
        command: str,
        *,
        timeout: int = 300,
        env: Optional[Mapping[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        if not self._session:
            raise TransportError("not connected")

        ps_lines: list[str] = []
        if env:
            for k, v in env.items():
                ps_lines.append(f'$env:{k} = "{_ps_escape(v)}"')
        if cwd:
            ps_lines.append(f'Set-Location -Path "{_ps_escape(cwd)}"')
        ps_lines.append(command)

        script = "\n".join(ps_lines)

        try:
            result = self._session.run_ps(script)
        except Exception as exc:
            raise TransportError(f"WinRM command failed: {exc}") from exc

        return CommandResult(
            exit_code=result.status_code,
            stdout=result.std_out.decode("utf-8", errors="replace"),
            stderr=result.std_err.decode("utf-8", errors="replace"),
        )

    def upload(self, local_path: str, remote_path: str) -> None:
        if not self._session:
            raise TransportError("not connected")

        local = Path(local_path)
        if not local.exists():
            raise TransportError(f"local path does not exist: {local_path}")

        if local.is_file():
            self._upload_file(str(local), remote_path)
        elif local.is_dir():
            self._upload_dir(str(local), remote_path)

    def download(self, remote_path: str, local_path: str) -> None:
        if not self._session:
            raise TransportError("not connected")

        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)

        is_dir = self.run(
            f'Test-Path -Path "{_ps_escape(remote_path)}" -PathType Container'
        )
        if is_dir.stdout.strip().lower() == "true":
            self._download_dir(remote_path, str(local))
        else:
            self._download_file(remote_path, str(local))

    def path_exists(self, remote_path: str) -> bool:
        if not self._session:
            raise TransportError("not connected")
        result = self.run(
            f'Test-Path -Path "{_ps_escape(remote_path)}"'
        )
        return result.stdout.strip().lower() == "true"

    def mkdir(self, remote_path: str) -> None:
        result = self.run(
            f'New-Item -ItemType Directory -Force '
            f'-Path "{_ps_escape(remote_path)}" | Out-Null'
        )
        if not result.ok:
            raise TransportError(
                f"failed to create remote directory {remote_path}: "
                f"{result.stderr}"
            )

    # -- file transfer via base64-over-PowerShell --------------------------

    def _upload_file(self, local_path: str, remote_path: str) -> None:
        with open(local_path, "rb") as f:
            data = f.read()

        remote_dir = str(PureWindowsPath(remote_path).parent)
        self.mkdir(remote_dir)

        for offset in range(0, len(data), _CHUNK_SIZE):
            chunk = data[offset : offset + _CHUNK_SIZE]
            b64 = base64.b64encode(chunk).decode("ascii")
            append = "-Append" if offset > 0 else ""
            script = (
                f'$bytes = [Convert]::FromBase64String("{b64}")\n'
                f'Add-Content -Path "{_ps_escape(remote_path)}" '
                f"-Value $bytes -Encoding Byte {append}"
            )
            result = self.run(script)
            if not result.ok:
                raise TransportError(
                    f"upload chunk failed at offset {offset}: {result.stderr}"
                )

    def _download_file(self, remote_path: str, local_path: str) -> None:
        script = (
            f'$bytes = [IO.File]::ReadAllBytes("{_ps_escape(remote_path)}")\n'
            f'[Convert]::ToBase64String($bytes)'
        )
        result = self.run(script)
        if not result.ok:
            raise TransportError(
                f"download failed for {remote_path}: {result.stderr}"
            )

        data = base64.b64decode(result.stdout.strip())
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        with open(local_path, "wb") as f:
            f.write(data)

    def _upload_dir(self, local_dir: str, remote_dir: str) -> None:
        self.mkdir(remote_dir)
        for root, dirs, files in os.walk(local_dir):
            rel = os.path.relpath(root, local_dir)
            remote_root = (
                str(PureWindowsPath(remote_dir) / rel)
                if rel != "."
                else remote_dir
            )
            for d in dirs:
                self.mkdir(str(PureWindowsPath(remote_root) / d))
            for f in files:
                local_file = os.path.join(root, f)
                remote_file = str(PureWindowsPath(remote_root) / f)
                self._upload_file(local_file, remote_file)

    def _download_dir(self, remote_dir: str, local_dir: str) -> None:
        os.makedirs(local_dir, exist_ok=True)
        result = self.run(
            f'Get-ChildItem -Path "{_ps_escape(remote_dir)}" -Recurse '
            f"| Select-Object FullName, PSIsContainer "
            f"| ConvertTo-Json -Depth 1"
        )
        if not result.ok:
            raise TransportError(
                f"directory listing failed for {remote_dir}: {result.stderr}"
            )

        import json

        try:
            entries = json.loads(result.stdout)
        except json.JSONDecodeError:
            return

        if isinstance(entries, dict):
            entries = [entries]

        for entry in entries:
            full = entry["FullName"]
            rel = os.path.relpath(
                full.replace("\\", "/"),
                remote_dir.replace("\\", "/"),
            )
            local_path = os.path.join(local_dir, rel)
            if entry["PSIsContainer"]:
                os.makedirs(local_path, exist_ok=True)
            else:
                self._download_file(full, local_path)


def _ps_escape(s: str) -> str:
    """Escape a string for safe embedding in a PowerShell double-quoted string."""
    return s.replace("`", "``").replace('"', '`"').replace("$", "`$")
