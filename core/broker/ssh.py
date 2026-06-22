"""SSH transport backend.

Uses paramiko for connection management and SFTP for file transfer,
with rsync as a fast-path when available on both ends.
"""

from __future__ import annotations

import logging
import os
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


class SSHTransport(Transport):
    """SSH-based transport using paramiko."""

    def __init__(self, entry: RemoteSystemEntry) -> None:
        self._entry = entry
        self._client: Optional[object] = None  # paramiko.SSHClient
        self._sftp: Optional[object] = None  # paramiko.SFTPClient

    def connect(self) -> None:
        try:
            import paramiko
        except ImportError as exc:
            raise TransportError(
                "paramiko is required for SSH transport — "
                "pip install paramiko"
            ) from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": self._entry.host,
            "port": self._entry.port,
            "username": self._entry.user,
            "timeout": 30,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if self._entry.key_path:
            connect_kwargs["key_filename"] = self._entry.key_path

        try:
            client.connect(**connect_kwargs)
        except Exception as exc:
            raise TransportError(
                f"SSH connection to {self._entry.host}:{self._entry.port} "
                f"failed: {exc}"
            ) from exc

        self._client = client
        self._sftp = client.open_sftp()
        logger.info(
            "SSH connected to %s@%s:%d",
            self._entry.user,
            self._entry.host,
            self._entry.port,
        )

    def disconnect(self) -> None:
        if self._sftp:
            self._sftp.close()
            self._sftp = None
        if self._client:
            self._client.close()
            self._client = None
        logger.info("SSH disconnected from %s", self._entry.host)

    def run(
        self,
        command: str,
        *,
        timeout: int = 300,
        env: Optional[Mapping[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        if not self._client:
            raise TransportError("not connected")

        full_cmd = command
        if cwd:
            full_cmd = f"cd {_shell_quote(cwd)} && {command}"
        if env:
            prefix = " ".join(
                f"{k}={_shell_quote(v)}" for k, v in env.items()
            )
            full_cmd = f"{prefix} {full_cmd}"

        try:
            _, stdout_ch, stderr_ch = self._client.exec_command(
                full_cmd, timeout=timeout
            )
            stdout = stdout_ch.read().decode("utf-8", errors="replace")
            stderr = stderr_ch.read().decode("utf-8", errors="replace")
            exit_code = stdout_ch.channel.recv_exit_status()
        except Exception as exc:
            raise TransportError(f"remote command failed: {exc}") from exc

        return CommandResult(
            exit_code=exit_code, stdout=stdout, stderr=stderr
        )

    def upload(self, local_path: str, remote_path: str) -> None:
        if not self._sftp:
            raise TransportError("not connected")

        local = Path(local_path)
        if not local.exists():
            raise TransportError(f"local path does not exist: {local_path}")

        if local.is_file():
            self._sftp.put(str(local), remote_path)
            return

        if local.is_dir():
            if _rsync_available() and self._rsync_available_remote():
                self._rsync_upload(str(local), remote_path)
            else:
                self._sftp_upload_dir(str(local), remote_path)

    def download(self, remote_path: str, local_path: str) -> None:
        if not self._sftp:
            raise TransportError("not connected")

        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)

        try:
            stat = self._sftp.stat(remote_path)
        except FileNotFoundError as exc:
            raise TransportError(
                f"remote path does not exist: {remote_path}"
            ) from exc

        import stat as stat_mod

        if stat_mod.S_ISDIR(stat.st_mode):
            if _rsync_available() and self._rsync_available_remote():
                self._rsync_download(remote_path, str(local))
            else:
                self._sftp_download_dir(remote_path, str(local))
        else:
            self._sftp.get(remote_path, str(local))

    def path_exists(self, remote_path: str) -> bool:
        if not self._sftp:
            raise TransportError("not connected")
        try:
            self._sftp.stat(remote_path)
            return True
        except FileNotFoundError:
            return False

    def mkdir(self, remote_path: str) -> None:
        result = self.run(f"mkdir -p {_shell_quote(remote_path)}")
        if not result.ok:
            raise TransportError(
                f"failed to create remote directory {remote_path}: "
                f"{result.stderr}"
            )

    # -- rsync fast-paths --------------------------------------------------

    def _rsync_available_remote(self) -> bool:
        result = self.run("which rsync", timeout=10)
        return result.ok

    def _rsync_upload(self, local_dir: str, remote_dir: str) -> None:
        dst = (
            f"{self._entry.user}@{self._entry.host}:{remote_dir}"
        )
        cmd = [
            "rsync", "-az", "--delete",
            "-e", f"ssh -p {self._entry.port} -o StrictHostKeyChecking=no",
        ]
        if self._entry.key_path:
            cmd[-1] += f" -i {self._entry.key_path}"
        cmd += [f"{local_dir}/", dst]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            raise TransportError(f"rsync upload failed: {proc.stderr}")

    def _rsync_download(self, remote_dir: str, local_dir: str) -> None:
        src = (
            f"{self._entry.user}@{self._entry.host}:{remote_dir}"
        )
        cmd = [
            "rsync", "-az",
            "-e", f"ssh -p {self._entry.port} -o StrictHostKeyChecking=no",
        ]
        if self._entry.key_path:
            cmd[-1] += f" -i {self._entry.key_path}"
        cmd += [f"{src}/", local_dir]

        os.makedirs(local_dir, exist_ok=True)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            raise TransportError(f"rsync download failed: {proc.stderr}")

    # -- SFTP recursive fallbacks ------------------------------------------

    def _sftp_upload_dir(self, local_dir: str, remote_dir: str) -> None:
        self.mkdir(remote_dir)
        for root, dirs, files in os.walk(local_dir):
            rel = os.path.relpath(root, local_dir)
            remote_root = (
                f"{remote_dir}/{rel}" if rel != "." else remote_dir
            )
            for d in dirs:
                self.mkdir(f"{remote_root}/{d}")
            for f in files:
                local_file = os.path.join(root, f)
                remote_file = f"{remote_root}/{f}"
                self._sftp.put(local_file, remote_file)

    def _sftp_download_dir(self, remote_dir: str, local_dir: str) -> None:
        os.makedirs(local_dir, exist_ok=True)
        for entry in self._sftp.listdir_attr(remote_dir):
            remote_path = f"{remote_dir}/{entry.filename}"
            local_path = os.path.join(local_dir, entry.filename)
            import stat as stat_mod

            if stat_mod.S_ISDIR(entry.st_mode):
                self._sftp_download_dir(remote_path, local_path)
            else:
                self._sftp.get(remote_path, local_path)


def _rsync_available() -> bool:
    return shutil.which("rsync") is not None


def _shell_quote(s: str) -> str:
    """POSIX shell-safe quoting."""
    if not s:
        return "''"
    return "'" + s.replace("'", "'\"'\"'") + "'"
