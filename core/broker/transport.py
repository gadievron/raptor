"""Transport abstraction for remote system communication.

Defines the protocol that SSH and WinRM backends implement and a
factory that picks the right one for a given system entry.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Mapping, Optional, Sequence


class TransportKind(Enum):
    SSH = "ssh"
    WINRM = "winrm"
    ADB = "adb"


@dataclass(frozen=True)
class RemoteSystemEntry:
    """Persistent record of a remote system in the broker inventory."""

    alias: str
    host: str
    port: int = 22
    user: str = "root"
    transport: TransportKind = TransportKind.SSH
    key_path: Optional[str] = None
    labels: frozenset[str] = field(default_factory=frozenset)
    winrm_use_ssl: bool = True
    winrm_auth: str = "ntlm"

    def to_dict(self) -> dict:
        return {
            "alias": self.alias,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "transport": self.transport.value,
            "key_path": self.key_path,
            "labels": sorted(self.labels),
            "winrm_use_ssl": self.winrm_use_ssl,
            "winrm_auth": self.winrm_auth,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RemoteSystemEntry":
        return cls(
            alias=d["alias"],
            host=d["host"],
            port=d.get("port", 22),
            user=d.get("user", "root"),
            transport=TransportKind(d.get("transport", "ssh")),
            key_path=d.get("key_path"),
            labels=frozenset(d.get("labels", [])),
            winrm_use_ssl=d.get("winrm_use_ssl", True),
            winrm_auth=d.get("winrm_auth", "ntlm"),
        )


@dataclass(frozen=True)
class CommandResult:
    """Outcome of a remote command execution."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class TransportError(Exception):
    """Raised when a transport-level operation fails."""


class Transport(abc.ABC):
    """Protocol for remote system communication."""

    @abc.abstractmethod
    def connect(self) -> None:
        """Establish a connection to the remote system."""

    @abc.abstractmethod
    def disconnect(self) -> None:
        """Tear down the connection."""

    @abc.abstractmethod
    def run(
        self,
        command: str,
        *,
        timeout: int = 300,
        env: Optional[Mapping[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        """Execute a command on the remote system."""

    @abc.abstractmethod
    def upload(self, local_path: str, remote_path: str) -> None:
        """Copy a local file or directory to the remote system."""

    @abc.abstractmethod
    def download(self, remote_path: str, local_path: str) -> None:
        """Copy a remote file or directory to the local system."""

    @abc.abstractmethod
    def path_exists(self, remote_path: str) -> bool:
        """Check whether a path exists on the remote system."""

    @abc.abstractmethod
    def mkdir(self, remote_path: str) -> None:
        """Create a directory (and parents) on the remote system."""

    def __enter__(self) -> "Transport":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.disconnect()
