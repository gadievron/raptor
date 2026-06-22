"""Capability model for systems and RAPTOR modes.

A *SystemCapabilities* snapshot describes what a host can do right now
(OS, architecture, installed tools, resource headroom).  A
*ModeRequirements* record describes what a RAPTOR mode needs to run.
The broker matches the two.
"""

from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Mapping, Optional, Sequence


class OperatingSystem(Enum):
    LINUX = "linux"
    DARWIN = "darwin"
    WINDOWS = "windows"
    UNKNOWN = "unknown"

    @classmethod
    def detect(cls) -> "OperatingSystem":
        name = platform.system().lower()
        return cls(name) if name in cls._value2member_map_ else cls.UNKNOWN


class Architecture(Enum):
    X86_64 = "x86_64"
    AARCH64 = "aarch64"
    ARM64 = "arm64"
    UNKNOWN = "unknown"

    @classmethod
    def detect(cls) -> "Architecture":
        raw = platform.machine().lower()
        normalised = {"amd64": "x86_64", "arm64": "aarch64"}.get(raw, raw)
        return cls(normalised) if normalised in cls._value2member_map_ else cls.UNKNOWN

    def is_arm(self) -> bool:
        return self in (Architecture.AARCH64, Architecture.ARM64)


@dataclass(frozen=True)
class SystemCapabilities:
    """Immutable snapshot of a system's capabilities."""

    alias: str
    os: OperatingSystem
    arch: Architecture
    tools: FrozenSet[str] = field(default_factory=frozenset)
    ram_mb: int = 0
    cores: int = 0
    free_disk_mb: int = 0
    labels: FrozenSet[str] = field(default_factory=frozenset)

    def satisfies(self, req: "ModeRequirements") -> "CapabilityVerdict":
        missing_os = req.os and req.os != self.os
        missing_arch = req.arch and req.arch != self.arch
        missing_tools = req.tools - self.tools
        missing_labels = req.labels - self.labels
        ram_ok = self.ram_mb >= req.min_ram_mb if req.min_ram_mb else True
        cores_ok = self.cores >= req.min_cores if req.min_cores else True
        disk_ok = (
            self.free_disk_mb >= req.min_free_disk_mb
            if req.min_free_disk_mb
            else True
        )

        is_met = (
            not missing_os
            and not missing_arch
            and not missing_tools
            and not missing_labels
            and ram_ok
            and cores_ok
            and disk_ok
        )
        return CapabilityVerdict(
            met=is_met,
            missing_os=req.os if missing_os else None,
            missing_arch=req.arch if missing_arch else None,
            missing_tools=frozenset(missing_tools),
            missing_labels=frozenset(missing_labels),
            ram_shortfall_mb=max(0, req.min_ram_mb - self.ram_mb)
            if req.min_ram_mb
            else 0,
            cores_shortfall=max(0, req.min_cores - self.cores)
            if req.min_cores
            else 0,
            disk_shortfall_mb=max(0, req.min_free_disk_mb - self.free_disk_mb)
            if req.min_free_disk_mb
            else 0,
        )

    @classmethod
    def detect_local(cls) -> "SystemCapabilities":
        """Probe the local host and return its capabilities snapshot."""
        import os as _os

        tools: set[str] = set()
        from core.config import RaptorConfig

        for name, dep in RaptorConfig.TOOL_DEPS.items():
            if shutil.which(dep["binary"]):
                tools.add(name)

        try:
            import psutil

            ram_mb = psutil.virtual_memory().total // (1024 * 1024)
            cores = _os.cpu_count() or 1
            disk = psutil.disk_usage("/")
            free_disk_mb = disk.free // (1024 * 1024)
        except ImportError:
            ram_mb = 0
            cores = _os.cpu_count() or 1
            free_disk_mb = 0

        return cls(
            alias="localhost",
            os=OperatingSystem.detect(),
            arch=Architecture.detect(),
            tools=frozenset(tools),
            ram_mb=ram_mb,
            cores=cores,
            free_disk_mb=free_disk_mb,
        )


@dataclass(frozen=True)
class ModeRequirements:
    """What a RAPTOR mode needs from the execution host."""

    mode: str
    os: Optional[OperatingSystem] = None
    arch: Optional[Architecture] = None
    tools: FrozenSet[str] = field(default_factory=frozenset)
    labels: FrozenSet[str] = field(default_factory=frozenset)
    min_ram_mb: int = 0
    min_cores: int = 0
    min_free_disk_mb: int = 0


@dataclass(frozen=True)
class CapabilityVerdict:
    """Result of matching requirements against a system."""

    met: bool
    missing_os: Optional[OperatingSystem] = None
    missing_arch: Optional[Architecture] = None
    missing_tools: FrozenSet[str] = field(default_factory=frozenset)
    missing_labels: FrozenSet[str] = field(default_factory=frozenset)
    ram_shortfall_mb: int = 0
    cores_shortfall: int = 0
    disk_shortfall_mb: int = 0

    def summary(self) -> str:
        if self.met:
            return "all requirements satisfied"
        parts: list[str] = []
        if self.missing_os:
            parts.append(f"needs OS {self.missing_os.value}")
        if self.missing_arch:
            parts.append(f"needs arch {self.missing_arch.value}")
        if self.missing_tools:
            parts.append(f"missing tools: {', '.join(sorted(self.missing_tools))}")
        if self.missing_labels:
            parts.append(
                f"missing labels: {', '.join(sorted(self.missing_labels))}"
            )
        if self.ram_shortfall_mb:
            parts.append(f"needs {self.ram_shortfall_mb} MB more RAM")
        if self.cores_shortfall:
            parts.append(f"needs {self.cores_shortfall} more cores")
        if self.disk_shortfall_mb:
            parts.append(f"needs {self.disk_shortfall_mb} MB more disk")
        return "; ".join(parts)


# Default requirements per mode — each mode can override by shipping
# a ``broker_requirements()`` callable in its entry module, but these
# cover the common case so an operator doesn't need per-mode config.
MODE_REQUIREMENTS: Mapping[str, ModeRequirements] = {
    "scan": ModeRequirements(mode="scan"),
    "sca": ModeRequirements(mode="sca"),
    "codeql": ModeRequirements(
        mode="codeql",
        tools=frozenset({"codeql"}),
        min_ram_mb=4096,
    ),
    "fuzz": ModeRequirements(
        mode="fuzz",
        os=OperatingSystem.LINUX,
        tools=frozenset({"afl++"}),
        min_ram_mb=2048,
    ),
    "web": ModeRequirements(mode="web"),
    "agentic": ModeRequirements(mode="agentic"),
    "frida": ModeRequirements(
        mode="frida",
        tools=frozenset({"frida"}),
    ),
}
