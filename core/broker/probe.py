"""Remote system probing — discover capabilities of a remote host.

Connects to a remote system via its transport, runs lightweight
detection commands, and returns a SystemCapabilities snapshot.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from core.broker.capabilities import (
    Architecture,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.transport import RemoteSystemEntry, Transport, TransportError

logger = logging.getLogger(__name__)

# Tool binary names to probe — subset of RaptorConfig.TOOL_DEPS plus
# common system utilities the provisioner needs.
_PROBE_TOOLS = (
    "afl-fuzz",
    "codeql",
    "semgrep",
    "gdb",
    "rr",
    "frida",
    "frida-trace",
    "jadx",
    "spatch",
    "python3",
    "pip3",
    "git",
    "rsync",
    "gcc",
    "make",
    "cmake",
)

# Map binary name -> RAPTOR tool-dep name
_BINARY_TO_TOOL = {
    "afl-fuzz": "afl++",
    "spatch": "coccinelle",
    "frida-trace": "frida-trace",
}


def probe_system(
    transport: Transport,
    entry: RemoteSystemEntry,
) -> SystemCapabilities:
    """Probe a remote system and return its capabilities."""

    os_info = _detect_os(transport)
    arch = _detect_arch(transport, os_info)
    tools = _detect_tools(transport, os_info)
    ram_mb = _detect_ram(transport, os_info)
    cores = _detect_cores(transport, os_info)
    free_disk_mb = _detect_disk(transport, os_info)

    return SystemCapabilities(
        alias=entry.alias,
        os=os_info,
        arch=arch,
        tools=frozenset(tools),
        ram_mb=ram_mb,
        cores=cores,
        free_disk_mb=free_disk_mb,
        labels=entry.labels,
    )


def _detect_os(transport: Transport) -> OperatingSystem:
    result = transport.run("uname -s 2>/dev/null || echo UNKNOWN", timeout=10)
    if result.ok:
        raw = result.stdout.strip().lower()
        if raw == "linux":
            return OperatingSystem.LINUX
        if raw == "darwin":
            return OperatingSystem.DARWIN

    result = transport.run(
        '$env:OS 2>$null; if (-not $?) { echo "UNKNOWN" }', timeout=10
    )
    if result.ok and "windows" in result.stdout.lower():
        return OperatingSystem.WINDOWS

    return OperatingSystem.UNKNOWN


def _detect_arch(
    transport: Transport, os_info: OperatingSystem
) -> Architecture:
    if os_info == OperatingSystem.WINDOWS:
        result = transport.run(
            "$env:PROCESSOR_ARCHITECTURE", timeout=10
        )
        if result.ok:
            raw = result.stdout.strip().lower()
            if raw == "amd64":
                return Architecture.X86_64
            if raw in ("arm64", "aarch64"):
                return Architecture.AARCH64
    else:
        result = transport.run("uname -m", timeout=10)
        if result.ok:
            raw = result.stdout.strip().lower()
            norm = {"amd64": "x86_64", "arm64": "aarch64"}.get(raw, raw)
            try:
                return Architecture(norm)
            except ValueError:
                pass

    return Architecture.UNKNOWN


def _detect_tools(
    transport: Transport, os_info: OperatingSystem
) -> set[str]:
    tools: set[str] = set()
    for binary in _PROBE_TOOLS:
        if os_info == OperatingSystem.WINDOWS:
            result = transport.run(
                f'Get-Command "{binary}" -ErrorAction SilentlyContinue '
                f"| Select-Object -ExpandProperty Source",
                timeout=10,
            )
        else:
            result = transport.run(f"which {binary} 2>/dev/null", timeout=10)

        if result.ok and result.stdout.strip():
            tool_name = _BINARY_TO_TOOL.get(binary, binary)
            tools.add(tool_name)

    return tools


def _detect_ram(
    transport: Transport, os_info: OperatingSystem
) -> int:
    try:
        if os_info == OperatingSystem.LINUX:
            result = transport.run(
                "awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo",
                timeout=10,
            )
            if result.ok:
                return int(result.stdout.strip())
        elif os_info == OperatingSystem.DARWIN:
            result = transport.run("sysctl -n hw.memsize", timeout=10)
            if result.ok:
                return int(result.stdout.strip()) // (1024 * 1024)
        elif os_info == OperatingSystem.WINDOWS:
            result = transport.run(
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory "
                "/ 1MB -as [int]",
                timeout=10,
            )
            if result.ok:
                return int(result.stdout.strip())
    except (ValueError, TransportError):
        pass
    return 0


def _detect_cores(
    transport: Transport, os_info: OperatingSystem
) -> int:
    try:
        if os_info == OperatingSystem.LINUX:
            result = transport.run("nproc", timeout=10)
            if result.ok:
                return int(result.stdout.strip())
        elif os_info == OperatingSystem.DARWIN:
            result = transport.run("sysctl -n hw.ncpu", timeout=10)
            if result.ok:
                return int(result.stdout.strip())
        elif os_info == OperatingSystem.WINDOWS:
            result = transport.run(
                "$env:NUMBER_OF_PROCESSORS", timeout=10
            )
            if result.ok:
                return int(result.stdout.strip())
    except (ValueError, TransportError):
        pass
    return 0


def _detect_disk(
    transport: Transport, os_info: OperatingSystem
) -> int:
    try:
        if os_info in (OperatingSystem.LINUX, OperatingSystem.DARWIN):
            result = transport.run(
                "df -m / | awk 'NR==2 {print $4}'", timeout=10
            )
            if result.ok:
                return int(result.stdout.strip())
        elif os_info == OperatingSystem.WINDOWS:
            result = transport.run(
                "(Get-PSDrive C).Free / 1MB -as [int]", timeout=10
            )
            if result.ok:
                return int(result.stdout.strip())
    except (ValueError, TransportError):
        pass
    return 0
