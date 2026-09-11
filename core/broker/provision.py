"""Remote system provisioning — install missing tools on remote hosts.

Given a capability verdict that lists missing tools, generates and
executes the install commands appropriate for the remote system's OS
and package manager.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from core.broker.capabilities import CapabilityVerdict, OperatingSystem
from core.broker.transport import CommandResult, Transport, TransportError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProvisionResult:
    """Outcome of a provisioning attempt."""

    tool: str
    success: bool
    message: str


# Package manager detection commands (tried in order)
_PM_DETECT = {
    OperatingSystem.LINUX: [
        ("apt-get", "which apt-get"),
        ("dnf", "which dnf"),
        ("yum", "which yum"),
        ("pacman", "which pacman"),
        ("apk", "which apk"),
        ("zypper", "which zypper"),
    ],
    OperatingSystem.DARWIN: [
        ("brew", "which brew"),
    ],
    OperatingSystem.WINDOWS: [
        ("choco", "Get-Command choco -ErrorAction SilentlyContinue"),
        ("winget", "Get-Command winget -ErrorAction SilentlyContinue"),
        ("scoop", "Get-Command scoop -ErrorAction SilentlyContinue"),
    ],
}

# Install recipes per tool per package manager.
# Each value is a list of commands to run in sequence.
_INSTALL_RECIPES: Mapping[str, Mapping[str, list[str]]] = {
    "afl++": {
        "apt-get": [
            "apt-get update -qq",
            "apt-get install -y afl++ afl++-clang",
        ],
        "dnf": ["dnf install -y american-fuzzy-lop"],
        "brew": [
            "echo 'AFL++ requires Linux — install in a Linux VM or container'"
        ],
    },
    "codeql": {
        "apt-get": [
            "curl -fsSL https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip -o /tmp/codeql.zip",
            "unzip -oq /tmp/codeql.zip -d /opt",
            "ln -sf /opt/codeql/codeql /usr/local/bin/codeql",
            "rm /tmp/codeql.zip",
        ],
        "dnf": [
            "curl -fsSL https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip -o /tmp/codeql.zip",
            "unzip -oq /tmp/codeql.zip -d /opt",
            "ln -sf /opt/codeql/codeql /usr/local/bin/codeql",
            "rm /tmp/codeql.zip",
        ],
        "brew": ["brew install codeql"],
        "choco": ["choco install codeql -y"],
    },
    "semgrep": {
        "apt-get": ["pip3 install semgrep"],
        "dnf": ["pip3 install semgrep"],
        "brew": ["brew install semgrep"],
        "pacman": ["pip3 install semgrep"],
        "choco": ["pip3 install semgrep"],
    },
    "gdb": {
        "apt-get": ["apt-get update -qq", "apt-get install -y gdb"],
        "dnf": ["dnf install -y gdb"],
        "pacman": ["pacman -S --noconfirm gdb"],
        "brew": ["brew install gdb"],
    },
    "rr": {
        "apt-get": ["apt-get update -qq", "apt-get install -y rr"],
        "dnf": ["dnf install -y rr"],
    },
    "frida": {
        "apt-get": ["pip3 install frida-tools"],
        "dnf": ["pip3 install frida-tools"],
        "brew": ["pip3 install frida-tools"],
        "choco": ["pip3 install frida-tools"],
    },
    "coccinelle": {
        "apt-get": ["apt-get update -qq", "apt-get install -y coccinelle"],
        "dnf": ["dnf install -y coccinelle"],
        "brew": ["brew install coccinelle"],
    },
    "python3": {
        "apt-get": [
            "apt-get update -qq",
            "apt-get install -y python3 python3-pip python3-venv",
        ],
        "dnf": ["dnf install -y python3 python3-pip"],
        "brew": ["brew install python@3"],
        "choco": ["choco install python3 -y"],
    },
    "git": {
        "apt-get": ["apt-get update -qq", "apt-get install -y git"],
        "dnf": ["dnf install -y git"],
        "brew": ["brew install git"],
        "choco": ["choco install git -y"],
    },
}


def detect_package_manager(
    transport: Transport, os_info: OperatingSystem
) -> Optional[str]:
    """Detect which package manager is available on the remote system."""
    candidates = _PM_DETECT.get(os_info, [])
    for name, check_cmd in candidates:
        result = transport.run(check_cmd, timeout=10)
        if result.ok and result.stdout.strip():
            logger.info("detected package manager: %s", name)
            return name
    return None


def provision_tools(
    transport: Transport,
    os_info: OperatingSystem,
    missing_tools: frozenset[str],
    *,
    dry_run: bool = False,
) -> list[ProvisionResult]:
    """Install *missing_tools* on the remote system.

    Returns a result per tool.  In dry-run mode, commands are logged
    but not executed.
    """
    pm = detect_package_manager(transport, os_info)
    if not pm:
        return [
            ProvisionResult(
                tool=t,
                success=False,
                message="no supported package manager found on remote system",
            )
            for t in sorted(missing_tools)
        ]

    results: list[ProvisionResult] = []
    for tool in sorted(missing_tools):
        recipes = _INSTALL_RECIPES.get(tool, {})
        commands = recipes.get(pm)
        if not commands:
            results.append(
                ProvisionResult(
                    tool=tool,
                    success=False,
                    message=f"no install recipe for {tool} via {pm}",
                )
            )
            continue

        if dry_run:
            results.append(
                ProvisionResult(
                    tool=tool,
                    success=True,
                    message=f"[dry-run] would run: {'; '.join(commands)}",
                )
            )
            continue

        success = True
        last_msg = ""
        for cmd in commands:
            logger.info("provisioning %s: %s", tool, cmd)
            result = transport.run(cmd, timeout=600)
            if not result.ok:
                success = False
                last_msg = result.stderr.strip() or result.stdout.strip()
                logger.warning(
                    "provision command failed for %s: %s", tool, last_msg
                )
                break
            last_msg = "installed successfully"

        results.append(
            ProvisionResult(tool=tool, success=success, message=last_msg)
        )

    return results
