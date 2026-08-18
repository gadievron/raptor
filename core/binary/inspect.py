"""Sandboxed binutils inspection — the one way to run readelf/nm-class
tools over a binary of unverified provenance.

Three families of ELF-inspection code grew independently
(``core/analysis/binary_oracle``, ``packages/exploit_feasibility``,
``packages/binary_analysis/crash_analyser``) with drifting execution
discipline: the binary_oracle runs binutils under the FULL sandbox
(network blocked, Landlock scoped to the binary's parent dir, seccomp,
rlimits — rationale: the tool binaries are RAPTOR-picked but the BYTES
they parse come from the target's build tree or an operator-supplied
path, and binutils' ELF/DWARF parsers have a long CVE history), while
the other two families ran the same tools with ``run_trusted`` (safe
env + rlimits only, no isolation).

This module adopts the strict posture as the shared default and hands
back RAW streams so each consumer's parsing stays byte-identical —
parse consolidation is deliberately out of scope (binary_oracle's
parses are corpus-precision-validated; it keeps its own ``_run`` /
``_stream`` for now and is the convergence template, not a consumer).

Allowlisted read-only tools only; list-based argv; never raises —
execution failure surfaces as ``returncode=None`` with empty streams.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = ["InspectResult", "inspect_binary", "nm", "objdump", "readelf"]

# Read-only inspection tools this helper will exec. Anything that can
# write, execute the target, or take a script stays out.
_ALLOWED_TOOLS = frozenset({
    "addr2line",
    "c++filt",
    "checksec",
    "file",
    "nm",
    "objdump",
    "readelf",
    "strings",
})


@dataclass(frozen=True)
class InspectResult:
    """One tool invocation's outcome.

    ``returncode is None`` means the invocation itself failed (tool
    missing, sandbox setup failure, timeout) — distinct from the tool
    running and rejecting the input (non-zero returncode, e.g. readelf
    on a Mach-O). Consumers that only substring-scan ``stdout`` can
    ignore the distinction; consumers that branch on "tool answered"
    check ``returncode == 0``.
    """

    returncode: int | None
    stdout: str = ""
    stderr: str = ""


def inspect_binary(
    tool: str,
    args: tuple[str, ...],
    binary: str | Path,
    *,
    timeout: float = 10,
) -> InspectResult:
    """Run ``tool *args binary`` under the full sandbox.

    The binary's parent directory becomes the sandbox ``target`` so
    the tool can read the file under the mount namespace; network is
    blocked. Never raises.
    """
    if tool not in _ALLOWED_TOOLS:
        raise ValueError(
            f"tool {tool!r} is not an allowlisted inspection tool"
        )
    # Lazy import — keep this module independently importable in unit
    # tests that stub the sandbox (same convention as binary_oracle).
    from core.sandbox import run as _sandbox_run
    try:
        target = str(Path(binary).resolve().parent)
    except OSError:
        return InspectResult(returncode=None)
    try:
        proc = _sandbox_run(
            [tool, *args, str(binary)],
            block_network=True,
            target=target,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("core.binary.inspect: %s failed on %s: %s",
                     tool, binary, exc)
        return InspectResult(returncode=None)
    if proc.returncode != 0:
        logger.debug("core.binary.inspect: %s rc=%s stderr=%s",
                     tool, proc.returncode, (proc.stderr or "")[:200])
    return InspectResult(
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )


def readelf(binary: str | Path, *flags: str,
            timeout: float = 10) -> InspectResult:
    """Sandboxed ``readelf <flags> <binary>``."""
    return inspect_binary("readelf", flags, binary, timeout=timeout)


def nm(binary: str | Path, *flags: str,
       timeout: float = 10) -> InspectResult:
    """Sandboxed ``nm <flags> <binary>``."""
    return inspect_binary("nm", flags, binary, timeout=timeout)


def objdump(binary: str | Path, *flags: str,
            timeout: float = 15) -> InspectResult:
    """Sandboxed ``objdump <flags> <binary>``. NOTE: for whole-binary
    DWARF dumps (multi-GB stdout) use a streaming path, not this."""
    return inspect_binary("objdump", flags, binary, timeout=timeout)
