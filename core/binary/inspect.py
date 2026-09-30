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

__all__ = ["InspectResult", "addr2line", "inspect_binary", "nm", "objdump",
           "readelf"]

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
    operands: tuple[str, ...] = (),
    timeout: float = 10,
) -> InspectResult:
    """Run ``tool *args binary *operands`` under the full sandbox.

    The binary's parent directory becomes the sandbox ``target`` so
    the tool can read the file under the mount namespace; network is
    blocked. Never raises on execution failure (``returncode=None``);
    raises ``ValueError`` only on caller-contract violations (tool not
    allowlisted, option-shaped operand).

    ``operands`` land AFTER the binary path in the argv — for tools
    whose positional inputs follow the file operand (addr2line's
    addresses after ``-e <binary>``). They must be plain values, never
    options: a dash- or @-leading operand would be parsed as a flag /
    response file by binutils, so it is refused here rather than
    passed through.
    """
    if tool not in _ALLOWED_TOOLS:
        msg = f"tool {tool!r} is not an allowlisted inspection tool"
        raise ValueError(msg)
    for operand in operands:
        if operand.startswith(("-", "@")):
            msg = f"operand {operand!r} is option-shaped; refusing"
            raise ValueError(msg)
    # Lazy import — keep this module independently importable in unit
    # tests that stub the sandbox (same convention as binary_oracle).
    from core.sandbox import run as _sandbox_run
    try:
        # The resolved path is used in argv too, not just for the
        # sandbox target: a caller-spelled relative name could be
        # dash-leading or @-leading (binutils option / response-file
        # expansion inside the sandbox); an absolute path is inert.
        resolved = Path(binary).resolve()
        target = str(resolved.parent)
    except OSError:
        return InspectResult(returncode=None)
    try:
        proc = _sandbox_run(
            [tool, *args, str(resolved), *operands],
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


def addr2line(binary: str | Path, *addresses: str,
              timeout: float = 10) -> InspectResult:
    """Sandboxed ``addr2line -f -C -e <binary> <addresses...>``.

    The addresses are positional operands after the binary path;
    ``inspect_binary`` refuses option-shaped values, so callers can
    pass parsed (hex-validated) addresses straight through.
    """
    return inspect_binary("addr2line", ("-f", "-C", "-e"), binary,
                          operands=addresses, timeout=timeout)


def nm(binary: str | Path, *flags: str,
       timeout: float = 10) -> InspectResult:
    """Sandboxed ``nm <flags> <binary>``."""
    return inspect_binary("nm", flags, binary, timeout=timeout)


def objdump(binary: str | Path, *flags: str,
            timeout: float = 15) -> InspectResult:
    """Sandboxed ``objdump <flags> <binary>``. NOTE: for whole-binary
    DWARF dumps (multi-GB stdout) use a streaming path, not this."""
    return inspect_binary("objdump", flags, binary, timeout=timeout)
