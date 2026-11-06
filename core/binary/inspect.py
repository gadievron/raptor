"""Sandboxed binutils inspection — the one way to run readelf/nm-class
tools over a binary of unverified provenance.

Trusted tools parse attacker-controlled ELF/DWARF bytes. Inspection admits
system runtime paths, the input directory and declared tool runtime; HOME,
cwd and writes use disposable scratch. The shared untrusted floor governs
backend selection and explicit operator consent.

Raw streams remain available to existing consumers. Ordinary subprocess
failures return ``returncode=None``; isolation refusals propagate so callers
cannot mistake an unavailable sandbox for clean analysis.
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
    missing or timeout) — distinct from the tool
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

    The input directory is read-only; HOME, cwd and writes use private
    scratch. Network is blocked and the shared untrusted floor applies. Ordinary subprocess failures do not raise (``returncode=None``);
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
    from core.run.scratch import scratch_dir
    from core.sandbox import run as _sandbox_run
    try:
        # The resolved path is used in argv too, not just for the
        # sandbox target: a caller-spelled relative name could be
        # dash-leading or @-leading (binutils option / response-file
        # expansion inside the sandbox); an absolute path is inert.
        resolved = Path(binary).resolve()
    except OSError:
        return InspectResult(returncode=None)
    try:
        from core.binary._inspection_policy import inspection_command, inspection_options
        from core.security.env_sanitisation import subprocess_tmpdir
        with scratch_dir("raptor-bininspect-", dir=subprocess_tmpdir(), keepalive=True) as scratch_path:
            scratch = str(scratch_path)
            proc = _sandbox_run(
                inspection_command([tool, *args, str(resolved), *operands], scratch),
                **inspection_options(resolved, tool, scratch),
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=timeout,
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
