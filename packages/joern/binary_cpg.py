"""ghidra2cpg wrapper: build a Joern CPG directly from a binary.

One entry point, :func:`build_ghidra_cpg`, runs the ``ghidra2cpg``
frontend (shipped inside the Joern distribution) on a compiled
binary and leaves ``<output_dir>/cpg.bin`` for the caller to bind
with ``GraphClient.import_cpg`` — the bridge that lets `/binary`
targets ride the whole resident-server query stack (tiered taint
sweep, structural_c.sc, ad-hoc CPGQL).

Semantics of the resulting graph differ from a source CPG and the
consumer must say so: methods are Ghidra-recovered functions,
"lineNumber" fields carry VIRTUAL ADDRESSES (decimal), arguments are
registers/P-code temporaries, and literal detection degrades (a
string literal in source is a pointer load in the binary). The
orchestration layer (:mod:`core.orchestration.joern_binary_scan`)
books everything from this channel as address-level evidence.

Containment matches the other JVM spawns in this package
(:mod:`packages.joern.runner`, :mod:`packages.joern.slicing`): the
binary is HOSTILE INPUT — Ghidra parses it but never executes it, the
spawn is sandboxed with the network blocked and CPU limits sized to
the wall timeout, and JVM/Ghidra scratch (``HOME``, ``TMPDIR``,
``user.home`` — Ghidra writes project state under the home dir) is
pinned inside the run-owned output directory. Failures report through
``errors_out`` and return ``None``; callers book that as "no graph",
never as a verdict about the binary.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from .prereqs import _joern_parse_path, joern_tool_paths
from .tunables import sandbox_cpu_limits

logger = logging.getLogger(__name__)

#: Ghidra auto-analysis dominates the wall time; real-world binaries
#: need far longer than a source parse.
DEFAULT_BUILD_TIMEOUT_S = 900

_CPG_NAME = "cpg.bin"

_resolved_ghidra: str | None = None
_ghidra_resolved: bool = False


def ghidra2cpg_path() -> str | None:
    """Resolved ``ghidra2cpg`` launcher, or ``None`` if not installed.

    Resolution rides the ``joern-parse`` resolution from
    :mod:`packages.joern.prereqs` (the frontend launcher ships in the
    same ``joern-cli`` directory), falling back to PATH lookup.
    """
    global _resolved_ghidra, _ghidra_resolved
    if not _ghidra_resolved:
        parse = _joern_parse_path()
        if parse:
            sibling = Path(parse).parent / "ghidra2cpg"
            if sibling.is_file() and os.access(sibling, os.X_OK):
                _resolved_ghidra = str(sibling)
        if _resolved_ghidra is None:
            import shutil
            found = shutil.which("ghidra2cpg")
            _resolved_ghidra = os.path.realpath(found) if found else None
        _ghidra_resolved = True
    return _resolved_ghidra


def reset_ghidra_path_cache() -> None:
    """Clear the cached launcher path (tests patching resolution)."""
    global _resolved_ghidra, _ghidra_resolved
    _resolved_ghidra = None
    _ghidra_resolved = False


def _record_error(errors_out: list | None, message: str) -> None:
    logger.warning("ghidra2cpg: %s", message)
    if errors_out is not None:
        errors_out.append(message)


def build_ghidra_cpg(
    binary_path: Path,
    output_dir: Path,
    *,
    timeout: int = DEFAULT_BUILD_TIMEOUT_S,
    subprocess_runner=None,
    errors_out: list | None = None,
) -> Path | None:
    """Build ``<output_dir>/cpg.bin`` from ``binary_path`` via Ghidra.

    Returns the CPG path on success, ``None`` on any failure (reason in
    ``errors_out``). The output directory is run-owned scratch — the
    build also leaves Ghidra project state there, never in the shared
    CPG cache or the operator's home.
    """
    binary_path = Path(binary_path).resolve()
    output_dir = Path(output_dir).resolve()
    if not binary_path.is_file():
        _record_error(errors_out, f"binary not found: {binary_path}")
        return None
    ghidra_bin = ghidra2cpg_path()
    if not ghidra_bin:
        _record_error(errors_out, "ghidra2cpg frontend not installed")
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    cpg_path = output_dir / _CPG_NAME
    # A graph from a previous attempt must never be bound as this
    # build's result.
    cpg_path.unlink(missing_ok=True)

    cmd = [ghidra_bin, str(binary_path), "-o", str(cpg_path)]

    from .runner import _default_sandbox_runner, _jvm_scratch_command
    cmd = _jvm_scratch_command(cmd, output_dir)
    runner = subprocess_runner or _default_sandbox_runner()

    try:
        proc = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            target=str(binary_path.parent),
            output=str(output_dir),
            block_network=True,
            tool_paths=joern_tool_paths(),
            limits=sandbox_cpu_limits(timeout),
        )
    except TypeError as exc:
        if subprocess_runner is None or "unexpected keyword argument" not in str(exc):
            _record_error(errors_out, f"sandbox rejected ghidra2cpg: {exc}")
            return None
        try:
            # Injected stub runners without the sandbox kwargs. cwd is
            # still pinned: any cwd-relative Ghidra write must land in
            # the run-owned output dir (mirrors the runner.py fallback).
            proc = runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(output_dir),
            )
        except subprocess.TimeoutExpired:
            _record_error(errors_out, f"ghidra2cpg timed out after {timeout}s")
            return None
        except OSError as e:
            _record_error(errors_out, f"ghidra2cpg failed to spawn: {e}")
            return None
    except subprocess.TimeoutExpired:
        _record_error(errors_out, f"ghidra2cpg timed out after {timeout}s")
        return None
    except OSError as e:
        _record_error(errors_out, f"ghidra2cpg failed to spawn: {e}")
        return None

    if proc.returncode != 0:
        stderr = (proc.stderr or "")[:500]
        _record_error(
            errors_out,
            f"ghidra2cpg exited {proc.returncode}: {stderr or '(no stderr)'}")
        return None
    if not cpg_path.is_file() or cpg_path.stat().st_size == 0:
        _record_error(errors_out, "ghidra2cpg exited 0 but wrote no graph")
        return None
    return cpg_path
