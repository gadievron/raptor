"""Bounded joern-slice wrapper: data-flow slices from a cached CPG.

One entry point, :func:`run_data_flow_slice`, runs the ``joern-slice``
CLI in **data-flow mode** against an already-built ``cpg.bin`` (one JVM
boot per call — callers run it once per run, not once per finding) and
returns the parsed slice document::

    {"$type": "DataFlowSlice",
     "nodes": [{id, label, code, name, lineNumber, columnNumber,
                parentFile, parentMethod}, ...],
     "edges": [{src, dst, label}, ...]}

The consumer is `/validate` Stage B
(:func:`core.orchestration.validate_joern.attach_slice_evidence`),
which carves per-finding def-use context out of the whole-program
slice. The wrapper holds the same containment lines as the CPG build
path in :mod:`packages.joern.runner`:

* sandboxed spawn (network blocked, tool roots declared, CPU limits
  sized to the wall timeout), JVM scratch pinned inside the run-owned
  output directory via ``_jvm_scratch_command``;
* bounded JVM heap, admitted against the host-global heap ledger for
  the spawn's duration (the same ``-J-Xmx`` + ``heap_admission``
  discipline as :func:`packages.joern.runner.run_query`) — an
  unbounded or unadmittable heap refuses rather than over-committing
  memory concurrent runs believe is free;
* the output JSON is size-bounded before it is read
  (:data:`MAX_SLICE_BYTES`) — a pathological or hostile CPG must not
  balloon the orchestrator;
* failures report through ``errors_out`` and return ``None`` — the
  caller's tri-state convention books that as "no verdict", never as
  evidence against a finding.

Argument order is load-bearing and verified empirically against the
shipped CLI (scopt command parsing): data-flow options come straight
after the ``data-flow`` command, the CPG path follows them, and
top-level options (``-o``, the filters) come last. The CPG positional
is silently IGNORED when it appears before the command options and the
tool then loads ``./cpg.bin`` — the canonical order below is pinned by
tests.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path

from .heap_ledger import heap_admission
from .prereqs import _joern_parse_path, joern_tool_paths
from .tunables import JoernTunables, sandbox_cpu_limits

logger = logging.getLogger(__name__)

#: Upper bound on the slice JSON read back from disk. A whole-program
#: reaching-definition slice of a fixture is tens of KB; multi-MB is a
#: large target; past this bound the document is refused unread.
MAX_SLICE_BYTES = 64 * 1024 * 1024

#: Output base name handed to ``-o`` — the tool appends ``.json``.
_SLICE_BASENAME = "dataflow-slice"

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_resolved_slice: str | None = None
_slice_resolved: bool = False


def joern_slice_path() -> str | None:
    """Resolved ``joern-slice`` launcher, or ``None`` if not installed.

    Resolution rides the ``joern-parse`` resolution from
    :mod:`packages.joern.prereqs` (the slicer ships in the same
    ``joern-cli`` directory), falling back to PATH lookup.
    """
    global _resolved_slice, _slice_resolved
    if not _slice_resolved:
        parse = _joern_parse_path()
        if parse:
            sibling = Path(parse).parent / "joern-slice"
            if sibling.is_file() and os.access(sibling, os.X_OK):
                _resolved_slice = str(sibling)
        if _resolved_slice is None:
            import shutil
            found = shutil.which("joern-slice")
            _resolved_slice = os.path.realpath(found) if found else None
        _slice_resolved = True
    return _resolved_slice


def reset_slice_path_cache() -> None:
    """Clear the cached launcher path (tests patching resolution)."""
    global _resolved_slice, _slice_resolved
    _resolved_slice = None
    _slice_resolved = False


def _record_error(errors_out: list | None, message: str) -> None:
    logger.warning("joern-slice: %s", message)
    if errors_out is not None:
        errors_out.append(message)


def run_data_flow_slice(
    cpg_path: Path,
    output_dir: Path,
    *,
    slice_depth: int = 20,
    file_filter: str | None = None,
    method_filter: str | None = None,
    timeout: int = 300,
    subprocess_runner=None,
    errors_out: list | None = None,
) -> dict | None:
    """Run ``joern-slice data-flow`` on ``cpg_path``; parsed doc or ``None``.

    ``method_filter`` must be a plain identifier — it is anchored into
    the tool's regex filter, so a caller cannot smuggle an unbounded
    pattern into the JVM. ``file_filter`` is a file name (matched
    verbatim by the tool, no regex). Every failure path records a
    message in ``errors_out`` and returns ``None``; the output document
    (``<output_dir>/dataflow-slice.json``) is left on disk for the
    audit trail when the run succeeds.
    """
    cpg_path = Path(cpg_path).resolve()
    output_dir = Path(output_dir).resolve()
    if not cpg_path.is_file():
        _record_error(errors_out, f"CPG not found: {cpg_path}")
        return None
    slice_bin = joern_slice_path()
    if not slice_bin:
        _record_error(errors_out, "joern-slice launcher not installed")
        return None
    if (isinstance(slice_depth, bool) or not isinstance(slice_depth, int)
            or slice_depth < 1):
        _record_error(
            errors_out,
            f"slice depth must be a positive integer: {slice_depth!r}")
        return None
    if method_filter is not None and not _IDENTIFIER_RE.fullmatch(method_filter):
        _record_error(
            errors_out,
            f"method filter must be an identifier: {method_filter!r}")
        return None
    if file_filter is not None and not file_filter.isprintable():
        _record_error(errors_out, "file filter carries non-printable bytes")
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    out_base = output_dir / _SLICE_BASENAME
    out_json = output_dir / f"{_SLICE_BASENAME}.json"
    # A stale document from a previous attempt must never be read back
    # as this run's result.
    out_json.unlink(missing_ok=True)

    # Same fail-closed heap posture as run_query: the slicer JVM never
    # runs with the platform-default (unbounded, un-ledgered) heap.
    tunables = JoernTunables.from_tuning()
    if tunables.heap_mb is None:
        _record_error(errors_out, "joern-slice requires a bounded heap")
        return None

    from .runner import _default_sandbox_runner, _jvm_scratch_command
    runner = subprocess_runner or _default_sandbox_runner()

    try:
        with heap_admission(tunables.heap_mb, derived=tunables.heap_is_derived,
                            require_capacity=True) as granted_mb:
            # Canonical argument order (see module docstring): the
            # launcher strips -J flags itself, then command options,
            # the CPG positional, and top-level options last.
            cmd = [slice_bin, f"-J-Xmx{granted_mb}m", "data-flow",
                   "--slice-depth", str(slice_depth),
                   str(cpg_path), "-o", str(out_base)]
            if file_filter is not None:
                cmd.extend(["--file-filter", file_filter])
            if method_filter is not None:
                cmd.extend(["--method-name-filter", f"^{method_filter}$"])
            cmd = _jvm_scratch_command(cmd, output_dir)

            try:
                proc = runner(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    target=str(cpg_path.parent),
                    output=str(output_dir),
                    block_network=True,
                    tool_paths=joern_tool_paths(),
                    limits=sandbox_cpu_limits(timeout),
                )
            except TypeError as exc:
                if (subprocess_runner is None
                        or "unexpected keyword argument" not in str(exc)):
                    _record_error(
                        errors_out, f"sandbox rejected joern-slice: {exc}")
                    return None
                # Injected stub runners without the sandbox kwargs. cwd
                # is still pinned: any cwd-relative JVM write must land
                # in the run-owned output dir (mirrors runner.py).
                proc = runner(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=str(output_dir),
                )
    except subprocess.TimeoutExpired:
        _record_error(errors_out, f"joern-slice timed out after {timeout}s")
        return None
    except OSError as e:
        # Heap-admission refusals (no ledger capacity) and spawn
        # failures both land here — either way the slice did not run.
        _record_error(errors_out, f"joern-slice could not run: {e}")
        return None

    if proc.returncode != 0:
        stderr = (proc.stderr or "")[:500]
        _record_error(
            errors_out,
            f"joern-slice exited {proc.returncode}: {stderr or '(no stderr)'}")
        return None
    if not out_json.is_file():
        _record_error(errors_out, "joern-slice exited 0 but wrote no document")
        return None
    if out_json.is_symlink():
        # Defence in depth: the slicer writes a regular file; a symlink
        # here is planted, and following it would read outside the
        # run-owned directory.
        _record_error(errors_out, "slice document is a symlink — refused")
        return None
    size = out_json.stat().st_size
    if size > MAX_SLICE_BYTES:
        _record_error(
            errors_out,
            f"slice document too large ({size} bytes > {MAX_SLICE_BYTES})")
        return None
    from core.json import load_json
    try:
        # strict=True surfaces the parse error for errors_out;
        # RecursionError covers a hostile deeply-nested document
        # (same containment as core.json.load_json's non-strict lane).
        doc = load_json(out_json, strict=True, max_bytes=MAX_SLICE_BYTES)
    except (OSError, ValueError, RecursionError) as e:
        _record_error(errors_out, f"slice document unreadable: {e}")
        return None
    if (not isinstance(doc, dict)
            or doc.get("$type") != "DataFlowSlice"
            or not isinstance(doc.get("nodes"), list)
            or not isinstance(doc.get("edges"), list)):
        _record_error(errors_out, "slice document has an unexpected shape")
        return None
    return doc
