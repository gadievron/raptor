"""Sandboxed compiler invocation followed by Python diagnostic parsing.

Callers supply the sandbox runner and trusted parser. They retain toolchain
selection, command construction, caching and evidence policy: diagnostics from
an unsuccessful compile must never become findings or refutations.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
import subprocess
from typing import Any

from core.run.scratch import scratch_dir

from .pipeline import Detector, DetectorResult, Stage, StageResult, run_detector


class CompilerInvocationError(Exception):
    """Distinguish tool invocation failures from parser/analysis failures."""

    def __init__(self, error: Exception):
        super().__init__(str(error))
        self.error = error


@dataclass(frozen=True)
class CompilerRequest:
    command: tuple[str, ...]
    target: Path
    timeout: int
    caller_label: str
    scratch_prefix: str
    parse: Callable[[Path, str], list[dict[str, Any]]]
    scratch_root: str | None = None
    raw_limit: int = 0
    analyze: Callable[[dict[str, Any], Path], Any] | None = None


@dataclass
class CompilerAnalysis:
    request: CompilerRequest
    sandbox_run: Callable[..., Any]
    record: dict[str, Any] | None = None
    result: Any = None
    _resources: ExitStack = field(default_factory=ExitStack, repr=False)
    _workdir: Path | None = field(default=None, repr=False)
    _returncode: int = field(default=0, repr=False)
    _stderr: str = field(default="", repr=False)


def _prepare(state: CompilerAnalysis) -> StageResult:
    request = state.request
    state._workdir = state._resources.enter_context(
        scratch_dir(request.scratch_prefix, dir=request.scratch_root),
    )
    return StageResult()


def _invoke(state: CompilerAnalysis) -> StageResult:
    request = state.request
    assert state._workdir is not None
    try:
        proc = state.sandbox_run(
            list(request.command),
            block_network=True,
            target=str(request.target),
            output=str(state._workdir),
            cwd=str(state._workdir),
            capture_output=True,
            text=True,
            timeout=request.timeout,
            caller_label=request.caller_label,
        )
    except (subprocess.SubprocessError, OSError, ValueError, TypeError) as exc:
        raise CompilerInvocationError(exc) from exc

    state._returncode = proc.returncode
    state._stderr = proc.stderr or ""
    # Even a failed compile needs parsing for its diagnostic error message.
    # The parse stage records the execution failure before any consumer runs.
    return StageResult()


def _parse(state: CompilerAnalysis) -> StageResult:
    assert state._workdir is not None
    request = state.request
    state.record = {
        "returncode": state._returncode,
        "diags": request.parse(state._workdir, state._stderr),
        "raw": state._stderr[:max(0, request.raw_limit)],
    }
    if state._returncode != 0:
        return StageResult("error", f"compiler exited {state._returncode}")
    return StageResult()


def _analyze(state: CompilerAnalysis) -> StageResult:
    assert state.record is not None and state._workdir is not None
    if state.request.analyze is not None:
        state.result = state.request.analyze(state.record, state._workdir)
    return StageResult()


DETECTOR = Detector(
    "compiler-diagnostics", "1",
    (Stage("prepare", _prepare), Stage("invoke", _invoke), Stage("parse", _parse),
     Stage("analyze", _analyze)),
)


def run_compiler_analysis(
    request: CompilerRequest, sandbox_run: Callable[..., Any],
) -> DetectorResult[CompilerAnalysis]:
    """Parse while scratch is live; propagate exceptions after closing it.

    Exceptions stay uncaught so the caller's cache cannot retain a transient
    timeout or invocation failure. Ordinary nonzero exits carry an error record
    that audit can memoize without granting it evidentiary authority.
    """
    state = CompilerAnalysis(request, sandbox_run)
    try:
        with state._resources:
            return run_detector(DETECTOR, state)
    finally:
        state._stderr = ""
