"""Corroborate GCC stack-return candidates with Clang's path-sensitive checker.

The frontend warns even inside an unreachable ``if (0)`` arm. Its warning is
only a candidate, not a finding. A successful second analysis must report a
stack address returned to the caller at the same attributable source point.
Neither compiler's silence is a refutation.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from heapq import nsmallest
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.atomic_fs import write_bytes_atomically
from core.run.scratch import scratch_dir

if TYPE_CHECKING:
    from core.audit.preprocessor_view import ExpandedView

from .budget import WorkBudget, bounded_futures
from .compiler import CompilerRequest, run_compiler_analysis
from .pipeline import Detector, DetectorResult, Stage, StageResult, run_detector

RULE_ID = "raptor.compiler.stack-return"
CANDIDATE_ID = "-Wreturn-local-addr"
_CLANG_ID = "core.StackAddressEscape"
_MAX_TUS = 50
_MAX_LOCATIONS = 256


@dataclass
class StackReturnAnalysis:
    target: Path
    seeds: dict[str, list[dict[str, Any]]]
    request_for: Callable[[str, Path], CompilerRequest] | None
    sandbox_run: Callable[..., Any] | None
    locate: Callable[[dict[str, Any], str], tuple[str, int] | None] | None
    prepare_view: Callable[[str, Path], ExpandedView] | None
    scratch_root: str | None = None
    max_workers: int = 4
    candidates: dict[str, set[tuple[str, int]]] = field(default_factory=dict)
    diagnostics: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    limitations: list[dict[str, str]] = field(default_factory=list)
    budget: WorkBudget | None = None


def _candidates(state: StackReturnAnalysis) -> StageResult:
    assert state.locate is not None
    selected = nsmallest(_MAX_TUS, state.seeds.items(), key=lambda item: item[0])
    if len(state.seeds) > _MAX_TUS:
        skipped = len(state.seeds) - _MAX_TUS
        state.limitations.append({"tu": "", "reason": f"stack-return candidate cap skipped {skipped} TU(s)"})
    for tu, diagnostics in selected:
        points = set()
        if len(diagnostics) > _MAX_LOCATIONS:
            state.limitations.append({"tu": tu, "reason": "stack-return candidate location budget exhausted"})
        for diagnostic in diagnostics[:_MAX_LOCATIONS]:
            if diagnostic.get("id") != CANDIDATE_ID or diagnostic.get("kind") != "warning":
                continue
            point = state.locate(diagnostic, tu)
            if point is not None:
                points.add(point)
        if points:
            state.candidates[tu] = points
    if not state.candidates:
        return StageResult("skipped", "no GCC stack-return candidates")
    if state.request_for is None:
        state.limitations.append({"tu": "", "reason": "stack-return corroboration requires Clang"})
        return StageResult("skipped", "Clang unavailable")
    return StageResult()


def _corroborate(state: StackReturnAnalysis) -> StageResult:
    request_for, sandbox_run = state.request_for, state.sandbox_run
    prepare_view, locate = state.prepare_view, state.locate
    assert request_for is not None and sandbox_run is not None
    assert prepare_view is not None and locate is not None

    def one(tu):
        with scratch_dir("stack_return_", dir=state.scratch_root) as scratch:
            view = prepare_view(tu, scratch)
            if not view.ok:
                detail = "; ".join(str(e) for e in view.errors[:2])[:160]
                raise RuntimeError("GCC preprocessed source view unavailable" + (": " + detail if detail else ""))
            source = (scratch / "view.c").resolve()
            write_bytes_atomically(source, view.text.encode("utf-8", errors="replace"))
            # Freeze GCC's macro decisions. Analyzing the original source under
            # Clang could select a different __clang__/__GNUC__ conditional arm.
            execution = run_compiler_analysis(request_for(tu, source), sandbox_run)
            record = execution.value.record
            if (execution.status != "complete" or record is None
                    or any("error" in str(d.get("kind", "")) for d in record["diags"])):
                errors = [str(d.get("message", "")) for d in (record or {}).get("diags", [])
                          if "error" in str(d.get("kind", ""))][:2]
                detail = "; ".join(errors)[:160]
                raise RuntimeError("Clang analysis did not complete successfully" + (": " + detail if detail else ""))
            matches = []
            for diagnostic in record["diags"]:
                if (diagnostic.get("id") != _CLANG_ID or diagnostic.get("kind") != "warning"
                        or "returned to caller" not in str(diagnostic.get("message", "")).lower()):
                    continue
                path = Path(diagnostic.get("file", ""))
                if not path.is_absolute():
                    path = source.parent / path
                # The compiler was given this exact private path. Do not
                # resolve a target-controlled diagnostic filename as a read grant.
                if path != source:
                    continue
                line = diagnostic.get("line", 0)
                if not isinstance(line, int) or isinstance(line, bool) or line <= 0:
                    continue
                origin = view.origin_of(line)
                if origin is None:
                    continue
                mapped = {**diagnostic, "file": str(state.target / origin[0]), "line": origin[1]}
                if locate(mapped, tu) in state.candidates[tu]:
                    matches.append(mapped)
            return matches

    attempted = set()
    for tu, future in bounded_futures(sorted(state.candidates), one,
                                     workers=state.max_workers, budget=state.budget):
        attempted.add(tu)
        try:
            state.diagnostics[tu] = future.result()
        except Exception as exc:
            state.limitations.append({
                "tu": tu, "reason": f"stack-return corroboration failed: {str(exc)[:200]}",
            })
    skipped = len(state.candidates) - len(attempted)
    if skipped:
        state.limitations.append({"tu": "", "reason": f"stack-return analysis budget skipped {skipped} TU(s)"})
    state.limitations.sort(key=lambda item: (item["tu"], item["reason"]))
    return StageResult("partial" if state.limitations else "complete")


DETECTOR = Detector(
    "stack-return", "1", (Stage("candidates", _candidates), Stage("clang", _corroborate)),
)


def run_stack_return(
    target: Path, seeds: dict[str, list[dict[str, Any]]], *,
    request_for: Callable[[str, Path], CompilerRequest] | None,
    sandbox_run: Callable[..., Any],
    locate: Callable[[dict[str, Any], str], tuple[str, int] | None],
    prepare_view: Callable[[str, Path], ExpandedView],
    scratch_root: str | None = None, max_workers: int = 4,
    budget: WorkBudget | None = None,
) -> DetectorResult[StackReturnAnalysis]:
    """Analyze only candidates from capped, baseline-successful GCC C TUs.

    A supplied prepare_view must honor the shared budget in its blocking tools,
    as the scan adapter does. Compiler invocations are clipped here.
    """
    state = StackReturnAnalysis(
        Path(target).resolve(), seeds, request_for,
        budget.runner(sandbox_run) if budget is not None else sandbox_run,
        locate, prepare_view, scratch_root, max_workers, budget=budget,
    )
    try:
        return run_detector(DETECTOR, state)
    finally:
        # Workers are joined before return; retain outcomes, not caller inputs.
        state.seeds = {}
        state.request_for = None
        state.sandbox_run = None
        state.locate = None
        state.prepare_view = None
