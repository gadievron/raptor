"""Compose internal Semgrep candidates with a supplemental GCC overlap pass.

The ordinary compiler pass remains authoritative for its own diagnostics. This
pass disables memcpy builtin lowering so GCC's analyzer can see the copy call;
using that flag globally loses other diagnostics. Only confirmed overlap
warnings from successful compiles leave this module. Silence never refutes a
hypothesis. Candidate errors and unsupported compilers limit this pass only.
"""
from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
import os

from .compiler import CompilerRequest, run_compiler_analysis
from .pipeline import Detector, DetectorResult, Stage, StageResult, run_detector
from .semgrep import PreparedInput, define_semgrep_detector, run_semgrep_analysis

_RULE = Path(__file__).parent / "rules" / "memcpy_candidates.yaml"
_CANDIDATES = define_semgrep_detector("memcpy-overlap-candidates", "1")
OVERLAP_ID = "-Wanalyzer-overlapping-buffers"


@dataclass
class OverlapAnalysis:
    target: Path
    files: tuple[str, ...]
    request_for: Callable[[str], CompilerRequest] | None
    sandbox_run: Callable[..., Any]
    max_workers: int = 4
    candidates: set[str] = field(default_factory=set)
    diagnostics: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    limitations: list[dict[str, str]] = field(default_factory=list)


def _limited(state: OverlapAnalysis, reason: str, *, tu: str = "") -> None:
    state.limitations.append({"tu": tu, "reason": reason})


def _candidates(state: OverlapAnalysis) -> StageResult:
    if not state.files:
        return StageResult("skipped", "no successfully analyzed C translation units")
    if state.request_for is None:
        _limited(state, "memcpy overlap check requires the GCC analyzer")
        return StageResult("skipped", "GCC analyzer unavailable")
    from packages.semgrep.runner import is_available
    if not is_available():
        _limited(state, "memcpy overlap candidate check requires Semgrep")
        return StageResult("skipped", "Semgrep unavailable")

    allowed = set(state.files)
    root = state.target.resolve()

    def select(findings):
        matches = set()
        for finding in findings:
            path = Path(finding.file)
            if not path.is_absolute():
                path = state.target / path
            try:
                rel = path.resolve().relative_to(root).as_posix()
            except (ValueError, OSError):
                continue
            if rel in allowed:
                matches.add(rel)
        return [{"file": rel} for rel in sorted(matches)], 0

    execution = run_semgrep_analysis(
        detector=_CANDIDATES,
        prepare=lambda: nullcontext(PreparedInput(state.target, select)),
        rule_config=str(_RULE), timeout=30,
    )
    state.candidates = {m["file"] for m in execution.value.matches}
    if execution.status != "complete":
        _limited(state, "memcpy overlap candidate scan was incomplete")
        return StageResult("partial" if state.candidates else "error", execution.reason)
    if not state.candidates:
        return StageResult("skipped", "no memcpy candidates in eligible C files")
    return StageResult()


def _compile(state: OverlapAnalysis) -> StageResult:
    assert state.request_for is not None
    first = state.request_for(sorted(state.candidates)[0])
    # Probe the exact pinned executable once per run. Older GCC remains usable
    # for the baseline; only this detector requires the overlap warning (GCC 14+).
    probe = replace(
        first,
        command=(first.command[0], "-fanalyzer", OVERLAP_ID, "-x", "c",
                 "-fsyntax-only", os.devnull),
        timeout=min(first.timeout, 30), analyze=None,
    )
    try:
        capability = run_compiler_analysis(probe, state.sandbox_run)
        if capability.status != "complete":
            raise RuntimeError("overlap warning option is unavailable")
    except Exception as exc:
        _limited(state, f"memcpy overlap capability probe failed: {str(exc)[:200]}")
        return StageResult("skipped", "overlap capability unavailable")

    def one(rel):
        request = state.request_for(rel)
        execution = run_compiler_analysis(request, state.sandbox_run)
        record = execution.value.record
        if execution.status != "complete" or record is None:
            raise RuntimeError("supplemental compiler did not complete successfully")
        return [d for d in record["diags"]
                if d.get("id") == OVERLAP_ID and d.get("kind") == "warning"]

    with ThreadPoolExecutor(max_workers=max(1, min(state.max_workers, len(state.candidates)))) as pool:
        futures = {pool.submit(one, rel): rel for rel in sorted(state.candidates)}
        for future in as_completed(futures):
            rel = futures[future]
            try:
                state.diagnostics[rel] = future.result()
            except Exception as exc:
                _limited(state, f"memcpy overlap analysis failed: {str(exc)[:200]}", tu=rel)
    state.limitations.sort(key=lambda item: (item["tu"], item["reason"]))
    return StageResult("partial" if state.limitations else "complete")


DETECTOR = Detector(
    "memcpy-overlap", "1",
    (Stage("candidates", _candidates), Stage("compiler", _compile)),
)


def run_memcpy_overlap(
    target: Path, files: tuple[str, ...], *,
    request_for: Callable[[str], CompilerRequest] | None,
    sandbox_run: Callable[..., Any], max_workers: int = 4,
) -> DetectorResult[OverlapAnalysis]:
    """Run only capped, baseline-successful C TUs supplied by the caller."""
    return run_detector(DETECTOR, OverlapAnalysis(
        target, files, request_for, sandbox_run, max_workers,
    ))
