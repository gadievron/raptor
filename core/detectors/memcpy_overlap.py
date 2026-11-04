"""Compose internal Semgrep candidates with a supplemental GCC overlap pass.

The ordinary compiler pass remains authoritative for its own diagnostics. This
pass disables memcpy builtin lowering so GCC's analyzer can see the copy call;
using that flag globally loses other diagnostics. Only confirmed overlap
warnings from successful compiles leave this module. Silence never refutes a
hypothesis. Candidate errors and unsupported compilers limit this pass only.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
import os
import math
from time import monotonic

from core.run.scratch import scratch_dir

from .compiler import CompilerRequest, run_compiler_analysis
from .pipeline import Detector, DetectorResult, Stage, StageResult, run_detector
from .semgrep import PreparedInput, define_semgrep_detector, run_semgrep_analysis

_RULE = Path(__file__).parent / "rules" / "memcpy_candidates.yaml"
_CANDIDATES = define_semgrep_detector("memcpy-overlap-candidates", "1")
# Leave argv headroom for the sandbox launcher and environment on small-ARG_MAX
# platforms. Each batch shares the original overall candidate-scan deadline.
_CANDIDATE_ARG_BYTES = 32_768
_CANDIDATE_SECONDS = 60
_RAW_CANDIDATE_SECONDS = 30
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


def _target_batches(paths: list[Path]) -> Iterator[tuple[Path, ...]]:
    batch: list[Path] = []
    used = 0
    for path in paths:
        size = len(os.fsencode(path)) + 1
        if size > _CANDIDATE_ARG_BYTES:
            raise ValueError("candidate path exceeds argument budget")
        if batch and used + size > _CANDIDATE_ARG_BYTES:
            yield tuple(batch)
            batch, used = [], 0
        batch.append(path)
        used += size
    if batch:
        yield tuple(batch)


def _expanded_candidates(state: OverlapAnalysis, paths: set[Path], deadline: float) -> bool:
    """Batch prepared views for still-unselected TUs; return incomplete coverage."""
    from core.audit.expanded_semgrep import build_expanded_corpus, translate_corpus_findings

    root = state.target.resolve()
    files = tuple(sorted(path.relative_to(root).as_posix() for path in paths
                         if path.relative_to(root).as_posix() not in state.candidates))
    if not files:
        return False
    remaining = deadline - monotonic()
    if remaining <= 0:
        _limited(state, "memcpy macro candidate time budget exhausted")
        return True
    assert state.request_for is not None
    request = state.request_for(files[0])
    # The baseline already used this pinned compiler successfully. Reuse it
    # rather than discovering/probing another executable for preprocessing.
    try:
        with scratch_dir("memcpy_candidates_", dir=request.scratch_root) as scratch:
            corpus = build_expanded_corpus(
                root, scratch / "views", files=files, timeout=remaining / 2,
                preprocessor=(request.command[0], "-E", "-x", "c"),
                out_dir=scratch, max_bytes=32 * 1024 * 1024,
            )
            incomplete = bool(corpus.failed or corpus.skipped_budget)
            if incomplete:
                _limited(state, f"memcpy macro preparation incomplete: {corpus.failed} failed, "
                         f"{corpus.skipped_budget} skipped by preparation budget")
            if not corpus.tus:
                return incomplete
            remaining = deadline - monotonic()
            if remaining <= 0:
                _limited(state, "memcpy macro candidate time budget exhausted")
                return True
            prepared = PreparedInput(corpus.root, lambda findings: translate_corpus_findings(corpus, findings))
            execution = run_semgrep_analysis(
                detector=_CANDIDATES, prepare=lambda: nullcontext(prepared),
                rule_config=str(_RULE), timeout=math.ceil(remaining),
            )
            state.candidates.update(match["file"] for match in execution.value.matches
                                    if match["file"] in files)
            if execution.status != "complete" or execution.value.coverage_incomplete:
                _limited(state, "memcpy macro candidate scan was incomplete")
                incomplete = True
            return incomplete
    except (OSError, ValueError):
        _limited(state, "memcpy macro preparation or matching was unavailable")
        return True


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

    paths = set()
    incomplete = False
    for rel in sorted(allowed):
        try:
            if Path(rel).is_absolute() or ".." in Path(rel).parts:
                raise ValueError("not a repository-relative path")
            path = (root / rel).resolve(strict=True)
            path.relative_to(root)
            if not path.is_file():
                raise ValueError("not a regular source file")
            paths.add(path)
        except (ValueError, OSError, RuntimeError):
            _limited(state, "memcpy candidate input is unavailable or outside the target", tu=rel)
            incomplete = True
    deadline = monotonic() + _CANDIDATE_SECONDS
    raw_deadline = min(deadline, monotonic() + _RAW_CANDIDATE_SECONDS)
    for batch in _target_batches(sorted(paths)):
        remaining = raw_deadline - monotonic()
        if remaining <= 0:
            incomplete = True
            break
        prepared = PreparedInput(batch[0], select, extra_targets=batch[1:], target_root=root)

        def prepare(item: PreparedInput = prepared) -> nullcontext[PreparedInput]:
            return nullcontext(item)

        execution = run_semgrep_analysis(
            detector=_CANDIDATES, prepare=prepare,
            rule_config=str(_RULE), timeout=math.ceil(remaining),
        )
        state.candidates.update(m["file"] for m in execution.value.matches)
        incomplete |= execution.status != "complete" or execution.value.coverage_incomplete
    incomplete |= _expanded_candidates(state, paths, deadline)
    if incomplete:
        _limited(state, "memcpy overlap candidate scan was incomplete")
        return StageResult("partial" if state.candidates else "error", "candidate scan incomplete")

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
