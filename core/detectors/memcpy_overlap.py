"""Compose bounded identifier candidates with a supplemental GCC overlap pass.

The ordinary compiler pass remains authoritative for its own diagnostics. This
pass disables memcpy builtin lowering so GCC's analyzer can see the copy call;
using that flag globally loses other diagnostics. Only confirmed overlap
warnings from successful compiles leave this module. Silence never refutes a
hypothesis. Candidate errors and unsupported compilers limit this pass only.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from heapq import nsmallest
from pathlib import Path
from typing import Any
import os
import re
from time import monotonic

from core.audit.run_memo import BoundedMemo
from .setup import AnalysisSetup
from core.run.scratch import scratch_dir
from core.source import read_text_capped
from core.source.strip import blank_c_noncode

from .budget import WorkBudget, bounded_futures
from .compiler import CompilerRequest, run_compiler_analysis
from .pipeline import Detector, DetectorResult, Stage, StageResult, run_detector

_CANDIDATE_SECONDS = 60
_RAW_CANDIDATE_SECONDS = 30
_RAW_SOURCE_CHARS = 1024 * 1024
OVERLAP_ID = "-Wanalyzer-overlapping-buffers"


@dataclass
class OverlapAnalysis:
    target: Path
    files: tuple[str, ...]
    request_for: Callable[[str], CompilerRequest] | None
    sandbox_run: Callable[..., Any] | None
    max_workers: int = 4
    candidates: set[str] = field(default_factory=set)
    diagnostics: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    limitations: list[dict[str, str]] = field(default_factory=list)
    include_dirs_memo: BoundedMemo[list[str]] | None = None
    setup: AnalysisSetup | None = None
    budget: WorkBudget | None = None


def _limited(state: OverlapAnalysis, reason: str, *, tu: str = "") -> None:
    state.limitations.append({"tu": tu, "reason": reason})


_EXPANDED_BYTE_BUDGET = 32 * 1024 * 1024
_MEMCPY_TOKEN = re.compile(r"(?<![\w$])memcpy(?![\w$])")


def _expanded_candidates(state: OverlapAnalysis, paths: set[Path], deadline: float) -> bool:
    """Select source-attributed memcpy identifiers, independent of parser versions.

    This is deliberately an over-approximation, not a call or bug judgment:
    parenthesized calls and function-pointer references also justify analyzing
    the TU. Only successful GCC overlap diagnostics can become findings.
    """
    from core.audit.preprocessor_view import _AUGMENT_FILE_CAP, expand_translation_unit

    root = state.target.resolve()
    eligible = 0

    def remaining_files():
        nonlocal eligible
        for path in paths:
            rel = path.relative_to(root).as_posix()
            if rel not in state.candidates:
                eligible += 1
                yield rel

    # Enumerate even at a zero cap so omitted-file counts remain exact.
    files = nsmallest(max(1, _AUGMENT_FILE_CAP), remaining_files())
    if _AUGMENT_FILE_CAP <= 0:
        files = []
    if not eligible:
        return False
    assert state.request_for is not None
    failed = processed_bytes = 0
    skipped = eligible - len(files)
    if not files:
        _limited(state, f"memcpy macro preparation incomplete: 0 failed, "
                 f"{skipped} skipped by preparation budget")
        return True
    try:
        first = state.request_for(files[0])
        with scratch_dir("memcpy_candidates_", dir=first.scratch_root) as scratch:
            for index, rel in enumerate(files):
                remaining = deadline - monotonic()
                if state.budget is not None:
                    remaining = min(remaining, state.budget.remaining())
                if remaining <= 0:
                    skipped = eligible - index
                    break
                request = state.request_for(rel)
                view = expand_translation_unit(
                    target_path=root, file_path=rel, out_dir=scratch,
                    preprocessor=(request.command[0], "-E", "-x", "c"), timeout=remaining,
                    include_dirs_memo=state.include_dirs_memo, setup=state.setup,
                )
                if not view.ok:
                    failed += 1
                    continue
                if deadline - monotonic() <= 0:
                    skipped = eligible - index
                    break
                processed_bytes += len(view.text.encode("utf-8", errors="replace"))
                if processed_bytes > _EXPANDED_BYTE_BUDGET:
                    skipped = eligible - index
                    break
                # Reuse the C comment/string blanker. Preprocessing has already
                # removed inactive arms and spliced escaped newlines. Do not
                # remove header declarations or reparse the translation unit:
                # compiler extensions must not hide a later candidate token.
                origins = {rel, (root / rel).resolve().relative_to(root).as_posix()}
                code = blank_c_noncode(view.text, allow_digit_separators=True)
                lineno = 1
                previous = 0
                for match in _MEMCPY_TOKEN.finditer(code):
                    # cpp maps count literal newlines. Count disjoint spans
                    # only at tokens instead of allocating every source line.
                    lineno += code.count("\n", previous, match.start())
                    previous = match.start()
                    origin = view.origin_of(lineno)
                    if origin is not None and origin[0] in origins:
                        state.candidates.add(rel)
                        break
                del code, view
    except (OSError, ValueError):
        _limited(state, "memcpy macro preparation was unavailable")
        return True
    if failed or skipped:
        _limited(state, f"memcpy macro preparation incomplete: {failed} failed, "
                 f"{skipped} skipped by preparation budget")
    return bool(failed or skipped)


def _candidates(state: OverlapAnalysis) -> StageResult:
    if not state.files:
        return StageResult("skipped", "no successfully analyzed C translation units")
    if state.request_for is None:
        _limited(state, "memcpy overlap check requires the GCC analyzer")
        return StageResult("skipped", "GCC analyzer unavailable")
    allowed = set(state.files)
    root = state.target.resolve()

    paths = set()
    resolved_inputs = {}
    incomplete = False
    for rel in sorted(allowed):
        try:
            if Path(rel).is_absolute() or ".." in Path(rel).parts:
                raise ValueError("not a repository-relative path")
            path = root / rel
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            if not resolved.is_file():
                raise ValueError("not a regular source file")
            paths.add(path)
            resolved_inputs[path] = resolved
        except (ValueError, OSError, RuntimeError):
            _limited(state, "memcpy candidate input is unavailable or outside the target", tu=rel)
            incomplete = True
    deadline = monotonic() + _CANDIDATE_SECONDS
    if state.budget is not None:
        deadline = min(deadline, state.budget.deadline)
    raw_deadline = min(deadline, monotonic() + _RAW_CANDIDATE_SECONDS)
    for path in sorted(paths):
        if monotonic() >= raw_deadline or (state.budget is not None and state.budget.remaining() <= 0):
            _limited(state, "memcpy source candidate budget exhausted")
            incomplete = True
            break
        got = read_text_capped(resolved_inputs[path], _RAW_SOURCE_CHARS)
        rel = path.relative_to(root).as_posix()
        if got is None:
            _limited(state, "memcpy source candidate input unreadable", tu=rel)
            incomplete = True
            continue
        text, truncated = got
        # C line splicing precedes comment/string handling. This also keeps
        # identifiers split by escaped newlines visible without a parser.
        spliced = text.replace("\\\n", "")
        if (_MEMCPY_TOKEN.search(spliced) is not None
                and _MEMCPY_TOKEN.search(blank_c_noncode(spliced, allow_digit_separators=True)) is not None):
            state.candidates.add(rel)
        elif truncated:
            _limited(state, "memcpy source candidate input exceeds the read budget", tu=rel)
            incomplete = True
        del text, spliced, got
    incomplete |= _expanded_candidates(state, paths, deadline)
    if incomplete:
        if state.budget is not None and state.budget.remaining() <= 0:
            state.budget.mark_exhausted()
        _limited(state, "memcpy overlap candidate scan was incomplete")
        return StageResult("partial" if state.candidates else "error", "candidate scan incomplete")

    if not state.candidates:
        return StageResult("skipped", "no memcpy candidates in eligible C files")
    return StageResult()


def _compile(state: OverlapAnalysis) -> StageResult:
    request_for, sandbox_run = state.request_for, state.sandbox_run
    assert request_for is not None and sandbox_run is not None
    first = request_for(sorted(state.candidates)[0])
    # Probe the exact pinned executable once per run. Older GCC remains usable
    # for the baseline; only this detector requires the overlap warning (GCC 14+).
    probe = replace(
        first,
        command=(first.command[0], "-fanalyzer", OVERLAP_ID, "-x", "c",
                 "-fsyntax-only", os.devnull),
        # This only asks whether GCC accepts the option; no source diagnostic
        # artifact is emitted by the syntax-only /dev/null command.
        parse=lambda _workdir, _stderr: [],
        timeout=min(first.timeout, 30), analyze=None,
    )
    try:
        capability = run_compiler_analysis(probe, sandbox_run)
        if capability.status != "complete":
            raise RuntimeError("overlap warning option is unavailable")
    except Exception as exc:
        _limited(state, f"memcpy overlap capability probe failed: {str(exc)[:200]}")
        return StageResult("skipped", "overlap capability unavailable")

    def one(rel):
        request = request_for(rel)
        execution = run_compiler_analysis(request, sandbox_run)
        record = execution.value.record
        if execution.status != "complete" or record is None:
            raise RuntimeError("supplemental compiler did not complete successfully")
        return [d for d in record["diags"]
                if d.get("id") == OVERLAP_ID and d.get("kind") == "warning"]

    attempted = set()
    for rel, future in bounded_futures(sorted(state.candidates), one,
                                      workers=state.max_workers, budget=state.budget):
        attempted.add(rel)
        try:
            state.diagnostics[rel] = future.result()
        except Exception as exc:
            _limited(state, f"memcpy overlap analysis failed: {str(exc)[:200]}", tu=rel)
    skipped = len(state.candidates) - len(attempted)
    if skipped:
        _limited(state, f"memcpy analysis budget skipped {skipped} candidate TU(s)")
    state.limitations.sort(key=lambda item: (item["tu"], item["reason"]))
    return StageResult("partial" if state.limitations else "complete")


DETECTOR = Detector(
    "memcpy-overlap", "2",
    (Stage("candidates", _candidates), Stage("compiler", _compile)),
)


def run_memcpy_overlap(
    target: Path, files: tuple[str, ...], *,
    request_for: Callable[[str], CompilerRequest] | None,
    sandbox_run: Callable[..., Any], max_workers: int = 4,
    include_dirs_memo: BoundedMemo[list[str]] | None = None,
    setup: AnalysisSetup | None = None,
    budget: WorkBudget | None = None,
) -> DetectorResult[OverlapAnalysis]:
    """Run only capped, baseline-successful C TUs supplied by the caller."""
    state = OverlapAnalysis(
        target, files, request_for, budget.runner(sandbox_run) if budget is not None else sandbox_run,
        max_workers, include_dirs_memo=include_dirs_memo,
        setup=setup, budget=budget,
    )
    try:
        return run_detector(DETECTOR, state)
    finally:
        # Detach borrowed preparation and callbacks without clearing their data.
        state.files = ()
        state.request_for = None
        state.sandbox_run = None
        state.include_dirs_memo = None
        state.setup = None
