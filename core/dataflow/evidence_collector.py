"""Top-level orchestrator for building :class:`SanitizerEvidence`
from a :class:`Finding`.

Combines the two halves shipped in PR1b-1 + PR1b-2:

* :mod:`core.dataflow.llm_extractor` builds the candidate pool
  (LLM extracts validators from a small set of project files).
* :mod:`core.dataflow.path_annotator` annotates each step of the
  finding with which candidates' calls appear.

The result is folded into a :class:`SanitizerEvidence` record with
``pool_completeness`` describing the scope and
``extraction_failures`` capturing per-file errors.

This module deliberately does NOT decide a verdict. The
``SanitizerEvidence`` is fed *into* the existing dataflow validator's
LLM prompt by :mod:`packages.codeql.dataflow_validator` (PR1c
integration) — never around it. The rejected verdict-with-short-circuit
design is documented at ``~/design/dataflow-sanitizer-bypass.md``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

from core.dataflow.finding import Finding
from core.dataflow.llm_extractor import ExtractorFn, extract_from_files
from core.dataflow.path_annotator import annotate_finding
from core.dataflow.sanitizer_evidence import (
    CandidateValidator,
    SanitizerEvidence,
)


DEFAULT_MAX_FILES = 5


def collect_sanitizer_evidence(
    finding: Finding,
    *,
    repo_root: Path,
    extractor: ExtractorFn,
    model_id: str = "",
    cache: Optional[Dict[str, Tuple[CandidateValidator, ...]]] = None,
    max_files: int = DEFAULT_MAX_FILES,
) -> SanitizerEvidence:
    """Build :class:`SanitizerEvidence` for one :class:`Finding`.

    1. Gather distinct file paths referenced by the finding's
       source / intermediate steps / sink, in path order.
    2. Cap at ``max_files`` (5 by default — keeps cost bounded; the
       downstream LLM weighs ``pool_completeness`` accordingly).
    3. LLM-extract candidates from those files via ``extractor``.
    4. Annotate every step of the finding against the candidate pool.
    5. Return a :class:`SanitizerEvidence` with no verdict — the
       validator pipeline (PR1c) decides exploitability with this
       evidence as input, not as a substitute.
    """
    paths_in_order = list(_unique_file_paths(finding))
    truncated = len(paths_in_order) > max_files
    scoped_paths = paths_in_order[:max_files]

    candidates, extraction_errors = extract_from_files(
        file_paths=scoped_paths,
        repo_root=repo_root,
        extractor=extractor,
        model_id=model_id,
        cache=cache,
    )

    annotations = annotate_finding(finding, candidates)

    return SanitizerEvidence(
        candidate_pool=candidates,
        step_annotations=annotations,
        pool_completeness=_describe_pool_completeness(
            file_count=len(scoped_paths),
            truncated=truncated,
        ),
        extraction_failures=tuple(extraction_errors),
    )


def _unique_file_paths(finding: Finding) -> Iterator[str]:
    """Yield distinct file paths from finding's steps in path order
    (source first, then intermediate, then sink)."""
    seen: set = set()
    all_steps = (finding.source,) + tuple(finding.intermediate_steps) + (finding.sink,)
    for step in all_steps:
        if step.file_path not in seen:
            seen.add(step.file_path)
            yield step.file_path


def _describe_pool_completeness(*, file_count: int, truncated: bool) -> str:
    """Render the pool-completeness label the downstream LLM reads.

    Distinguishes "we read every referenced file" from "we capped at
    N files" so the LLM knows whether the absence of a candidate
    reflects "no validator exists" or "we didn't look at the file
    that defines it"."""
    if file_count == 0:
        return "no_files_in_scope"
    if truncated:
        return f"scoped_to_first_{file_count}_files_truncated"
    return f"scoped_to_{file_count}_files"
