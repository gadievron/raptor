"""Render :class:`SanitizerEvidence` as a structured text block for
inclusion in downstream LLM prompts.

The output is a single string with three labelled sections —
candidate pool, per-step annotations, metadata. The format is stable
so the downstream LLM (PR1c-2 integration) can rely on consistent
section headings.

**Caller MUST wrap the result as an** :class:`UntrustedBlock` —
candidate ``name``, ``qualified_name``, and ``semantics_text``
fields came from LLM extraction over potentially-adversarial
source. The renderer makes no envelope/defang choices; that is the
envelope's job at the caller site.

The trusted instructions ("review this evidence and judge whether
the validator covers the sink's attack class") belong in the
caller's system prompt, NOT in this rendered block. Mixing trusted
and untrusted content in one untrusted-rendered block would weaken
the envelope's separation guarantee.
"""

from __future__ import annotations

from typing import Iterable, List

from core.dataflow.sanitizer_evidence import (
    CandidateValidator,
    SanitizerEvidence,
    StepAnnotation,
)


def render_evidence_for_prompt(evidence: SanitizerEvidence) -> str:
    """Render evidence into the standard prompt-block format.

    The result is guaranteed to be non-empty (renders ``"(no
    candidates)"`` and similar placeholders rather than collapsing).
    Section order is stable: candidates → step annotations → metadata.
    """
    sections: List[str] = [
        _render_candidate_pool(evidence.candidate_pool),
        _render_step_annotations(evidence.step_annotations),
        _render_metadata(evidence),
    ]
    return "\n\n".join(sections)


def _render_candidate_pool(pool: Iterable[CandidateValidator]) -> str:
    pool_list = list(pool)
    lines = ["Validator candidates extracted from project source:"]
    if not pool_list:
        lines.append("  (no candidates extracted)")
        return "\n".join(lines)

    for c in pool_list:
        header = (
            f"  - {c.name} (semantics_tag={c.semantics_tag}, "
            f"confidence={c.confidence:.2f}, "
            f"defined {c.source_file}:{c.source_line}, "
            f"qualified_name={c.qualified_name})"
        )
        body = f'      "{c.semantics_text}"'
        provenance = f"      [extraction_provenance={c.extraction_provenance}]"
        lines.extend([header, body, provenance])
    return "\n".join(lines)


def _render_step_annotations(annotations: Iterable[StepAnnotation]) -> str:
    annotation_list = list(annotations)
    lines = ["Path-step annotations:"]
    if not annotation_list:
        lines.append("  (no steps)")
        return "\n".join(lines)

    for ann in annotation_list:
        if ann.on_path_validators:
            validators_part = (
                "calls validators: ["
                + ", ".join(ann.on_path_validators)
                + "]"
            )
        else:
            validators_part = "no validators called"
        lines.append(f"  step {ann.step_index}: {validators_part}")
        if ann.variables_referenced:
            lines.append(
                "      variables_referenced: ["
                + ", ".join(ann.variables_referenced)
                + "]"
            )
        if ann.inlined_helpers:
            lines.append(
                "      inlined_helpers (annotation incomplete past these): ["
                + ", ".join(ann.inlined_helpers)
                + "]"
            )
    return "\n".join(lines)


def _render_metadata(evidence: SanitizerEvidence) -> str:
    lines = [f"Pool completeness: {evidence.pool_completeness}"]
    if evidence.extraction_failures:
        lines.append("Extraction failures:")
        for f in evidence.extraction_failures:
            lines.append(f"  - {f}")
    else:
        lines.append("Extraction failures: (none)")
    return "\n".join(lines)
