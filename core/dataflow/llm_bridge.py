"""Production wiring: bridges :mod:`core.llm.client.LLMClient` to the
:data:`~core.dataflow.llm_extractor.ExtractorFn` signature, and
provides an :data:`~packages.codeql.dataflow_validator.EvidenceCollector`
factory ready to plug into ``DataflowValidator(evidence_collector=...)``.

The bridge keeps the LLM-extractor module
(:mod:`core.dataflow.llm_extractor`) provider-agnostic — it only
knows about ``ExtractorFn``, never about RAPTOR's specific LLM
client. This module is the one place where the two concerns meet.

Typical use (PR1c-3 → operator wiring for evidence-aware validation):

    from core.dataflow.llm_bridge import make_evidence_collector
    from packages.codeql.dataflow_validator import DataflowValidator

    collector = make_evidence_collector(llm_client)
    validator = DataflowValidator(llm_client, evidence_collector=collector)
    result = validator.validate_dataflow_path(dataflow, repo_path)

The extractor task type defaults to :data:`TaskType.CLASSIFY` —
extraction is a structured-output classification problem (per-function
``semantics_tag`` from a closed enum). Operators can override.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from core.dataflow.adapters.codeql import from_dataflow_path
from core.dataflow.evidence_collector import (
    DEFAULT_MAX_FILES,
    collect_sanitizer_evidence,
)
from core.dataflow.llm_extractor import ExtractorFn
from core.dataflow.sanitizer_evidence import (
    CandidateValidator,
    SanitizerEvidence,
)
from core.llm.task_types import TaskType
from core.security.prompt_envelope import PromptBundle


def make_llm_extractor(
    llm_client: Any,
    *,
    task_type: str = TaskType.CLASSIFY,
) -> ExtractorFn:
    """Adapt :class:`core.llm.client.LLMClient` to :data:`ExtractorFn`.

    The returned callable takes the enveloped :class:`PromptBundle`
    (already split into trusted system / untrusted user messages by
    :func:`core.security.prompt_envelope.build_prompt`), forwards them
    to ``llm_client.generate``, and returns the raw response text.

    Returns ``None`` on any exception — the caller (path annotator)
    treats that as "no candidates extracted" plus an
    ``extraction_failures`` entry. We intentionally don't bubble up
    the exception: an LLM hiccup on one file shouldn't fail the whole
    finding's validation.

    ``task_type`` defaults to :data:`TaskType.CLASSIFY` — extraction
    is a closed-enum classification problem and most RAPTOR
    deployments route ``CLASSIFY`` to a cheap tier. Operators can
    override (e.g. :data:`TaskType.ANALYSE` for higher quality at
    higher cost).
    """

    def _extractor(bundle: PromptBundle) -> Optional[str]:
        system_msg = next(
            (m.content for m in bundle.messages if m.role == "system"),
            None,
        )
        user_msg = next(
            (m.content for m in bundle.messages if m.role == "user"),
            "",
        )
        try:
            response = llm_client.generate(
                prompt=user_msg,
                system_prompt=system_msg,
                task_type=task_type,
            )
        except Exception:
            return None
        return getattr(response, "content", None)

    return _extractor


def make_evidence_collector(
    llm_client: Any,
    *,
    model_id: str = "",
    cache: Optional[Dict[str, Tuple[CandidateValidator, ...]]] = None,
    max_files: int = DEFAULT_MAX_FILES,
    task_type: str = TaskType.CLASSIFY,
):
    """Build an evidence-collector closure for ``DataflowValidator``.

    The returned callable matches the
    :data:`~packages.codeql.dataflow_validator.EvidenceCollector`
    signature ``(DataflowPath, Path) -> SanitizerEvidence``. It:

    1. Converts the CodeQL ``DataflowPath`` to a producer-neutral
       :class:`~core.dataflow.Finding` via the existing CodeQL
       adapter.
    2. Runs :func:`collect_sanitizer_evidence` with an LLM-backed
       extractor wired through :func:`make_llm_extractor`.

    ``cache`` is operator-supplied (any mutable dict). Pass the same
    cache across multiple validate calls in one run to amortise
    extraction across findings that share files.
    """
    extractor = make_llm_extractor(llm_client, task_type=task_type)

    def _collector(dataflow, repo_path: Path) -> SanitizerEvidence:
        finding = from_dataflow_path(dataflow)
        return collect_sanitizer_evidence(
            finding,
            repo_root=repo_path,
            extractor=extractor,
            model_id=model_id,
            cache=cache,
            max_files=max_files,
        )

    return _collector
