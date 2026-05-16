"""Corpus-runner :class:`Validator` adapter that drives the CodeQL
:class:`DataflowValidator` with the sanitizer-evidence pipeline enabled.

This is the operator-facing measurement entry point. Wire via:

    libexec/raptor-corpus-run --output evidence.csv \\
        --validator packages.codeql.evidence_validator:CodeQLEvidenceValidator
    libexec/raptor-corpus-metrics evidence.csv

The resulting metrics compare against the TrivialValidator baseline
(precision/recall/F1 on the same corpus). PR1's exit criterion —
≥10% reduction in LLM-decision-error — is judged by that delta.

The class implements :class:`core.dataflow.validator.Validator` (the
corpus-side protocol). It accepts any :class:`Finding`, but the
underlying CodeQL :class:`DataflowValidator` was designed for CodeQL
findings. Findings from other producers (Semgrep) still validate, but
the rule-id-driven SMT profile heuristic falls back to defaults.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from core.dataflow.finding import Finding, Step
from core.dataflow.llm_bridge import make_evidence_collector
from core.dataflow.sanitizer_evidence import CandidateValidator
from core.dataflow.validator import ValidatorVerdict
from packages.codeql.dataflow_validator import (
    DataflowPath,
    DataflowStep,
    DataflowValidator,
)


# packages/codeql/evidence_validator.py → repo root via parents[2].
# Resolved at import time; doesn't depend on cwd or env.
_DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]


class CodeQLEvidenceValidator:
    """:class:`Validator` adapter that drives the evidence-aware
    :class:`DataflowValidator`.

    Zero-arg construction works (for ``--validator`` import-spec
    use); LLM client and DataflowValidator are constructed lazily on
    the first :meth:`validate` call. Optional kwargs for tests:

    * ``llm_client`` — inject a mock; default constructs ``LLMClient()``
      lazily on first validate
    * ``repo_root`` — override fixture root; default is the RAPTOR
      repo root resolved at import time
    * ``cache`` — share extraction cache across :meth:`validate` calls
      to amortise LLM cost when corpus findings reference common files
    """

    def __init__(
        self,
        llm_client: Any = None,
        repo_root: Optional[Path] = None,
        cache: Optional[Dict[str, Tuple[CandidateValidator, ...]]] = None,
    ) -> None:
        self._injected_llm_client = llm_client
        self._repo_root = repo_root or _DEFAULT_REPO_ROOT
        self._cache: Dict[str, Tuple[CandidateValidator, ...]] = (
            cache if cache is not None else {}
        )
        # Lazy: the LLMClient (default-constructed) brings up the
        # egress proxy at __init__ time. Defer until we actually need
        # to call the LLM, so importing this module + zero-arg
        # construction stays cheap.
        self._validator: Optional[DataflowValidator] = None

    def _get_dataflow_validator(self) -> DataflowValidator:
        if self._validator is None:
            llm = self._injected_llm_client or _construct_default_llm_client()
            collector = make_evidence_collector(llm, cache=self._cache)
            self._validator = DataflowValidator(
                llm, evidence_collector=collector
            )
        return self._validator

    def validate(self, finding: Finding) -> ValidatorVerdict:
        """Map a corpus :class:`Finding` to a :class:`ValidatorVerdict`
        via the evidence-aware :meth:`DataflowValidator.validate_dataflow_path`.

        Errors in the underlying validator (LLM transport failures,
        budget exhaustion, parse errors) collapse to
        :data:`ValidatorVerdict.UNCERTAIN` — corpus metrics treats
        these as separate from confident verdicts and they don't
        contribute to precision/recall.
        """
        dp = _finding_to_dataflow_path(finding)
        try:
            result = self._get_dataflow_validator().validate_dataflow_path(
                dp, self._repo_root
            )
        except Exception:
            return ValidatorVerdict.UNCERTAIN

        return (
            ValidatorVerdict.EXPLOITABLE
            if result.is_exploitable
            else ValidatorVerdict.NOT_EXPLOITABLE
        )


def _construct_default_llm_client():
    """Lazy LLMClient construction. Imported inside the function so
    importing :mod:`packages.codeql.evidence_validator` doesn't
    trigger LLM-client side effects (egress proxy bring-up, config
    loading) — those happen on the first :meth:`validate` call."""
    from core.llm.client import LLMClient
    return LLMClient()


def _finding_to_dataflow_path(finding: Finding) -> DataflowPath:
    """Convert a producer-neutral :class:`Finding` to the CodeQL-shaped
    :class:`DataflowPath` ``DataflowValidator`` expects.

    ``sanitizers`` is left empty — the evidence pipeline replaces the
    legacy sanitizer-list field with structured ``CandidateValidator``
    records folded into the prompt as an :class:`UntrustedBlock`.
    """
    return DataflowPath(
        source=_step_to_dataflow_step(finding.source),
        sink=_step_to_dataflow_step(finding.sink),
        intermediate_steps=[
            _step_to_dataflow_step(s) for s in finding.intermediate_steps
        ],
        sanitizers=[],
        rule_id=finding.rule_id,
        message=finding.message,
    )


def _step_to_dataflow_step(step: Step) -> DataflowStep:
    return DataflowStep(
        file_path=step.file_path,
        line=step.line,
        column=step.column,
        snippet=step.snippet,
        label=step.label or "",
    )
