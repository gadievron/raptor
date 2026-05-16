"""Hypothesis-driven, tool-grounded vulnerability validation.

The LLM forms hypotheses about security weaknesses ("input X flows unchecked
to sink Y"); deterministic tools (Semgrep, Coccinelle, CodeQL, SMT) test
those hypotheses; the LLM never directly classifies code as vulnerable.

Research basis: KNighter (SOSP 2025, 92 kernel bugs), SAILOR
(arXiv:2604.06506, 379 vulns vs 12 pure-agentic), IRIS (ICLR 2025, 2x
CodeQL recall). Pure self-critique without tool grounding actively
degrades quality (IEEE-ISTAS 2025: 37.6% more critical vulns after 5
iterations) — this package exists to ground LLM reasoning in mechanical
evidence.

Public API:
    from packages.hypothesis_validation import (
        Hypothesis, ValidationResult, ToolAdapter, ToolCapability,
    )
    from packages.hypothesis_validation.adapters import (
        CoccinelleAdapter, SemgrepAdapter,
    )
    from packages.hypothesis_validation.runner import validate

    h = Hypothesis(
        claim="parse_input return value used as array index without check",
        target=Path("src/parser.c"),
        target_function="dispatch",
        cwe="CWE-129",
    )
    result = validate(h, [CoccinelleAdapter(), SemgrepAdapter()], llm_client)
    if result.verdict == "confirmed":
        for ev in result.evidence:
            print(f"{ev.tool}: {ev.summary}")

Optional structured fields on Hypothesis (source/sink/flow_steps/
sanitizers/smt_constraints), evidence provenance (Evidence.refers_to +
hash_hypothesis), the verdict ladder (verdict_from/aggregate), and the
must_progress iteration guard are all additive — Phase A callers see
no change.
"""

from .hypothesis import (
    Hypothesis,
    Location,
    SourceLocation,  # back-compat alias for Location
    SinkLocation,    # back-compat alias for Location
    FlowStep,
)
from .result import Evidence, ValidationResult
from .adapters.base import ToolAdapter, ToolCapability, ToolInvocation, ToolEvidence
from .verdict import verdict_from, aggregate
from .provenance import (
    HypothesisHash,
    ProvenanceMismatch,
    ensure_same_provenance,
    hash_hypothesis,
)
from .iteration import IterationStep, IterationStalled, uncertainty, must_progress
from .posterior import (
    Posterior,
    UNIFORM_PRIOR,
    posterior_from,
    update as posterior_update,
    verdict_from_posterior,
)

__all__ = [
    "Hypothesis",
    "Location",
    "SourceLocation",
    "SinkLocation",
    "FlowStep",
    "ValidationResult",
    "Evidence",
    "ToolAdapter",
    "ToolCapability",
    "ToolInvocation",
    "ToolEvidence",
    "verdict_from",
    "aggregate",
    "HypothesisHash",
    "ProvenanceMismatch",
    "hash_hypothesis",
    "ensure_same_provenance",
    "IterationStep",
    "IterationStalled",
    "uncertainty",
    "must_progress",
    "Posterior",
    "UNIFORM_PRIOR",
    "posterior_from",
    "posterior_update",
    "verdict_from_posterior",
]
