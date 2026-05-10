"""Producer-neutral dataflow finding schema and adapters.

The :mod:`core.dataflow` package is the shared shape used by every
dataflow consumer in RAPTOR — the labeled corpus under
``core/dataflow/corpus/``, the PR1 sanitizer-evidence pipeline, and
the CodeQL data-extension emitter for PR1b.

CodeQL's :class:`DataflowPath`, IRIS LocalFlowSource hits, Semgrep
results, and future dynamic-web producers all convert into a
:class:`Finding` via per-producer adapters under
``core.dataflow.adapters`` so downstream consumers see one shape.

See ``~/design/dataflow-sanitizer-bypass.md`` for the design.
"""

from .finding import SCHEMA_VERSION, Finding, Step
from .label import (
    FP_DEAD_CODE,
    FP_FRAMEWORK_MITIGATION,
    FP_INFEASIBLE_BRANCH,
    FP_MISSING_SANITIZER_MODEL,
    FP_REFLECTION_IMPRECISION,
    FP_TYPE_CONSTRAINT,
    GroundTruth,
    VALID_FP_CATEGORIES,
    VALID_VERDICTS,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)

__all__ = [
    "SCHEMA_VERSION",
    "Finding",
    "Step",
    "GroundTruth",
    "VERDICT_TRUE_POSITIVE",
    "VERDICT_FALSE_POSITIVE",
    "VALID_VERDICTS",
    "FP_MISSING_SANITIZER_MODEL",
    "FP_INFEASIBLE_BRANCH",
    "FP_FRAMEWORK_MITIGATION",
    "FP_DEAD_CODE",
    "FP_TYPE_CONSTRAINT",
    "FP_REFLECTION_IMPRECISION",
    "VALID_FP_CATEGORIES",
]
