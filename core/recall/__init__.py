"""End-to-end detector-recall measurement.

Every other calibration surface in RAPTOR measures precision or
suppression-soundness (SCA ranking, negative controls, binary-oracle
absent-precision, validator recall over producer-emitted findings).
This package measures the number none of them can: how many KNOWN
bugs the detection pipeline surfaces at all — detector recall against
ground truth the producers never saw.

Segregation contract: recall ground-truth labels exist to count
false negatives. They must NEVER feed the FP-suppression stores,
the model scorecard, or any learning surface that tunes verdicts —
the cvefix_corpus_generator warning generalised. This package never
imports those stores, and every report it writes carries
``label_class: recall-ground-truth`` so downstream tooling can refuse
to ingest it.
"""

from core.recall.manifest import (
    ExpectedFinding,
    ManifestError,
    RecallManifest,
    load_manifest,
)
from core.recall.matcher import MatchResult, match_findings
from core.recall.score import RecallReport, compare_reports, score

__all__ = [
    "ExpectedFinding",
    "ManifestError",
    "MatchResult",
    "RecallManifest",
    "RecallReport",
    "compare_reports",
    "load_manifest",
    "match_findings",
    "score",
]
