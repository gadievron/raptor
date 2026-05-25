"""Generate trust-corpus entries from a CVE fix-commit pair.

Sibling of :mod:`core.dataflow.owasp_corpus_generator`, but the ground
truth comes from the *fix commit* rather than a benchmark's
``expectedresults`` CSV. The labeling insight (see
``~/design/trust-witness.md``):

    Run the producer (CodeQL) on the pre-fix and post-fix source of a
    real injection CVE.

      * A finding on the **pre-fix** code is the real vulnerability →
        ``true_positive`` (the CVE).
      * A finding the producer **still emits on the post-fix** code is a
        ``false_positive``: the fix added a sanitizer the producer does
        not model. ``fp_category = missing_sanitizer_model``. This is the
        exact shape the trust sound-tier must learn to suppress.
      * Findings that *disappear* after the fix (producer recognised the
        sanitizer) are uninteresting — no FP to fix — and are not emitted.

This module is producer-agnostic about parsing: it consumes already-parsed
SARIF dicts (the caller runs ``codeql_augmented_run`` / ``finding_diff``)
and uses :func:`core.dataflow.adapters.codeql.from_sarif_result` to build
:class:`Finding` objects. It does NOT run CodeQL itself.

**These are CANDIDATE labels, not ground truth.** "Post-fix still-flagged →
FP" assumes the fix *fully* neutralised the path. Incomplete fixes are common:
CodeQL may still flag post-fix code because the path is *genuinely still
vulnerable* (partial fix, or a different path fixed) — a real TP mislabeled FP.
So generator output MUST be hand-verified before it gates anything (the design's
"re-label our filtered subset" step). Treating raw output as a soundness corpus
would corrupt the FN-gate it exists to protect.
"""

from __future__ import annotations

import logging
import re
from typing import Any, FrozenSet, Iterable, Iterator, List, Mapping, Optional, Tuple

from core.dataflow.adapters.codeql import from_sarif_result
from core.dataflow.finding import Finding
from core.dataflow.label import (
    FP_MISSING_SANITIZER_MODEL,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
    GroundTruth,
)
# Reuse the corpus writer verbatim — same on-disk shape as every other corpus.
from core.dataflow.owasp_corpus_generator import write_corpus  # noqa: F401 (re-exported)

_DEFAULT_LABELER = "trust-corpus-cvefix"

logger = logging.getLogger(__name__)


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")


def _iter_results(sarif: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    for run in sarif.get("runs", []) or []:
        for result in run.get("results", []) or []:
            yield result


def _path_touches(f: Finding, files: FrozenSet[str]) -> bool:
    """True if any step on the finding's path lives in a fix-changed file."""
    steps = [f.source, *f.intermediate_steps, f.sink]
    return any(s.file_path in files for s in steps)


def _findings_from_sarif(
    sarif: Mapping[str, Any],
    *,
    id_prefix: str,
    touched: Optional[FrozenSet[str]] = None,
) -> List[Finding]:
    out: List[Finding] = []
    for idx, result in enumerate(_iter_results(sarif)):
        fid = f"{id_prefix}__{idx:03d}"
        try:
            f = from_sarif_result(result, finding_id=fid)
        except ValueError as exc:
            # One malformed SARIF entry must not kill a batch over a real
            # dataset of thousands of findings — skip + record.
            logger.warning("skipping malformed SARIF result %s: %s", fid, exc)
            continue
        if f is None:  # not a dataflow-path result
            continue
        # Localize to the fix: only findings whose path touches a changed
        # file are attributable to THIS CVE. Without this filter, unrelated
        # findings get mislabeled (a real vuln tagged FP, or an unrelated FP
        # tagged TP) — corrupting the FN-gate the corpus protects.
        if touched is not None and not _path_touches(f, touched):
            continue
        out.append(f)
    return out


def generate_from_sarif(
    before_sarif: Mapping[str, Any],
    after_sarif: Mapping[str, Any],
    *,
    cve_id: str,
    cwe: str,
    labeled_at: str,
    labeler: str = _DEFAULT_LABELER,
    fix_touched_files: Optional[Iterable[str]] = None,
) -> List[Tuple[Finding, GroundTruth]]:
    """Build (Finding, GroundTruth) pairs from one CVE fix-commit pair.

    ``before_sarif`` / ``after_sarif`` are parsed CodeQL SARIF dicts from
    running the same queries on the pre- and post-fix source.

    ``fix_touched_files`` is the set of source files the fix commit changed.
    **Strongly recommended for real data:** without it, every emitted finding
    is labeled by position (post → FP, pre → TP), which mislabels findings on
    paths unrelated to the CVE. With it, only findings whose path touches a
    changed file are emitted — the ones actually attributable to this CVE.
    Omitting it is appropriate only for single-finding / synthetic inputs.
    """
    cve = _slug(cve_id)
    touched: Optional[FrozenSet[str]] = (
        frozenset(fix_touched_files) if fix_touched_files is not None else None
    )
    if touched is None:
        logger.warning(
            "generate_from_sarif(%s): no fix_touched_files — labels are "
            "position-only and may mislabel CVE-unrelated findings.", cve_id,
        )
    pairs: List[Tuple[Finding, GroundTruth]] = []

    # Post-fix findings the producer still emits = FP candidates (the
    # added sanitizer isn't modelled). This is the trust sound-tier target.
    for f in _findings_from_sarif(after_sarif, id_prefix=f"{cve}__post", touched=touched):
        pairs.append((
            f,
            GroundTruth(
                finding_id=f.finding_id,
                verdict=VERDICT_FALSE_POSITIVE,
                fp_category=FP_MISSING_SANITIZER_MODEL,
                rationale=(
                    f"{cve_id} ({cwe}): producer still flags the post-fix path; "
                    f"the fix added a sanitizer the producer does not model "
                    f"(missing_sanitizer_model). Trust sound-tier should suppress."
                ),
                labeler=labeler,
                labeled_at=labeled_at,
            ),
        ))

    # Pre-fix findings = the real vulnerability = true positives (FN-gate:
    # a sound trust witness must NEVER suppress these).
    for f in _findings_from_sarif(before_sarif, id_prefix=f"{cve}__pre", touched=touched):
        pairs.append((
            f,
            GroundTruth(
                finding_id=f.finding_id,
                verdict=VERDICT_TRUE_POSITIVE,
                rationale=f"{cve_id} ({cwe}): pre-fix vulnerable path (the CVE).",
                labeler=labeler,
                labeled_at=labeled_at,
            ),
        ))

    return pairs
