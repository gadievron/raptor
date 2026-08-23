"""Surface consensus-confirmed discoveries as verified outcomes.

When the 2-method pointer consensus (OSV references + NVD Patch-tagged
references — ``report/consensus.py``) independently agrees with the
pipeline's extracted fix pointer, that is an oracle-grade confirmation
of the discovery: two public databases and the clone-based extraction
all name the same ``(repo, sha)``. Append it to the run-local
``verified-outcomes.jsonl`` so ``libexec/raptor-verified-outcomes``
surfaces /cve-diff confirmations alongside /fuzz, /agentic,
/crash-analysis, and /validate.

Deliberately NOT a LabeledAttempt: those records carry exactly one of
the sandbox/codeql/web evidence shapes and exploit-attempt semantics.
Pointer consensus is a different oracle, so it uses the run-local
VerifiedOutcome sidecar (source 3 of
``core.labeled_attempts.view.collect_outcomes``) with
``Oracle.CONSENSUS``. ``reproducible=False`` — the vote is
point-in-time against live OSV/NVD records, like web evidence.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover — type-only imports
    from cve_diff.core.models import DiffBundle

logger = logging.getLogger(__name__)

# Both consensus methods must have voted for the same pointer.
_MIN_AGREEMENT = 2


def _consensus_matches_bundle(consensus: dict[str, Any],
                              bundle: DiffBundle) -> bool:
    """The consensus pointer must name the commit the pipeline actually
    extracted — agreement on some OTHER pointer refutes rather than
    confirms the run."""
    sha = (consensus.get("consensus_sha") or "").lower()
    slug = (consensus.get("consensus_slug") or "").lower()
    if not sha or not slug:
        return False
    picked_sha = (bundle.commit_after or "").lower()
    if not picked_sha:
        return False
    if not (picked_sha.startswith(sha) or sha.startswith(picked_sha)):
        return False
    # Exact slug comparison, mirroring report/markdown.py ``_matches``.
    # A substring match (`slug in url`) minted wrong-repo VERIFIED
    # records for two shapes: slug "foo/bar" inside
    # "https://github.com/evilfoo/bar-extra", and cross-component
    # "y/z" inside "https://github.com/x-y/z-w". Parse the URL path
    # and require equality with the bare `owner/repo` slug instead.
    from urllib.parse import urlparse
    try:
        path = urlparse(bundle.repo_ref.repository_url or "").path
    except Exception:  # noqa: BLE001 — unparseable URL means "no match", never an error
        return False
    repo_slug = path.lstrip("/").rstrip("/").lower()
    repo_slug = repo_slug.removesuffix(".git")
    return slug == repo_slug


def write_consensus_outcome(
    output_dir: Path,
    bundle: DiffBundle,
    *,
    cwe_id: str | None = None,
) -> bool:
    """Append one Oracle.CONSENSUS record when the run qualifies.

    Returns True when a record was written; False on skip (no
    consensus, insufficient agreement, pointer mismatch) or I/O
    trouble. Never raises — verified-outcome surfacing must not break
    the run.
    """
    consensus = bundle.consensus or {}
    try:
        if int(consensus.get("agreement_count") or 0) < _MIN_AGREEMENT:
            return False
        if not _consensus_matches_bundle(consensus, bundle):
            return False

        from core.labeled_attempts.view import (
            VERIFIED_OUTCOMES_FILENAME,
            Oracle,
            OutcomeStatus,
            VerifiedOutcome,
        )

        outcome = VerifiedOutcome(
            finding_id=bundle.cve_id,
            oracle=Oracle.CONSENSUS,
            status=OutcomeStatus.VERIFIED,
            reproducible=False,
            evidence={
                "repository_url": bundle.repo_ref.repository_url,
                "fix_commit": bundle.commit_after,
                "parent_commit": bundle.commit_before,
                "agreement_count": consensus.get("agreement_count"),
                "attempted_count": consensus.get("attempted_count"),
                "methods": [
                    m.get("name")
                    for m in (consensus.get("methods") or [])
                    if isinstance(m, dict)
                ],
                "diff_shape": bundle.shape,
                "files_changed": bundle.files_changed,
                "extraction_agreement": (
                    (bundle.extraction_agreement or {}).get("verdict")
                    if bundle.extraction_agreement else None
                ),
            },
            cwe_id=cwe_id,
            produced_by="cve-diff",
        )
        path = Path(output_dir) / VERIFIED_OUTCOMES_FILENAME
        with Path(path).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(outcome.to_dict(), default=str) + "\n")
        return True
    except Exception:  # noqa: BLE001 — surfacing must never break the run
        logger.debug(
            "verified-outcome write failed for %s",
            getattr(bundle, "cve_id", "?"), exc_info=True,
        )
        return False
