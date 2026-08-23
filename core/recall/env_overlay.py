"""Read cvefix env-verification sidecars (the entry-level overlay).

``raptor-cvefix-envs`` writes one ``<CVE>.env-verification.json`` per
corpus entry into a local overlay directory: entry-level provenance
that the corpus BOUNDARY provably built, deployed, and served
(``verification: "env-verified"``). This module is the read side —
corpus reporting folds the counts in wherever corpus meta/history is
rendered.

Contract notes:

* Entry-level only. These sidecars say nothing about span-level
  manifest ``review`` fields, which stay human
  (see :mod:`core.recall.cvefix_manifest`).
* Overlay content is local-only (labels-stay-private): every reader
  must degrade gracefully to "no overlay" on public checkouts —
  ``load_overlay`` on a missing directory returns ``{}`` and a
  summary over it reports every entry unattempted.
* The ``verification`` enum is ``env-verified`` today with
  ``repro-verified`` reserved (populated once /exploit can generate
  triggers); readers must tolerate both plus absence.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from core.json import load_json

# Byte budget per overlay sidecar — small per-CVE records.
_MAX_SIDECAR_BYTES = 8 * 1024 * 1024

logger = logging.getLogger(__name__)

SIDECAR_SUFFIX = ".env-verification.json"

#: Known verification tiers, strongest last. Readers tolerate values
#: outside this list (forward compatibility) but never invent them.
VERIFICATION_TIERS = ("env-verified", "repro-verified")


def load_overlay(overlay_dir: Path | str | None) -> dict[str, dict[str, Any]]:
    """All parseable sidecars in ``overlay_dir``, keyed by CVE id.

    Missing/None directory → ``{}`` (public checkouts carry no
    overlay). Unparseable or id-less sidecars are skipped with a debug
    log — one corrupt file must not hide the rest of the overlay.
    """
    if not overlay_dir:
        return {}
    root = Path(overlay_dir)
    if not root.is_dir():
        return {}
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob(f"*{SIDECAR_SUFFIX}")):
        data = load_json(path, max_bytes=_MAX_SIDECAR_BYTES)
        if data is None:
            logger.debug("env_overlay: unreadable sidecar %s", path)
            continue
        cve_id = data.get("cve_id") if isinstance(data, dict) else None
        if not cve_id:
            logger.debug("env_overlay: sidecar %s lacks cve_id", path)
            continue
        out[cve_id] = data
    return out


def corpus_env_summary(
    cve_ids: list[str],
    overlay: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Fold the overlay over a corpus's entry list.

    Buckets: ``verified`` (a ``verification`` tier is present),
    ``missed`` (attempted, no tier — the sidecar keeps the typed
    give-up as information), ``unattempted`` (no sidecar). The
    ``by_tier`` map counts each verification value seen so a future
    repro-verified rollout needs no reader change.
    """
    verified: list[str] = []
    missed: list[str] = []
    unattempted: list[str] = []
    by_tier: dict[str, int] = {}
    for cve in cve_ids:
        row = overlay.get(cve)
        if row is None:
            unattempted.append(cve)
        elif row.get("verification"):
            verified.append(cve)
            tier = str(row["verification"])
            by_tier[tier] = by_tier.get(tier, 0) + 1
        else:
            missed.append(cve)
    return {
        "total": len(cve_ids),
        "verified": len(verified),
        "missed": len(missed),
        "unattempted": len(unattempted),
        "by_tier": by_tier,
        "verified_cves": verified,
        "missed_cves": missed,
        "unattempted_cves": unattempted,
    }
