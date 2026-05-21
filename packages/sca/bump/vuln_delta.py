"""Bump-time vulnerability delta — what CVEs would a bump expose?

The Tier 1 supply-chain detectors in ``evaluator.py`` answer
"is the bump's METADATA suspicious" (recent publish, maintainer
change, new install hook). This module answers a different
question: "if I apply this bump, what KNOWN vulnerabilities is
the operator newly exposed to?"

Returns ``VulnFinding`` records the verdict ladder already knows
how to handle — KEV escalation, multiple-critical block, etc.

Delta semantics:

* Advisory affects ``target`` AND affects ``current``: NOT
  emitted (neutral — the bump doesn't change exposure for this
  advisory).
* Advisory affects ``target`` AND does NOT affect ``current``:
  emitted as a ``VulnFinding``. The bump introduces new
  vulnerability surface — the verdict ladder gates.
* Advisory affects ``current`` AND does NOT affect ``target``:
  NOT emitted. (Future: emit as a positive signal for
  PR-comment rendering "this bump fixes N CVEs"; out of scope
  here.)

The delta semantics intentionally only surface NEWLY-INTRODUCED
CVEs. Operators running a bumper that proposes ``cur → tgt``
care about "does this make security posture WORSE?" Already-
present CVEs are the current scan's job, not the bumper's.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from ..findings import build_vuln_findings
from ..models import Confidence, Dependency, PinStyle, VulnFinding
from ..osv import OsvClient, OsvResult

logger = logging.getLogger(__name__)


def evaluate_bump_vulns(
    *,
    ecosystem: str,
    name: str,
    current_version: str,
    target_version: str,
    osv_client: OsvClient,
    kev_client=None,
    epss_client=None,
) -> List[VulnFinding]:
    """Return the vuln findings for advisories introduced by
    bumping from ``current_version`` to ``target_version``.

    Queries OSV for both versions, computes the set difference
    on advisory IDs, returns VulnFindings for the new ones.
    KEV / EPSS enrichment is plumbed through if clients are
    supplied — the verdict ladder uses both for escalation
    (KEV → Block; high EPSS + critical → Block).
    """
    current_dep = _synthesise(ecosystem, name, current_version)
    target_dep = _synthesise(ecosystem, name, target_version)
    try:
        results = osv_client.query_batch([current_dep, target_dep])
    except Exception:                    # noqa: BLE001
        logger.warning(
            "sca.bump: OSV query failed for %s:%s@(%s→%s); "
            "skipping vuln delta",
            ecosystem, name, current_version, target_version,
            exc_info=True,
        )
        return []
    # ``query_batch`` returns ``OsvResult`` per dep, in input
    # order. We always pass [current, target] so we know which is
    # which.
    current_result, target_result = results[0], results[1]
    new_advisories = _advisory_delta(
        target_advisories=target_result.advisories,
        current_advisories=current_result.advisories,
    )
    if not new_advisories:
        return []
    # Build VulnFindings for the new advisories. The target_dep
    # is what we're proposing TO, so the findings are tagged
    # against it.
    findings = build_vuln_findings(
        [target_dep],
        [OsvResult(target_dep.key(), new_advisories)],
        kev=kev_client, epss=epss_client,
    )
    return findings


def _advisory_delta(
    *, target_advisories, current_advisories,
):
    """Return advisories in ``target_advisories`` that are NOT
    in ``current_advisories``. Match by ``osv_id`` — the
    canonical advisory identifier (``GHSA-...`` / ``CVE-...``).
    """
    current_ids = {a.osv_id for a in current_advisories}
    return [a for a in target_advisories
            if a.osv_id not in current_ids]


def _synthesise(eco: str, name: str, version: str) -> Dependency:
    """Build a synthetic ``Dependency`` for OSV's batch query.
    The path / scope / pin_style are dummies — OSV only reads
    the (ecosystem, name, version) triple. Reuses the pattern
    from ``packages/sca/whatif.py`` for the same reason."""
    return Dependency(
        ecosystem=eco, name=name, version=version,
        declared_in=Path("/<bump-vuln-delta>"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:{eco.lower()}/{name}@{version}",
        parser_confidence=Confidence(
            "high", reason="bump vuln-delta synthetic dep",
        ),
    )
