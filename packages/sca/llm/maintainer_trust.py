"""LLM maintainer-trust synthesis.

Gathers registry metadata signals for a direct dependency and asks
the LLM for a 3-sentence trust assessment.  Triggered by:

- Mechanical ``maintainer_change`` or ``maintainer_account_change``
  findings from ``supply_chain.registry_metadata``.
- The operator passing ``--review-maintainers``.

Output is **informational** — it produces a trust assessment attached
to the finding's evidence, not a new finding or a severity change.
The operator gets a starting point for manual review.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from core.llm.task_types import TaskType
from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from .prompts import MAINTAINER_TRUST_SYSTEM
from .schemas import MaintainerTrustVerdict

if TYPE_CHECKING:
    from ..models import Dependency

logger = logging.getLogger(__name__)


def assess_maintainer_trust(
    client,
    dep: Dependency,
    metadata: dict[str, Any],
) -> MaintainerTrustVerdict | None:
    """Run the LLM on registry metadata for one dependency.

    ``metadata`` should contain keys from the registry client:
    ``maintainers``, ``publish_dates``, ``repository_url``,
    ``download_count``, etc.  Missing keys are tolerated — the
    LLM works with whatever's available.

    Returns ``None`` when the LLM is unavailable.
    """
    metadata_text = _format_metadata(dep, metadata)

    result: StageResult = run_stage(
        client=client,
        system=MAINTAINER_TRUST_SYSTEM,
        untrusted_blocks=(
            UntrustedBlock(
                content=metadata_text,
                kind="REGISTRY_METADATA",
                origin=f"{dep.ecosystem}/{dep.name} registry metadata",
            ),
        ),
        slots={
            "package_name": TaintedString(value=dep.name, trust="untrusted"),
            "ecosystem": TaintedString(value=dep.ecosystem, trust="trusted"),
            "version": TaintedString(
                value=dep.version or "unknown", trust="untrusted",
            ),
        },
        schema_cls=MaintainerTrustVerdict,
        task_type=TaskType.CLASSIFY,
    )

    if result.error or result.model is None:
        logger.debug("sca.llm.maintainer_trust: %s/%s failed: %s",
                      dep.ecosystem, dep.name, result.error)
        return None

    verdict: MaintainerTrustVerdict = result.model  # type: ignore[assignment]
    if result.preflight_hit and verdict.confidence == "high":
        verdict = verdict.model_copy(update={"confidence": "medium"})
    return verdict


def assess_batch(
    client,
    dep_metadata_pairs: list[tuple[Dependency, dict[str, Any]]],
) -> dict[str, MaintainerTrustVerdict | None]:
    """Assess multiple dependencies, keyed by ``dep.key()``."""
    results: dict[str, MaintainerTrustVerdict | None] = {}
    for dep, meta in dep_metadata_pairs:
        results[dep.key()] = assess_maintainer_trust(client, dep, meta)
    return results


# Per-field cap for registry-sourced strings in the prompt block:
# registry metadata is attacker-influenced, and an uncapped field
# would let one hostile value dominate the prompt. (This module
# renders metadata fields only — readme_preview is rendered, and
# separately capped, by slopsquat_verdict.)
_FIELD_CAP = 200


def _format_metadata(dep: Dependency, meta: dict[str, Any]) -> str:
    """Render metadata into a structured text block for the LLM."""
    lines = [
        f"Package: {dep.ecosystem}/{dep.name}",
        f"Version analysed: {dep.version or 'unknown'}",
    ]

    maintainers = meta.get("maintainers", [])
    if isinstance(maintainers, list) and maintainers:
        from .registry_view import iter_maintainers

        lines.append(f"Maintainers ({len(maintainers)}):")
        # iter_maintainers skips hostile entry shapes (non-dict rows,
        # non-string fields) so a poisoned packument degrades instead
        # of raising out of the review stage.
        for name, email, added in iter_maintainers(meta, 20):
            # Per-field caps: registry-sourced strings are attacker
            # publishable; 20 maintainers x unbounded names/emails is
            # an easy budget-domination channel into a trust verdict
            # (same rationale as the readme_preview cap).
            line = f"  - {name[:_FIELD_CAP]}"
            if email:
                line += f" <{email[:_FIELD_CAP]}>"
            if added:
                line += f" (added {added[:_FIELD_CAP]})"
            lines.append(line)

    publish_dates = meta.get("publish_dates", [])
    if publish_dates:
        lines.append(f"Recent publishes: {', '.join(str(d) for d in publish_dates[:10])}")

    repo = meta.get("repository_url", "")
    if repo:
        lines.append(f"Repository: {str(repo)[:_FIELD_CAP]}")

    downloads = meta.get("download_count")
    if downloads is not None:
        lines.append(f"Downloads (recent): {downloads}")

    deprecated = meta.get("deprecated")
    if deprecated:
        lines.append(f"Deprecated: {str(deprecated)[:_FIELD_CAP]}")

    for key in ("stars", "open_issues", "last_commit_date"):
        val = meta.get(key)
        if val is not None:
            lines.append(f"{key}: {str(val)[:_FIELD_CAP]}")

    return "\n".join(lines)
