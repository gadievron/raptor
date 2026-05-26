"""LLM slopsquat-verdict synthesis.

Companion to ``supply_chain/slopsquat.py``'s mechanical heuristic.
The heuristic surfaces names that LOOK like LLM hallucinations
(generic suffix on a popular prefix, lookalike-character
substitutions, untrusted scope); this module asks an LLM to
synthesise the heuristic-shape signal with registry metadata to
produce a final verdict.

Triggered by:
  * Operator passing ``--review-slopsquats``.
  * ``/agentic`` SCA invocation with the corresponding opt-in.

Output is **informational** — attaches a verdict to the
``slopsquat_suspect`` finding's evidence, not a new finding or a
severity change. Operators get a pointed verdict
(``probably_slopsquat`` / ``probably_legit`` / ``inconclusive``)
plus 3-sentence reasoning to drive their next step.

Same untrusted-block + run_stage shape as
``maintainer_trust.py`` — the heuristic's reasons + the
registry-side facts feed in as separate trust-tagged blocks so
the LLM can distinguish ground-truth signals from
attacker-controlled package metadata.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.llm.task_types import TaskType
from ..models import Dependency
from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from .prompts import SLOPSQUAT_VERDICT_SYSTEM
from .schemas import SlopsquatVerdict

logger = logging.getLogger(__name__)


def assess_slopsquat(
    client,
    dep: Dependency,
    heuristic_reasons: List[str],
    heuristic_score: float,
    suspected_root: Optional[str],
    metadata: Dict[str, Any],
) -> Optional[SlopsquatVerdict]:
    """Run the LLM on heuristic + registry data for one suspect.

    ``heuristic_reasons`` is the tag list from
    ``SlopsquatFinding.reasons`` (e.g.
    ``["popular_prefix_generic_suffix"]``). ``heuristic_score`` is
    the [0, 1] score. ``suspected_root`` is the nearest popular
    name if the heuristic matched a prefix or lookalike.

    ``metadata`` should carry the registry-side facts:
    ``first_publish``, ``latest_publish``, ``maintainers``,
    ``download_count``, ``repository_url``, ``readme_preview``.

    Returns ``None`` when the LLM is unavailable or the call
    failed. Caller treats None as "no LLM verdict — keep the
    heuristic + registry-co-occurrence severity as-is".
    """
    heuristic_text = _format_heuristic(
        dep, heuristic_reasons, heuristic_score, suspected_root,
    )
    metadata_text = _format_metadata(dep, metadata)

    result: StageResult = run_stage(
        client=client,
        system=SLOPSQUAT_VERDICT_SYSTEM,
        untrusted_blocks=(
            # Heuristic reasons are RAPTOR-internal and not
            # attacker-influenced — but slot through the
            # untrusted-block channel anyway for shape symmetry
            # with the registry block. The LLM is told to treat
            # ANY block as potentially adversarial.
            UntrustedBlock(
                content=heuristic_text,
                kind="HEURISTIC_REASONS",
                origin="raptor-sca slopsquat heuristic",
            ),
            UntrustedBlock(
                content=metadata_text,
                kind="REGISTRY_METADATA",
                origin=(
                    f"{dep.ecosystem}/{dep.name} registry metadata"
                ),
            ),
        ),
        slots={
            "package_name": TaintedString(
                value=dep.name, trust="untrusted",
            ),
            "ecosystem": TaintedString(
                value=dep.ecosystem, trust="trusted",
            ),
            "version": TaintedString(
                value=dep.version or "unknown", trust="untrusted",
            ),
        },
        schema_cls=SlopsquatVerdict,
        task_type=TaskType.CLASSIFY,
    )

    if result.error or result.model is None:
        logger.debug(
            "sca.llm.slopsquat_verdict: %s/%s failed: %s",
            dep.ecosystem, dep.name, result.error,
        )
        return None

    verdict: SlopsquatVerdict = result.model  # type: ignore[assignment]
    # Preflight-defended verdicts get their confidence capped at
    # medium — same pattern as maintainer_trust. The LLM can be
    # too eager on partial signals when it's seen pre-defense
    # patterns it knows about.
    if result.preflight_hit and verdict.confidence == "high":
        verdict = verdict.model_copy(update={"confidence": "medium"})
    return verdict


def assess_batch(
    client,
    suspects: List[tuple],
) -> Dict[str, Optional[SlopsquatVerdict]]:
    """Assess multiple suspects, keyed by ``dep.key()``.

    ``suspects`` is a list of
    ``(dep, heuristic_reasons, heuristic_score, suspected_root,
    metadata)`` tuples."""
    results: Dict[str, Optional[SlopsquatVerdict]] = {}
    for dep, reasons, score, root, meta in suspects:
        results[dep.key()] = assess_slopsquat(
            client, dep, reasons, score, root, meta,
        )
    return results


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _format_heuristic(
    dep: Dependency,
    reasons: List[str],
    score: float,
    suspected_root: Optional[str],
) -> str:
    lines = [
        f"Package: {dep.ecosystem}/{dep.name}",
        f"Heuristic score: {score:.2f} (0.0–1.0)",
        f"Heuristic reasons: {', '.join(reasons) if reasons else '(none)'}",
    ]
    if suspected_root is not None:
        lines.append(
            f"Suspected imitation target: {suspected_root}"
        )
    return "\n".join(lines)


def _format_metadata(
    dep: Dependency, meta: Dict[str, Any],
) -> str:
    """Render registry-side metadata into a structured block.

    Mirrors ``maintainer_trust._format_metadata`` so the two
    modules' prompts see identically-shaped input — drift
    between them is a maintenance hazard."""
    lines = [
        f"Registry record for {dep.ecosystem}/{dep.name}",
        f"Version analysed: {dep.version or 'unknown'}",
    ]
    first_pub = meta.get("first_publish")
    if first_pub:
        lines.append(f"First published: {first_pub}")
    latest_pub = meta.get("latest_publish")
    if latest_pub:
        lines.append(f"Latest version published: {latest_pub}")
    maintainers = meta.get("maintainers", [])
    if maintainers:
        lines.append(f"Maintainers ({len(maintainers)}):")
        for m in maintainers[:10]:
            name = m.get("name", m.get("username", "?"))
            email = m.get("email", "")
            lines.append(
                f"  - {name}" + (f" <{email}>" if email else "")
            )
    repo = meta.get("repository_url", "")
    if repo:
        lines.append(f"Repository URL (claimed): {repo}")
    else:
        lines.append("Repository URL: (none declared)")
    downloads = meta.get("download_count")
    if downloads is not None:
        lines.append(f"Recent downloads: {downloads}")
    readme = meta.get("readme_preview", "")
    if readme:
        # Cap at 500 chars so an attacker-controlled README
        # can't dominate the prompt budget.
        snippet = readme[:500].rstrip()
        lines.append(f"README preview (first 500 chars):\n  {snippet}")
    return "\n".join(lines)


__all__ = ["SlopsquatVerdict", "assess_slopsquat", "assess_batch"]
