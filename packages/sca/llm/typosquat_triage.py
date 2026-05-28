"""LLM typosquat-triage verdict (curation step 2, Stage A).

Companion to ``supply_chain/typosquat_audit.py`` (which generates the candidate
delta) and ``supply_chain/typosquat_triage.py`` (the gate). The candidate
generator surfaces names one edit from a much-more-popular package; this module
asks an LLM to judge IDENTITY — is it a confusable near-name to flag, or a
legitimate independent project to keep trusted? — the call rank cannot make.

Same untrusted-block + ``run_stage`` shape as ``slopsquat_verdict.py``: the
registry evidence is fed as a trust-tagged block so the LLM treats it as
potentially adversarial. Returns ``None`` when the LLM is unavailable or the
call fails — the caller (the gate) then treats the candidate as ``unsure`` and
escalates to a human (never auto-trusts on a missing verdict).
"""

from __future__ import annotations

import logging
from typing import Optional

from core.llm.task_types import TaskType

from . import StageResult, TaintedString, UntrustedBlock, run_stage
from .prompts import TYPOSQUAT_TRIAGE_SYSTEM
from .schemas import TyposquatTriageVerdict

logger = logging.getLogger(__name__)


def assess_typosquat(
    client,
    ecosystem: str,
    name: str,
    near_twin: str,
    rank: int,
    twin_rank: int,
    distance: int,
    evidence_text: str,
) -> Optional[TyposquatTriageVerdict]:
    """Run the LLM on one near-name candidate + its registry evidence.

    ``evidence_text`` is the rendered registry block (description, age,
    releases, repo, deprecation, downloads). Returns ``None`` on LLM
    unavailability / failure — the caller escalates rather than guessing."""
    relation = (
        f"Candidate: {ecosystem}/{name} (popularity rank #{rank})\n"
        f"Near-twin (much more popular): {near_twin} (rank #{twin_rank})\n"
        f"Edit distance: {distance}"
    )

    result: StageResult = run_stage(
        client=client,
        system=TYPOSQUAT_TRIAGE_SYSTEM,
        untrusted_blocks=(
            UntrustedBlock(
                content=relation,
                kind="CANDIDATE_RELATION",
                origin="raptor-sca typosquat candidate generator",
            ),
            UntrustedBlock(
                content=evidence_text,
                kind="REGISTRY_EVIDENCE",
                origin=f"{ecosystem}/{name} registry metadata",
            ),
        ),
        slots={
            "package_name": TaintedString(value=name, trust="untrusted"),
            "near_twin": TaintedString(value=near_twin, trust="untrusted"),
            "ecosystem": TaintedString(value=ecosystem, trust="trusted"),
        },
        schema_cls=TyposquatTriageVerdict,
        task_type=TaskType.CLASSIFY,
    )

    if result.error or result.model is None:
        logger.debug("sca.llm.typosquat_triage: %s/%s failed: %s",
                     ecosystem, name, result.error)
        return None

    verdict: TyposquatTriageVerdict = result.model  # type: ignore[assignment]
    # Cap confidence at medium when preflight saw injection indicators in the
    # (attacker-controlled) registry block — same haircut as slopsquat_verdict.
    if result.preflight_hit and verdict.confidence == "high":
        verdict = verdict.model_copy(update={"confidence": "medium"})
    return verdict


__all__ = ["TyposquatTriageVerdict", "assess_typosquat"]
