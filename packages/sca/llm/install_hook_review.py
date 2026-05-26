"""LLM review of install lifecycle scripts.

Covers all ecosystems with automatic install hooks:

- npm: preinstall, install, postinstall, prepare, prepublishOnly
- PyPI: setup.py custom build, pyproject.toml custom build backends
- Cargo: build.rs, [package].build
- RubyGems: extconf.rb, Rakefile build tasks
- Composer: scripts.*-install, scripts.*-update

The mechanical detector (``supply_chain.install_hooks``) already fires
on regex-matched dangerous patterns.  This stage adds behavioural
analysis: the LLM reads the full script and judges intent, catching
obfuscated or indirect patterns the regex misses.

**Mechanical override:** the LLM verdict is additive signal.  It cannot
suppress a mechanical ``install_hook_suspicious`` finding.  If the LLM
says "benign" but the mechanical detector fired, the mechanical finding
stands at its original severity.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.llm.task_types import TaskType
from ..models import Confidence, SupplyChainFinding
from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    cross_family_check,
    run_stage,
)
from .exemplars import exfil_destinations_block
from .prompts import INSTALL_HOOK_SYSTEM
from .schemas import InstallHookVerdict

logger = logging.getLogger(__name__)


def review_install_hooks(
    client,
    findings: List[SupplyChainFinding],
) -> List[SupplyChainFinding]:
    """Enrich install-hook findings with LLM behavioural analysis.

    For each ``install_hook_suspicious`` finding that carries a script
    body in its evidence, run the LLM review and merge the verdict back
    into the finding's detail and evidence fields.

    Returns the same list with enriched findings (mutated in place for
    efficiency — the caller owns the list).
    """
    hook_findings = [
        f for f in findings
        if f.kind == "install_hook_suspicious"
        and f.evidence.get("script_body")
    ]
    if not hook_findings:
        return findings

    for finding in hook_findings:
        script_body = finding.evidence["script_body"]
        script_key = finding.evidence.get("script_key", "unknown")
        pkg_name = finding.dependency.name
        ecosystem = finding.dependency.ecosystem

        result = _review_one(
            client, script_body, script_key, pkg_name, ecosystem,
        )
        if result is None:
            continue

        _merge_verdict(finding, result)

    return findings


def _review_one(
    client,
    script_body: str,
    script_key: str,
    pkg_name: str,
    ecosystem: str,
) -> Optional[InstallHookVerdict]:
    """Run the LLM on a single install script."""
    blocks: list[UntrustedBlock] = [
        UntrustedBlock(
            content=script_body,
            kind="SCRIPT",
            origin=f"{ecosystem}/{pkg_name} scripts.{script_key}",
        ),
    ]
    exfil = exfil_destinations_block()
    if exfil is not None:
        blocks.append(exfil)
    slots = {
        "package_name": TaintedString(value=pkg_name, trust="untrusted"),
        "ecosystem": TaintedString(value=ecosystem, trust="trusted"),
        "hook_phase": TaintedString(value=script_key, trust="trusted"),
    }

    blocks_t = tuple(blocks)
    result: StageResult = run_stage(
        client=client,
        system=INSTALL_HOOK_SYSTEM,
        untrusted_blocks=blocks_t,
        slots=slots,
        schema_cls=InstallHookVerdict,
        task_type=TaskType.ANALYSE,
    )

    if result.error:
        logger.debug("sca.llm.install_hook_review: %s/%s failed: %s",
                      ecosystem, pkg_name, result.error)
        return None

    # Cross-family verification for malicious/suspicious verdicts.
    result = cross_family_check(
        client=client,
        system=INSTALL_HOOK_SYSTEM,
        untrusted_blocks=blocks_t,
        slots=slots,
        schema_cls=InstallHookVerdict,
        primary_result=result,
        verdict_field="verdict",
        high_severity_values=("malicious", "suspicious"),
        task_type=TaskType.ANALYSE,
    )

    verdict: Optional[InstallHookVerdict] = result.model  # type: ignore[assignment]
    if verdict is None:
        return None

    if result.preflight_hit and verdict.confidence == "high":
        verdict = verdict.model_copy(update={"confidence": "medium"})

    return verdict


def _merge_verdict(
    finding: SupplyChainFinding,
    verdict: InstallHookVerdict,
) -> None:
    """Merge LLM verdict into a mechanical finding.

    **Mechanical override rule:** the LLM can only *escalate* severity,
    never downgrade.  A "benign" LLM verdict on a mechanically-flagged
    finding is recorded for transparency but does not change severity.
    """
    finding.evidence["llm_verdict"] = verdict.verdict
    finding.evidence["llm_confidence"] = verdict.confidence
    finding.evidence["llm_behaviours"] = list(verdict.behaviours)
    finding.evidence["llm_reasoning"] = verdict.reasoning
    if verdict.evidence_quotes:
        finding.evidence["llm_evidence_quotes"] = list(verdict.evidence_quotes)

    if verdict.verdict == "malicious":
        finding.severity = "critical"
        finding.confidence = Confidence(
            level=verdict.confidence,
            numeric=_confidence_numeric(verdict.confidence),
            reason="LLM classified as malicious",
        )
    elif verdict.verdict == "suspicious" and finding.severity in ("low", "info"):
        finding.severity = "medium"

    if verdict.behaviours:
        existing = finding.evidence.get("reasons", [])
        for b in verdict.behaviours:
            tag = f"llm:{b}"
            if tag not in existing:
                existing.append(tag)
        finding.evidence["reasons"] = existing


def _confidence_numeric(level: str) -> float:
    return {"low": 0.30, "medium": 0.70, "high": 0.95}.get(level, 0.50)
