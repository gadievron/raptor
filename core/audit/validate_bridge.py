"""Validate↔audit bridge: cross-command evidence reuse.

When /validate has already run on the same target, /audit imports
its Stage E feasibility verdicts and runtime evidence rather than
re-analysing the binary.  The reverse direction also works: /audit
Layer 0 findings and taint flows feed /validate's Stage A/C.

Search order for sibling output (same as understand_bridge):
  1. Co-located (same output directory — shared --out)
  2. Project siblings (same project, different run type)
  3. Global out/ by target path + SHA-256 freshness

No binary is analysed twice — the first command to touch it caches
results by build-ID; subsequent commands consume the cache.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BridgeResult:
    """What the bridge imported from a sibling run."""

    source_dir: str = ""
    source_command: str = ""
    feasibility_verdicts: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_profile: Optional[Dict[str, Any]] = None
    runtime_evidence: List[Dict[str, Any]] = field(default_factory=list)
    layer0_findings: List[Dict[str, Any]] = field(default_factory=list)
    taint_flows: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_content(self) -> bool:
        return bool(
            self.feasibility_verdicts
            or self.mitigation_profile
            or self.runtime_evidence
            or self.layer0_findings
            or self.taint_flows
        )

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "source_dir": self.source_dir,
            "source_command": self.source_command,
            "imported": {
                "feasibility_verdicts": len(self.feasibility_verdicts),
                "has_mitigation_profile": self.mitigation_profile is not None,
                "runtime_evidence": len(self.runtime_evidence),
                "layer0_findings": len(self.layer0_findings),
                "taint_flows": len(self.taint_flows),
            },
        }
        return d


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _load_json_list(path: Path) -> List[Dict[str, Any]]:
    data = _load_json(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("findings", "items", "flows", "results"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def _extract_feasibility_verdicts(
    findings_data: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Extract feasibility verdicts from /validate findings.json."""
    if not findings_data:
        return []

    findings = findings_data.get("findings", [])
    verdicts = []
    for f in findings:
        feasibility = f.get("feasibility")
        if feasibility:
            verdicts.append({
                "finding_id": f.get("id", ""),
                "function": f.get("function", ""),
                "file": f.get("file", ""),
                "verdict": feasibility.get("verdict", ""),
                "final_status": f.get("final_status", ""),
                "chain_breaks": feasibility.get("chain_breaks", []),
            })
    return verdicts


def _extract_runtime_evidence(
    findings_data: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Extract Frida/dynamic evidence from /validate findings."""
    if not findings_data:
        return []

    findings = findings_data.get("findings", [])
    evidence = []
    for f in findings:
        for ev in f.get("evidence_chain", []):
            if ev.get("tier") in ("OBSERVED_RUNTIME", "REPLAYED_CRASH"):
                evidence.append({
                    "finding_id": f.get("id", ""),
                    "function": f.get("function", ""),
                    "file": f.get("file", ""),
                    "source": ev.get("source", ""),
                    "tier": ev.get("tier", ""),
                    "detail": ev.get("detail", ""),
                })
    return evidence


def _extract_mitigation_profile(
    findings_data: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Extract binary mitigation profile from /validate feasibility data."""
    if not findings_data:
        return None
    findings = findings_data.get("findings", [])
    for f in findings:
        feasibility = f.get("feasibility", {})
        mitigations = feasibility.get("mitigations") or feasibility.get("security_posture")
        if mitigations and isinstance(mitigations, dict):
            return mitigations
    metadata = findings_data.get("metadata", {})
    posture = metadata.get("security_posture") or metadata.get("mitigations")
    if posture and isinstance(posture, dict):
        return posture
    return None


def _check_target_match(
    candidate_dir: Path,
    target_path: Path,
) -> bool:
    """Check if a candidate output dir is for the same target."""
    checklist = _load_json(candidate_dir / "checklist.json")
    if not checklist:
        manifest = _load_json(candidate_dir / ".raptor-run.json")
        if manifest:
            return str(target_path) == manifest.get("target", "")
        return False

    return checklist.get("target", "") == str(target_path)


def import_validate_evidence(
    audit_output_dir: Path,
    target_path: Path,
    *,
    project_dir: Optional[Path] = None,
) -> BridgeResult:
    """Find and import /validate output for the same target.

    Search order:
      1. Co-located (same output dir)
      2. Project siblings (same project, different run type)
      3. Global out/ by target path match
    """
    result = BridgeResult()

    # 1. Co-located
    findings_path = audit_output_dir / "findings.json"
    if findings_path.is_file():
        data = _load_json(findings_path)
        if data and data.get("findings"):
            first = data["findings"][0]
            if first.get("feasibility"):
                result.source_dir = str(audit_output_dir)
                result.source_command = "validate (co-located)"
                result.feasibility_verdicts = _extract_feasibility_verdicts(data)
                result.runtime_evidence = _extract_runtime_evidence(data)
                result.mitigation_profile = _extract_mitigation_profile(data)
                logger.debug("bridge: found co-located validate output")
                return result

    # 2. Project siblings
    if project_dir and project_dir.is_dir():
        for sibling in sorted(project_dir.iterdir(), reverse=True):
            if not sibling.is_dir():
                continue
            if not sibling.name.startswith("exploitability-validation"):
                continue
            if not _check_target_match(sibling, target_path):
                continue

            sibling_findings = _load_json(sibling / "findings.json")
            if sibling_findings:
                result.source_dir = str(sibling)
                result.source_command = "validate (project sibling)"
                result.feasibility_verdicts = _extract_feasibility_verdicts(
                    sibling_findings
                )
                result.runtime_evidence = _extract_runtime_evidence(
                    sibling_findings
                )
                result.mitigation_profile = _extract_mitigation_profile(
                    sibling_findings
                )
                logger.debug("bridge: found project sibling at %s", sibling)
                return result

    # 3. Global out/
    out_dir = Path("out")
    if out_dir.is_dir():
        for candidate in sorted(out_dir.iterdir(), reverse=True):
            if not candidate.is_dir():
                continue
            if "validation" not in candidate.name:
                continue
            if not _check_target_match(candidate, target_path):
                continue

            candidate_findings = _load_json(candidate / "findings.json")
            if candidate_findings:
                result.source_dir = str(candidate)
                result.source_command = "validate (global out)"
                result.feasibility_verdicts = _extract_feasibility_verdicts(
                    candidate_findings
                )
                result.runtime_evidence = _extract_runtime_evidence(
                    candidate_findings
                )
                result.mitigation_profile = _extract_mitigation_profile(
                    candidate_findings
                )
                logger.debug("bridge: found global validate output at %s", candidate)
                return result

    return result


def import_audit_evidence(
    validate_output_dir: Path,
    target_path: Path,
    *,
    project_dir: Optional[Path] = None,
) -> BridgeResult:
    """Find and import /audit output for /validate to consume.

    Reverse direction: /audit's Layer 0 findings and taint flows
    feed /validate's Stage A pre-population.
    """
    result = BridgeResult()

    search_dirs = []

    # 1. Co-located
    search_dirs.append(validate_output_dir)

    # 2. Project siblings
    if project_dir and project_dir.is_dir():
        for sibling in sorted(project_dir.iterdir(), reverse=True):
            if sibling.is_dir() and sibling.name.startswith("audit_"):
                search_dirs.append(sibling)

    # 3. Global out/
    out_dir = Path("out")
    if out_dir.is_dir():
        for candidate in sorted(out_dir.iterdir(), reverse=True):
            if candidate.is_dir() and candidate.name.startswith("audit_"):
                search_dirs.append(candidate)

    for candidate in search_dirs:
        if not _check_target_match(candidate, target_path):
            continue

        layer0 = _load_json(candidate / "layer0-findings.json")
        if layer0:
            result.layer0_findings = layer0.get("findings", [])

        findings = _load_json(candidate / "findings.json")
        if findings:
            for f in findings.get("findings", []):
                for ev in f.get("evidence_chain", []):
                    if ev.get("source") in ("joern_taint", "joern"):
                        result.taint_flows.append({
                            "finding_id": f.get("id", ""),
                            "function": f.get("function", ""),
                            "file": f.get("file", ""),
                            "detail": ev.get("detail", ""),
                        })

        if result.layer0_findings or result.taint_flows:
            result.source_dir = str(candidate)
            result.source_command = "audit"
            logger.debug(
                "bridge: found audit output at %s (%d layer0, %d taint)",
                candidate,
                len(result.layer0_findings),
                len(result.taint_flows),
            )
            return result

    return result


def format_bridge_summary(result: BridgeResult) -> str:
    if not result.has_content:
        return "Cross-command bridge: no sibling output found"

    parts = [f"Cross-command bridge: imported from {result.source_command}"]
    if result.feasibility_verdicts:
        parts.append(
            f"  {len(result.feasibility_verdicts)} feasibility verdicts"
        )
    if result.mitigation_profile:
        parts.append("  mitigation profile")
    if result.runtime_evidence:
        parts.append(f"  {len(result.runtime_evidence)} runtime evidence items")
    if result.layer0_findings:
        parts.append(f"  {len(result.layer0_findings)} Layer 0 findings")
    if result.taint_flows:
        parts.append(f"  {len(result.taint_flows)} taint flows")
    return "\n".join(parts)
