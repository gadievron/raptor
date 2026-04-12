"""Shared findings utilities for diff and merge.

Centralises finding ID extraction, loading, and semantic grouping
to avoid duplication across diff.py, merge.py, and coverage.
"""

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.json import load_json
from core.logging import get_logger

logger = get_logger()


def get_finding_id(finding: Dict[str, Any]) -> Optional[str]:
    """Extract finding ID, checking both 'id' and 'finding_id' fields."""
    return finding.get("id") or finding.get("finding_id")


def dedup_key(finding: Dict[str, Any]) -> Tuple[str, str, int]:
    """Dedup key for a finding: (file, function, line). More stable than ID."""
    return (finding.get("file", ""), finding.get("function", ""), finding.get("line", 0))


def group_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """Semantic group key: (file, function, vuln_type).

    Findings with the same group key are likely the same logical bug
    (e.g. TOCTOU check at line 7 and use at line 10).
    """
    return (
        finding.get("file", ""),
        finding.get("function", ""),
        finding.get("vuln_type", ""),
    )


def group_findings(findings: List[Dict[str, Any]]) -> Dict[Tuple, List[Dict[str, Any]]]:
    """Group findings by (file, function, vuln_type).

    Returns:
        Dict mapping group_key -> list of findings in that group.
        Single-finding groups represent unique vulns.
        Multi-finding groups represent one logical vuln with multiple locations.
    """
    groups: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        groups[group_key(f)].append(f)
    return dict(groups)


def count_vulns(findings: List[Dict[str, Any]]) -> int:
    """Count logical vulns (semantic groups) rather than raw findings."""
    return len(group_findings(findings))


def load_findings_from_dir(run_dir: Path) -> List[Dict[str, Any]]:
    """Load findings list from a run directory's findings.json."""
    data = load_json(run_dir / "findings.json")
    if data is None:
        logger.debug(f"No findings.json in {run_dir}")
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", data.get("results", []))
    return []
