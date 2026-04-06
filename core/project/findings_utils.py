"""Shared findings utilities for diff and merge.

Centralises finding ID extraction and loading to avoid duplication
across diff.py and merge.py.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from core.json import load_json
from core.logging import get_logger

logger = get_logger()


def get_finding_id(finding: Dict[str, Any]) -> Optional[str]:
    """Extract finding ID, checking both 'id' and 'finding_id' fields."""
    return finding.get("id") or finding.get("finding_id")


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
