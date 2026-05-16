"""Convert Coccinelle results to RAPTOR findings format."""

from collections import defaultdict
from typing import Dict, List

from .models import SpatchResult


def to_findings(results: List[SpatchResult]) -> List[Dict]:
    """Convert spatch results to RAPTOR findings.json entries.

    Each match becomes a finding with origin "coccinelle" and
    vuln_type "inconsistency" (Coccinelle's primary value-add).
    """
    findings = []
    counters: Dict[str, int] = defaultdict(int)
    for result in results:
        for match in result.matches:
            counters[result.rule] += 1
            findings.append({
                "id": f"COCCI-{result.rule}-{counters[result.rule]}",
                "file": match.file,
                "line": match.line,
                "function": "",
                "vuln_type": "inconsistency",
                "confidence": "medium",
                "origin": "coccinelle",
                "rule": result.rule,
                "description": match.message or f"Inconsistency detected by {result.rule}",
            })
    return findings
