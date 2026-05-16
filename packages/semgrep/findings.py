"""Convert Semgrep results to RAPTOR findings format."""

from collections import defaultdict
from typing import Dict, List

from .models import SemgrepResult


def to_findings(results: List[SemgrepResult]) -> List[Dict]:
    """Convert Semgrep results to RAPTOR findings.json entries.

    Each Semgrep finding becomes a finding with origin "semgrep". The vuln_type
    is left blank — the caller (typically the agentic pipeline) maps from
    rule_id to a CWE/vuln_type via core/sarif normalisation.
    """
    findings = []
    counters: Dict[str, int] = defaultdict(int)
    for result in results:
        run_label = result.name or "semgrep"
        for f in result.findings:
            counters[run_label] += 1
            findings.append({
                "id": f"SEMGREP-{run_label}-{counters[run_label]}",
                "file": f.file,
                "line": f.line,
                "function": "",
                "vuln_type": "",
                "confidence": "medium",
                "origin": "semgrep",
                "rule": f.rule_id,
                "level": f.level,
                "description": f.message or f"Match for {f.rule_id}",
            })
    return findings
