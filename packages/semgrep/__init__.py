"""Semgrep integration — pattern-matching static analysis for many languages.

Public API:
    from packages.semgrep import run_rule, run_rules, SemgrepFinding, SemgrepResult

    result = run_rule(target=Path("/src"), config="p/security-audit")
    for finding in result.findings:
        print(f"{finding.file}:{finding.line}: {finding.rule_id} — {finding.message}")

This package owns Semgrep invocation and result parsing only. Sandbox engagement,
HOME redirect, registry-pack proxy hosts, and parallel orchestration belong to
the caller (e.g. packages/static-analysis/scanner.py).
"""

from .runner import build_cmd, is_available, run_rule, run_rules, version
from .models import SemgrepFinding, SemgrepResult
from .findings import to_findings
from .coverage import to_coverage_record

__all__ = [
    "build_cmd",
    "is_available",
    "run_rule",
    "run_rules",
    "version",
    "SemgrepFinding",
    "SemgrepResult",
    "to_findings",
    "to_coverage_record",
]
