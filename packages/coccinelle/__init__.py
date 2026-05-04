"""Coccinelle integration — semantic patching and inconsistency detection for C/C++.

Public API:
    from packages.coccinelle import run_rule, run_rules, SpatchMatch, SpatchResult

    result = run_rule(target=Path("/src"), rule=Path("rule.cocci"))
    for match in result.matches:
        print(f"{match.file}:{match.line}: {match.message}")
"""

from .runner import run_rule, run_rules, is_available, version
from .models import SpatchMatch, SpatchResult
from .findings import to_findings
from .coverage import to_coverage_record

__all__ = [
    "run_rule",
    "run_rules",
    "is_available",
    "version",
    "SpatchMatch",
    "SpatchResult",
    "to_findings",
    "to_coverage_record",
]
