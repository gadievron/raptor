"""Coccinelle integration — semantic patching and inconsistency detection for C.

C only: the runner's directory walk enumerates ``*.c``/``*.h`` and
spatch parses C translation units — C++ sources (``.cc``/``.cpp``/
``.hpp``…) are never examined, and the prereqs evaluator skips
findings on them rather than answering from a blind fact base.

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
    "SpatchMatch",
    "SpatchResult",
    "is_available",
    "run_rule",
    "run_rules",
    "to_coverage_record",
    "to_findings",
    "version",
]
