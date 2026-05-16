"""Coverage record builder for Coccinelle — same shape as Semgrep/CodeQL records."""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from .models import SpatchResult


def to_coverage_record(results: List[SpatchResult]) -> Optional[Dict]:
    """Build a coverage-coccinelle.json record from spatch results.

    Returns None if no files were examined.
    """
    files = set()
    rules = []
    failures = []

    for r in results:
        files.update(r.files_examined)
        if r.rule:
            rules.append(r.rule)
        for err in r.errors:
            failures.append({"rule": r.rule, "reason": err})

    if not files:
        return None

    record: Dict = {
        "tool": "coccinelle",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
    }
    if rules:
        record["rules_applied"] = list(dict.fromkeys(rules))
    if failures:
        record["files_failed"] = failures

    return record
