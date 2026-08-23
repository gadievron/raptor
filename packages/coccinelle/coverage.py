"""Coverage record builder for Coccinelle — same shape as Semgrep/CodeQL records."""

from datetime import datetime, timezone

from .models import SpatchResult


def to_coverage_record(results: list[SpatchResult]) -> dict | None:
    """Build a coverage-coccinelle.json record from spatch results.

    Returns None if no files were examined.
    """
    files = set()
    rules = []
    failures: list[dict[str, str]] = []

    for r in results:
        files.update(r.files_examined)
        if r.rule:
            rules.append(r.rule)
        failures.extend({"rule": r.rule, "reason": err} for err in r.errors)

    if not files:
        return None

    record: dict = {
        "tool": "coccinelle",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
    }
    if rules:
        record["rules_applied"] = list(dict.fromkeys(rules))
    if failures:
        record["files_failed"] = failures

    return record
