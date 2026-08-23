"""Coverage record builder for Semgrep — same shape as Coccinelle/CodeQL records."""

from datetime import datetime, timezone

from .models import SemgrepResult


def to_coverage_record(
    results: list[SemgrepResult],
    *,
    rules_applied: list[str] | None = None,
) -> dict | None:
    """Build a coverage-semgrep.json record from in-memory SemgrepResult objects.

    Aggregates files_examined and files_failed across all results. Returns
    None if no files were examined across any result (no point writing an
    empty record).

    Args:
        results: SemgrepResult objects from one or more run_rule invocations.
        rules_applied: Optional explicit list of rule groups/packs applied.
            If None, derived from each result's name.

    Returns:
        Coverage record dict matching the schema in core/coverage/record.py,
        or None if there's nothing to record.
    """
    files = set()
    failures: list[dict[str, str]] = []
    versions = []
    derived_rules: list[str] = []

    for r in results:
        files.update(r.files_examined)
        failures.extend({
                "rule": r.name or "semgrep",
                "path": f.get("path", ""),
                "reason": f.get("reason", "error"),
            } for f in r.files_failed)
        failures.extend({"rule": r.name or "semgrep", "reason": err} for err in r.errors)
        if r.semgrep_version:
            versions.append(r.semgrep_version)
        if r.name:
            derived_rules.append(r.name)

    if not files:
        return None

    record: dict = {
        "tool": "semgrep",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
    }

    rules = rules_applied if rules_applied is not None else list(dict.fromkeys(derived_rules))
    if rules:
        record["rules_applied"] = rules
    if versions:
        record["version"] = versions[0]
    if failures:
        record["files_failed"] = failures

    return record
