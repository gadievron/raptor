"""Coverage record builder for Semgrep — same shape as Coccinelle/CodeQL records."""

from datetime import datetime, timezone

from .models import SemgrepResult


def to_coverage_record(
    results: list[SemgrepResult],
    *,
    rules_applied: list[str] | None = None,
) -> dict | None:
    """Build a coverage-semgrep.json record from in-memory SemgrepResult objects.

    Aggregates files_examined and files_failed across all results.
    Returns None only when there is no signal at all (no files, no
    rules, no failures) — a total-failure run (every pack errored, no
    file scanned) still yields a record carrying rules_applied and
    files_failed, matching ``core.coverage.record``'s builders:
    engine failure must not read as verified silence.

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
        # Path-bearing per-file failures (any level) — the entries
        # parse_json_output routed into files_failed.
        failed_reasons = set()
        for f in r.files_failed:
            failures.append({
                "rule": r.name or "semgrep",
                "path": f.get("path", ""),
                "reason": f.get("reason", "error"),
            })
            failed_reasons.add(f.get("reason", "error"))
        # Engine-level errors. parse_json_output renders error/fatal
        # entries into ``errors`` regardless of whether they were also
        # path-bearing, so an error-level per-file failure appears in
        # BOTH lists — skip renderings whose message is already
        # accounted for above, otherwise one underlying error produces
        # two files_failed records and inflates failure counts.
        for err in r.errors:
            if any(reason and reason in err for reason in failed_reasons):
                continue
            # Every entry is path-bearing (sibling-builder contract:
            # consumers key and dedupe on ``path``); no per-file
            # binding exists for an engine error, so the pack itself
            # is what failed — mirror build_from_cocci's rule-as-path.
            failures.append({
                "rule": r.name or "semgrep",
                "path": r.name or "semgrep",
                "reason": err,
            })
        if r.semgrep_version:
            versions.append(r.semgrep_version)
        if r.name:
            derived_rules.append(r.name)

    rules = rules_applied if rules_applied is not None else list(dict.fromkeys(derived_rules))
    failures = [f for f in failures if f.get("path")]

    if not files and not rules and not failures:
        return None

    record: dict = {
        "tool": "semgrep",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
    }

    if rules:
        record["rules_applied"] = rules
    if versions:
        record["version"] = versions[0]
    if failures:
        record["files_failed"] = failures

    return record
