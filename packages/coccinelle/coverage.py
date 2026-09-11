"""Coverage record builder for Coccinelle — same shape as Semgrep/CodeQL records."""

from datetime import datetime, timezone

from .models import SpatchResult


def to_coverage_record(results: list[SpatchResult]) -> dict | None:
    """Build a coverage-coccinelle.json record from spatch results.

    Returns None only when there is no signal at all (no files, no
    rules, no failures) — a total-failure run (spatch failed to parse
    every rule, nothing examined) still yields a record carrying
    rules_applied and files_failed, matching
    ``core.coverage.record.build_from_cocci``: engine failure must not
    read as verified silence.
    """
    files = set()
    rules = []
    failures: list[dict[str, str]] = []

    for r in results:
        files.update(r.files_examined)
        if r.rule:
            rules.append(r.rule)
        # Failures are path-bearing (sibling-builder contract:
        # consumers key and dedupe on ``path``). spatch errors carry
        # no per-file binding — the rule itself is what failed — so
        # the rule name is the path, exactly as build_from_cocci emits.
        failures.extend({
            "rule": r.rule,
            "path": r.rule,
            "reason": str(err)[:500],
        } for err in r.errors)

    failures = [f for f in failures if f.get("path")]

    if not files and not rules and not failures:
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
