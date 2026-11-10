"""Convert ``SpatchResult`` to SARIF for RAPTOR's combined-scan output.

``packages/static-analysis/scanner.py`` emits per-tool SARIFs that
``core.sarif.parser.merge_sarif`` unions into one combined.sarif. This
module is the cocci leg of that pipeline.

Single-file conversion so the dependency graph stays narrow:
``packages.coccinelle.runner`` returns ``SpatchResult``, this turns it
into the SARIF dict, the scanner does the file write. No I/O here —
keeps the converter testable without filesystem fixtures.

SARIF schema target: 2.1.0 (the version ``merge_sarif`` consumes).
Each ``SpatchMatch`` becomes one ``runs[*].results[*]`` entry. Each
distinct rule name becomes one ``runs[*].tool.driver.rules[*]`` entry
so downstream consumers (operator triage, /agentic prep, /validate
pre-check) can filter by rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.sarif import emit


if TYPE_CHECKING:
    from .models import SpatchResult
    from collections.abc import Iterable


# SARIF level mapping. spatch doesn't emit severity; we treat every
# match as ``warning`` (the default for bug-pattern detectors that
# haven't been triaged). Operators promote to ``error`` via the
# usual finding-review path.
_DEFAULT_LEVEL = "warning"

# Tool driver shape mirrors what semgrep / codeql emit.
_TOOL_NAME = "coccinelle"
_TOOL_FULL_NAME = "Coccinelle (spatch)"
_TOOL_INFO_URI = "https://coccinelle.gitlabpages.inria.fr/website/"


def _rel_to_repo(file_path: str, repo_path: Path | None) -> str:
    """Normalize a match lexically against the already resolved target root.

    Keep explicit outside-target paths as supplied; never borrow a local
    basename or follow source-file symlinks while formatting a report.
    """
    from core.paths import to_repo_relative

    if not file_path:
        return ""
    # Spatch supplies filesystem paths, not file:// URIs. Preserve legacy
    # spelling for URI-looking names rather than rebinding their basename.
    if repo_path is None or file_path.startswith("file://"):
        return file_path
    relative = to_repo_relative(file_path, repo_path, outside_root="relative")
    confined = to_repo_relative(relative, repo_path) if relative is not None else None
    return confined if confined is not None else file_path


def results_to_sarif(
    results: Iterable[SpatchResult],
    repo_path: Path,
) -> dict[str, Any]:
    """Turn a sequence of per-rule ``SpatchResult`` into a SARIF 2.1.0
    document. Rules with no matches still appear in
    ``tool.driver.rules`` so operators see the rule corpus that ran;
    only the ``results`` list filters to actual matches.
    """
    try:
        resolved_root = Path(repo_path).resolve()
    except (OSError, RuntimeError):
        # Report formatting must not discard findings when the target has
        # disappeared or its root can no longer be resolved.
        resolved_root = None

    # Collect distinct rule definitions. ``rule`` is the rule's stem
    # (filename without .cocci), used as ``ruleId`` in results.
    rule_index = emit.RuleIndex()
    sarif_results: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []
    relative_paths: dict[str, str] = {}

    for r in results:
        rule_id = r.rule or "(unnamed)"
        rule_index.add(emit.minimal_rule(
            rule_id,
            full_description=(
                f"Coccinelle rule emitted from {r.rule_path}"
                if r.rule_path else f"Coccinelle rule {rule_id}"
            ),
            level=_DEFAULT_LEVEL,
            help_uri=_TOOL_INFO_URI,
        ))

        for match in r.matches:
            if type(match.file) is str:
                file_rel = relative_paths.get(match.file)
                if file_rel is None:
                    file_rel = _rel_to_repo(match.file, resolved_root)
                    relative_paths[match.file] = file_rel
            else:
                # String adapters may override operations or disable hashing.
                file_rel = _rel_to_repo(match.file, resolved_root)
            sarif_results.append(emit.result(
                rule_id,
                match.message or f"{rule_id} matched",
                [emit.location(file_rel, emit.source_region(
                    match.line, end_line=match.line_end,
                    column=match.column, end_column=match.column_end,
                ))],
                level=_DEFAULT_LEVEL,
            ))

        # spatch errors → SARIF tool-execution notifications. Distinct
        # from results — operators see the rule had a problem without
        # mistaking it for a finding.
        notifications.extend({
                "level": "error",
                "message": {"text": err[:500]},
                "associatedRule": {"id": rule_id},
            } for err in r.errors or [])

    run: dict[str, Any] = emit.run(
        _TOOL_NAME, rule_index.rules(), sarif_results,
        full_name=_TOOL_FULL_NAME, information_uri=_TOOL_INFO_URI,
    )
    if notifications:
        run["invocations"] = [{
            "executionSuccessful": False,
            "toolExecutionNotifications": notifications,
        }]

    return emit.document([run], schema_uri=emit.SCHEMA_URI_COMMITTEE)
