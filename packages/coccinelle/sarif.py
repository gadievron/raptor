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
from typing import Any, Dict, Iterable, List

from .models import SpatchResult


# SARIF level mapping. spatch doesn't emit severity; we treat every
# match as ``warning`` (the default for bug-pattern detectors that
# haven't been triaged). Operators promote to ``error`` via the
# usual finding-review path.
_DEFAULT_LEVEL = "warning"

# Tool driver shape mirrors what semgrep / codeql emit.
_TOOL_NAME = "coccinelle"
_TOOL_FULL_NAME = "Coccinelle (spatch)"
_TOOL_INFO_URI = "https://coccinelle.gitlabpages.inria.fr/website/"


def _rel_to_repo(file_path: str, repo_path: Path) -> str:
    """Best-effort repo-relative path. SpatchMatch's ``file`` is
    sometimes absolute (when spatch was given an absolute target) or
    target-relative (when given a relative target). Normalize so two
    findings at the same line dedupe across spatch invocations."""
    if not file_path:
        return ""
    try:
        p = Path(file_path)
        if p.is_absolute():
            return str(p.resolve().relative_to(repo_path.resolve()))
    except (ValueError, OSError):
        # Cross-FS, non-repo path — leave as-is.
        pass
    return file_path


def results_to_sarif(
    results: Iterable[SpatchResult],
    repo_path: Path,
) -> Dict[str, Any]:
    """Turn a sequence of per-rule ``SpatchResult`` into a SARIF 2.1.0
    document. Rules with no matches still appear in
    ``tool.driver.rules`` so operators see the rule corpus that ran;
    only the ``results`` list filters to actual matches.
    """
    repo_path = Path(repo_path)

    # Collect distinct rule definitions. ``rule`` is the rule's stem
    # (filename without .cocci), used as ``ruleId`` in results.
    rule_defs: List[Dict[str, Any]] = []
    seen_rule_ids: set = set()
    sarif_results: List[Dict[str, Any]] = []
    notifications: List[Dict[str, Any]] = []

    for r in results:
        rule_id = r.rule or "(unnamed)"
        if rule_id not in seen_rule_ids:
            rule_defs.append({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "fullDescription": {"text": (
                    f"Coccinelle rule emitted from {r.rule_path}"
                    if r.rule_path else f"Coccinelle rule {rule_id}"
                )},
                "defaultConfiguration": {"level": _DEFAULT_LEVEL},
                "helpUri": _TOOL_INFO_URI,
            })
            seen_rule_ids.add(rule_id)

        for match in r.matches:
            file_rel = _rel_to_repo(match.file, repo_path)
            sarif_results.append({
                "ruleId": rule_id,
                "level": _DEFAULT_LEVEL,
                "message": {
                    "text": match.message or f"{rule_id} matched",
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_rel},
                        "region": {
                            "startLine": match.line,
                            **({"endLine": match.line_end}
                               if match.line_end else {}),
                            **({"startColumn": match.column}
                               if match.column else {}),
                            **({"endColumn": match.column_end}
                               if match.column_end else {}),
                        },
                    },
                }],
            })

        # spatch errors → SARIF tool-execution notifications. Distinct
        # from results — operators see the rule had a problem without
        # mistaking it for a finding.
        for err in r.errors or []:
            notifications.append({
                "level": "error",
                "message": {"text": err[:500]},
                "associatedRule": {"id": rule_id},
            })

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": _TOOL_NAME,
                "fullName": _TOOL_FULL_NAME,
                "informationUri": _TOOL_INFO_URI,
                "rules": rule_defs,
            },
        },
        "results": sarif_results,
    }
    if notifications:
        run["invocations"] = [{
            "executionSuccessful": False,
            "toolExecutionNotifications": notifications,
        }]

    return {
        "$schema":
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master"
            "/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
