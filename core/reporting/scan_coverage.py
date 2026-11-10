"""Operator-facing tool-execution coverage renderer.

Reads the ``coverage-<tool>.json`` records each scanner emits and
renders a small aligned block at /scan end so the operator sees
which tools actually ran, how many findings each produced, and any
silent-drop signal (failed packs surfaced by the scanner's own
detection).

Distinct from ``core/coverage/store_summary.py``: that one renders
the FUNCTION-level inventory coverage ("which functions did any
tool examine?"). This one renders the TOOL-EXECUTION coverage
("which tools ran with what result?"). They're complementary —
function-coverage answers "what code did we look at"; tool-coverage
answers "what did we look at it WITH".
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.json import load_json
from core.security.log_sanitisation import sanitise_excerpt

if TYPE_CHECKING:
    from pathlib import Path


# coverage-<tool>.json / scan_metrics.json are small RAPTOR-written
# run records.
_MAX_RECORD_BYTES = 8 * 1024 * 1024

# Tool display ordering — most-likely-to-fire first so the block
# reads top-to-bottom in approximate produce-findings order.
_TOOL_ORDER = ("semgrep", "coccinelle", "codeql", "sca")

# Display labels (capitalised, fixed-width for alignment).
_TOOL_LABELS = {
    "semgrep":    "Semgrep   ",
    "coccinelle": "Coccinelle",
    "codeql":     "CodeQL    ",
    "sca":        "SCA       ",
}


def _load_coverage_record(out_dir: Path, tool: str) -> dict | None:
    """Read ``coverage-<tool>.json`` from ``out_dir``. Best-effort —
    missing file / malformed JSON returns ``None`` (tool didn't run
    or its coverage emit failed; both fold to ''no record to render''
    in the caller's loop)."""
    p = out_dir / f"coverage-{tool}.json"
    data = load_json(p, max_bytes=_MAX_RECORD_BYTES)
    return data if isinstance(data, dict) else None


def _findings_for_tool(metrics: dict, tool: str) -> int:
    """Count findings attributable to ``tool``.

    Prefers the authoritative ``findings_by_tool`` dict (keyed by
    canonical tool name, populated from SARIF driver metadata).
    Falls back to rule-id heuristics for old-format metrics files
    that lack ``findings_by_tool``.
    """
    by_tool = metrics.get("findings_by_tool")
    if isinstance(by_tool, dict):
        v = by_tool.get(tool)
        return v if type(v) is int and v >= 0 else 0

    findings_by_rule = metrics.get("findings_by_rule") or {}
    total = 0
    if not isinstance(findings_by_rule, dict):
        return 0
    for rule_id, count in findings_by_rule.items():
        if not isinstance(rule_id, str) or type(count) is not int or count < 0:
            continue
        rule_lower = rule_id.lower()
        if tool == "semgrep":
            if (rule_lower.startswith(("engine.semgrep.", "c.lang.", "python.lang.")) or "semgrep" in rule_lower):
                total += count
        elif tool == "codeql":
            head = rule_id.split("/", 1)[0] if "/" in rule_id else ""
            if head in {"cpp", "c", "py", "python", "js", "java",
                        "javascript", "ts", "typescript", "go",
                        "rb", "ruby", "cs", "csharp"}:
                total += count
        elif tool == "coccinelle" and "/" not in rule_id and "." not in rule_id:
            total += count
    return total


_EXECUTION_FAILURE_FIELDS = (
    "semgrep_failed_packs", "dropped_registry_packs", "sarif_merge_failed",
    "analysis_gaps", "semgrep_dropped_files", "codeql_no_output",
    "tool_execution_failures", "tool_coverage_limitations", "sarif_input_errors",
    "semgrep_metadata_errors", "semgrep_partial_files", "semgrep_skipped_rules",
)


def scan_execution_status(metrics: dict) -> str:
    """Summarise known execution failures, without claiming complete coverage.

    Legacy metrics lack an explicit status; their recorded failures still
    prevent a success indicator. Unknown coverage is not a safety verdict.
    """
    recorded = metrics.get("execution_status")
    if recorded == "error":
        return "error"
    if "execution_status" in metrics and recorded not in ("ok", "partial"):
        return "partial"
    if recorded == "partial" or any(metrics.get(key) for key in _EXECUTION_FAILURE_FIELDS):
        return "partial"
    return "ok"


def render_scan_execution(metrics: dict) -> str | None:
    """Render saved execution status, including failures without coverage files."""
    status = scan_execution_status(metrics)
    if status == "ok" and "execution_status" not in metrics:
        return None
    details = []
    for key, label in (("tool_execution_failures", "failed tool invocation(s)"),
                       ("tool_coverage_limitations", "coverage limitation(s)")):
        counts = metrics.get(key)
        if isinstance(counts, dict):
            total = sum(value for value in counts.values() if type(value) is int and value > 0)
            if total:
                details.append(f"{total} {label}")
    input_errors = metrics.get("sarif_input_errors")
    if type(input_errors) is int and input_errors > 0:
        details.append(f"{input_errors} report issue(s)")
    suffix = f" ({'; '.join(details)})" if details else ""
    return f"Scan execution: {status}{suffix}"


def summarize_tool_coverage(record: dict) -> dict:
    """Keep only counts needed for a saved, invocation-local tool summary."""
    summary = {}
    rules = record.get("rules_applied")
    if isinstance(rules, list):
        summary["rules_applied"] = len({rule for rule in rules if isinstance(rule, str) and rule})
    elif type(rules) is int and rules >= 0:
        summary["rules_applied"] = rules
    issues = record.get("files_failed")
    if isinstance(issues, list):
        summary["paths_with_issues"] = len({row["path"] for row in issues
            if isinstance(row, dict) and isinstance(row.get("path"), str) and row["path"]})
    else:
        count = record.get("paths_with_issues")
        if type(count) is int and count >= 0:
            summary["paths_with_issues"] = count
    return summary


def render_scan_coverage(out_dir: Path) -> str | None:
    """Render the operator-facing tool-execution coverage block for
    a /scan run. Saved execution failures remain visible even when no
    per-tool coverage files exist. Returns ``None`` when neither tool
    coverage nor an execution summary is available.

    Output shape (aligned, one line per tool that ran)::

        Coverage: Semgrep    47 findings  (3 rule group(s); 0 failed)
                  Coccinelle  0 findings  (3 rule group(s))
                  CodeQL      skipped (autoreconf missing)

    The first line carries the ``Coverage:`` label; subsequent lines
    indent to align under the tool-name column for readability.
    """
    # scan_metrics.json gives per-tool finding counts via the
    # findings_by_rule namespace split. Best-effort: missing /
    # malformed metrics falls back to ''— findings'' on each line.
    metrics: dict = {}
    metrics_path = out_dir / "scan_metrics.json"
    loaded_metrics = load_json(metrics_path, max_bytes=_MAX_RECORD_BYTES)
    if isinstance(loaded_metrics, dict):
        metrics = loaded_metrics

    rendered_lines: list[str] = []
    for tool in _TOOL_ORDER:
        # A present snapshot is authoritative, including an empty or damaged
        # one. Never resurrect earlier per-tool files for a modern scan.
        if "tool_coverage" in metrics:
            snapshot = metrics["tool_coverage"]
            rec = snapshot.get(tool) if isinstance(snapshot, dict) else None
        else:
            rec = _load_coverage_record(out_dir, tool)
        if not isinstance(rec, dict):
            continue
        label = _TOOL_LABELS[tool]
        finds = _findings_for_tool(metrics, tool)
        summary = summarize_tool_coverage(rec)
        rule_count = summary.get("rules_applied")

        # Pack-level failures supplement the per-path diagnostics below.
        failed_packs: list = []
        if tool == "semgrep":
            value = metrics.get("semgrep_failed_packs")
            if isinstance(value, list):
                failed_packs = list(dict.fromkeys(pack for pack in value if isinstance(pack, str) and pack))

        detail_parts: list[str] = []
        affected = summary.get("paths_with_issues", 0)
        if affected:
            detail_parts.append(f"{affected} path(s) with tool warnings or errors")
        if rule_count is not None:
            detail_parts.append(
                f"{rule_count} rule group{'s' if rule_count != 1 else ''}"
            )
        if failed_packs:
            detail_parts.append(
                f"⚠️  {len(failed_packs)} pack(s) failed: "
                f"{', '.join(sanitise_excerpt(pack) for pack in failed_packs[:3])}"
                + ("..." if len(failed_packs) > 3 else "")
            )
        detail = (
            f"  ({'; '.join(detail_parts)})" if detail_parts else ""
        )
        finds_part = f"{finds:>3} finding{'s' if finds != 1 else ''}"
        rendered_lines.append(f"{label} {finds_part}{detail}")

    execution = render_scan_execution(metrics)
    if not rendered_lines:
        return execution

    # First line gets the ``Coverage:`` label; remaining lines
    # indent to align the tool-name column.
    first, *rest = rendered_lines
    indent = " " * len("Coverage: ")
    out_lines = [f"Coverage: {first}"]
    out_lines.extend(f"{indent}{line}" for line in rest)
    if execution:
        out_lines.append(execution)
    return "\n".join(out_lines)


__all__ = [
    "render_scan_coverage",
    "render_scan_execution",
    "scan_execution_status",
]
