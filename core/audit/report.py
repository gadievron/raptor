"""Final summary report generation for /audit runs.

Reads the review journal (per-run ``review-journal.jsonl`` and the
project-level ``review-journal-index.json``), ``findings.json``, and
annotations to produce a human-readable summary and structured
report. ``coverage-audit.json`` was removed under the annotation →
journal migration; the journal is the authoritative LLM review
store.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def generate_report(
    out_dir: Path,
    *,
    target_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Generate the final audit report.

    Returns a dict with:
        summary: human-readable summary string
        stats: {reviewed, clean, suspicious, finding, error}
        findings_count: number of tool-confirmed findings
        coverage_delta: functions reviewed this run
        gaps_remaining: number of unreviewed functions
    """
    audit_data = _load_review_state(out_dir)
    findings = _load_findings(out_dir)
    # JOIN findings with the journal for current-verdict authority.
    # findings.json is emit-only at /audit run completion; Reflexion
    # corrections land in the journal only. See amendment §4.
    #
    # Drop findings whose journal verdict is now benign
    # (clean/dormant) — those are Reflexion-refuted and shouldn't
    # count toward findings_count or appear in the summary list.
    # The retained findings carry ``_verdict_source="journal"`` when
    # the journal changed their status (e.g. finding → suspicious).
    findings = _apply_journal_verdict_overrides(findings, audit_data)
    gaps = _load_gaps(out_dir)

    stats = _compute_stats(audit_data)
    gaps_remaining = _count_remaining_gaps(gaps, audit_data)

    unrecorded = _find_unrecorded_reads(out_dir, audit_data, target_path)

    report = {
        "stats": stats,
        "findings_count": len(findings),
        "coverage_delta": stats["reviewed"],
        "gaps_remaining": gaps_remaining,
        "findings": findings,
        "unrecorded_reads": unrecorded,
    }

    eval_path = out_dir / "evaluation.json"
    if eval_path.is_file():
        try:
            eval_data = json.loads(eval_path.read_text())
            report["evaluation"] = eval_data
        except Exception as e:
            logger.warning("failed to load evaluation results from %s: %s", eval_path, e)

    report["summary"] = _format_summary(report)
    return report


def format_summary(report: Dict[str, Any]) -> str:
    """Format a report dict as a human-readable summary."""
    return report.get("summary", _format_summary(report))


def write_report(report: Dict[str, Any], out_dir: Path) -> Path:
    """Write the report to audit-report.json."""
    path = out_dir / "audit-report.json"
    serializable = {k: v for k, v in report.items() if k != "summary"}
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=out_dir, prefix=".audit-report-", suffix=".json",
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    return path


def write_markdown_report(
    report: Dict[str, Any],
    out_dir: Path,
    *,
    target_path: Optional[Path] = None,
    model: str = "",
    duration_minutes: float = 0.0,
    cost_usd: float = 0.0,
    capabilities: Optional[Dict[str, bool]] = None,
    suppressions_count: int = 0,
) -> Path:
    """Write the full audit-report.md per the /audit output contract."""
    stats = report.get("stats", {})
    findings = report.get("findings", [])

    lines = ["# Audit Report", ""]

    # Header metadata
    if target_path:
        lines.append(f"**Target:** {target_path}")
    if model:
        lines.append(f"**Model:** {model}")
    if duration_minutes > 0:
        lines.append(f"**Duration:** {duration_minutes:.0f} minutes")
    if cost_usd > 0:
        lines.append(f"**Cost:** ${cost_usd:.2f}")

    reviewed = stats.get("reviewed", 0)
    total_funcs = reviewed + report.get("gaps_remaining", 0)
    if total_funcs > 0:
        pct = reviewed * 100.0 / total_funcs
        lines.append(
            f"**Functions reviewed:** {reviewed:,} of {total_funcs:,} ({pct:.1f}%)"
        )
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    if findings:
        severity_counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "medium").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        sev_parts = [f"{count} {sev}" for sev, count in sorted(severity_counts.items())]
        lines.append(f"{len(findings)} findings: {', '.join(sev_parts)}.")
    else:
        lines.append("No findings.")
    lines.append("")

    # Capabilities used
    if capabilities:
        lines.append("## Capabilities used")
        lines.append("")
        lines.append("| Tool | Available |")
        lines.append("|---|---|")
        for tool in sorted(capabilities):
            avail = "Yes" if capabilities[tool] else "No"
            lines.append(f"| {tool} | {avail} |")
        lines.append("")

    # Findings
    if findings:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            fid = f.get("id", "FIND-???")
            title = f.get("title", "Untitled")
            tier = f.get("evidence_tier", "HEURISTIC")
            lines.append(f"### {fid}: {title} ({tier})")
            file_loc = f.get("file", "?")
            line_no = f.get("line", "?")
            depth = f.get("depth", "?")
            lines.append(
                f"**File:** {file_loc}:{line_no}  "
                f"**Depth:** {depth}  "
                f"**Evidence:** {tier}"
            )
            lines.append("")

    # Evidence distribution
    lines.append("## Evidence distribution")
    lines.append("")
    evidence_dist = _evidence_distribution(findings)
    if evidence_dist:
        lines.append("| Tier | Count |")
        lines.append("|---|---|")
        for tier, count in sorted(evidence_dist.items()):
            lines.append(f"| {tier} | {count} |")
    else:
        lines.append("No evidence recorded.")
    lines.append("")

    # Suppressions
    if suppressions_count > 0:
        lines.append("## Suppressions")
        lines.append("")
        lines.append(
            f"{suppressions_count} findings suppressed by binary oracle "
            f"(function absent from binary)."
        )
        lines.append("See suppressions.jsonl for details.")
        lines.append("")

    # Measurement evaluation
    evaluation = report.get("evaluation")
    if evaluation:
        lines.append("## Evaluation")
        lines.append("")
        lines.append(
            f"**Detection:** {evaluation.get('recall', 0):.0%} "
            f"**Precision:** {evaluation.get('precision', 0):.0%} "
            f"**F1:** {evaluation.get('f1', 0):.2f}"
        )
        per_cap = evaluation.get("per_capability", {})
        if per_cap:
            lines.append("")
            lines.append("| Evidence source | TP | FP |")
            lines.append("|---|---|---|")
            for src, counts in sorted(per_cap.items()):
                lines.append(f"| {src} | {counts.get('tp', 0)} | {counts.get('fp', 0)} |")
        per_cell = evaluation.get("per_cell", {})
        if per_cell:
            lines.append("")
            lines.append("| Depth x Failure mode | TP | FN |")
            lines.append("|---|---|---|")
            for cell_key, counts in sorted(per_cell.items()):
                lines.append(f"| {cell_key} | {counts.get('tp', 0)} | {counts.get('fn', 0)} |")
        lines.append("")

    # Unrecorded reads
    unrecorded = report.get("unrecorded_reads", [])
    if unrecorded:
        total_funcs_unrec = sum(len(u["functions"]) for u in unrecorded)
        lines.append(
            f"## Unrecorded reads ({total_funcs_unrec} functions in "
            f"{len(unrecorded)} files)"
        )
        lines.append("")
        for u in unrecorded[:10]:
            fn_list = ", ".join(u["functions"][:5])
            extra = len(u["functions"]) - 5
            suffix = f" (+{extra} more)" if extra > 0 else ""
            lines.append(f"- {u['file']}: {fn_list}{suffix}")
        lines.append("")

    content = "\n".join(lines)
    path = out_dir / "audit-report.md"
    path.write_text(content)
    return path


def _evidence_distribution(
    findings: List[Dict[str, Any]],
) -> Dict[str, int]:
    """Count findings per evidence tier."""
    dist: Dict[str, int] = {}
    for f in findings:
        tier = f.get("evidence_tier", "HEURISTIC")
        dist[tier] = dist.get(tier, 0) + 1
    return dist


def _load_review_state(out_dir: Path) -> Dict[str, Any]:
    """Load LLM review state from the review journal.

    Returns a ``coverage-audit.json``-shaped dict
    (``{"functions_analysed": [...]}``) so the downstream stats /
    remaining-gap helpers work unchanged. Each journal entry becomes
    one function record with ``file`` / ``function`` / ``status`` /
    ``hash`` fields — matches the pre-migration record schema.
    """
    try:
        from .journal import latest_entries
    except Exception:  # noqa: BLE001
        return {"functions_analysed": []}
    try:
        entries = latest_entries(out_dir)
    except Exception:  # noqa: BLE001
        return {"functions_analysed": []}
    if not entries:
        return {"functions_analysed": []}

    functions: List[Dict[str, Any]] = []
    files_examined: set = set()
    for entry in entries.values():
        functions.append({
            "file": entry.file,
            "function": entry.function,
            "status": entry.verdict,
            "hash": entry.source_hash or None,
        })
        if entry.file:
            files_examined.add(entry.file)
    return {
        "tool": "audit",
        "functions_analysed": functions,
        "files_examined": sorted(files_examined),
    }


_BENIGN_VERDICTS = frozenset({"clean", "dormant"})


def _apply_journal_verdict_overrides(
    findings: List[Dict[str, Any]],
    audit_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """JOIN semantics: findings.json is emit-only at /audit run end;
    the journal is authoritative for current verdict.

    Two behaviours:

    - **Status override**: when the journal's latest entry for a
      finding's ``(file, function)`` disagrees with the finding's
      status, the finding's ``status`` field is overwritten from the
      journal and ``_verdict_source="journal"`` is stamped for
      audit-trail visibility.
    - **Benign drop**: when the journal reports a benign verdict
      (``clean``, ``dormant``) — i.e. Reflexion refuted the finding
      after initial emission — the finding is dropped from the
      returned list entirely. Without this, ``findings_count`` +
      the report's Findings section still tally refuted issues,
      defeating the JOIN's whole purpose.

    Returns the filtered list (never mutates the input list's
    length in place).
    """
    by_key: Dict[str, str] = {}
    for func in audit_data.get("functions_analysed", []):
        f = func.get("file", "")
        fn = func.get("function", "")
        status = func.get("status")
        if f and fn and status:
            by_key[f"{f}:{fn}"] = status

    out: List[Dict[str, Any]] = []
    for finding in findings:
        key = f"{finding.get('file', '')}:{finding.get('function', '')}"
        journal_verdict = by_key.get(key)
        if journal_verdict and journal_verdict != finding.get("status"):
            finding["status"] = journal_verdict
            finding["_verdict_source"] = "journal"
        if finding.get("status") in _BENIGN_VERDICTS:
            # Reflexion refuted this finding — drop from active
            # findings so counts and summaries reflect current state.
            continue
        out.append(finding)
    return out


def _load_findings(out_dir: Path) -> List[Dict[str, Any]]:
    path = out_dir / "findings.json"
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else data.get("findings", [])


def _load_gaps(out_dir: Path) -> Dict[str, Any]:
    path = out_dir / "gaps.json"
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _compute_stats(audit_data: Dict[str, Any]) -> Dict[str, int]:
    """Count statuses across all reviewed functions."""
    counts = {"reviewed": 0, "clean": 0, "suspicious": 0, "finding": 0, "dormant": 0, "error": 0}

    if "files" in audit_data:
        for file_data in audit_data["files"].values():
            for func_data in file_data.get("functions", {}).values():
                counts["reviewed"] += 1
                status = func_data.get("status", "clean")
                if status in counts:
                    counts[status] += 1
    elif "functions_analysed" in audit_data:
        for func_data in audit_data["functions_analysed"]:
            counts["reviewed"] += 1
            status = func_data.get("status", "clean")
            if status in counts:
                counts[status] += 1

    return counts


def _count_remaining_gaps(
    gaps_data: Dict[str, Any],
    audit_data: Dict[str, Any],
) -> int:
    """Count gaps not covered by this audit run."""
    total_gaps = gaps_data.get("count", 0)
    if "files" in audit_data:
        reviewed = sum(
            len(fd.get("functions", {}))
            for fd in audit_data["files"].values()
        )
    elif "functions_analysed" in audit_data:
        reviewed = len(audit_data["functions_analysed"])
    else:
        reviewed = 0
    return max(0, total_gaps - reviewed)


def _find_unrecorded_reads(
    out_dir: Path,
    audit_data: Dict[str, Any],
    target_path: Optional[Path],
) -> List[Dict[str, Any]]:
    """Find functions in files the LLM read but didn't record.

    Cross-references the coverage plugin's .reads-manifest (files the
    Read tool touched) against coverage-audit.json (functions explicitly
    recorded via ``libexec/raptor-audit record``).  Returns a list of
    {file, functions: [name, ...]} dicts for files with unrecorded
    functions, sorted by number of unrecorded functions descending.
    """
    manifest_path = out_dir / ".reads-manifest"
    checklist_path = out_dir / "checklist.json"
    if not manifest_path.exists() or not checklist_path.exists():
        return []

    try:
        with open(manifest_path, encoding="utf-8", errors="replace") as f:
            read_paths = {line.strip() for line in f if line.strip()}
    except OSError:
        return []

    try:
        with open(checklist_path, encoding="utf-8") as f:
            checklist = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    recorded_funcs: set[str] = set()
    if "files" in audit_data:
        for file_path, file_data in audit_data["files"].items():
            for func_name in file_data.get("functions", {}):
                recorded_funcs.add(f"{file_path}:{func_name}")
    elif "functions_analysed" in audit_data:
        for entry in audit_data["functions_analysed"]:
            f = entry.get("file", "")
            fn = entry.get("function", "")
            if f and fn:
                recorded_funcs.add(f"{f}:{fn}")

    file_functions: Dict[str, List[str]] = {}
    for file_entry in checklist.get("files", []):
        rel_path = file_entry.get("path", "")
        if not rel_path:
            continue
        funcs = [
            item["name"]
            for item in file_entry.get("items", [])
            if item.get("kind") in ("function", "method") and item.get("name")
        ]
        if funcs:
            file_functions[rel_path] = funcs

    if target_path:
        target_resolved = str(Path(target_path).resolve())
    else:
        target_resolved = None

    result = []
    for abs_path in read_paths:
        rel_path = None
        if target_resolved and abs_path.startswith(target_resolved + os.sep):
            rel_path = abs_path[len(target_resolved) + 1:]
        elif target_resolved and abs_path == target_resolved:
            rel_path = abs_path[len(target_resolved):]
        if not rel_path:
            continue

        if rel_path not in file_functions:
            continue

        unrecorded = [
            fn for fn in file_functions[rel_path]
            if f"{rel_path}:{fn}" not in recorded_funcs
        ]
        if unrecorded:
            result.append({"file": rel_path, "functions": unrecorded})

    result.sort(key=lambda x: len(x["functions"]), reverse=True)
    return result


def _format_summary(report: Dict[str, Any]) -> str:
    """Format a human-readable summary."""
    stats = report.get("stats", {})
    lines = [
        "## Audit Summary",
        "",
        f"Functions reviewed: {stats.get('reviewed', 0)}",
        f"  Clean: {stats.get('clean', 0)}",
        f"  Dormant: {stats.get('dormant', 0)}",
        f"  Suspicious: {stats.get('suspicious', 0)}",
        f"  Finding: {stats.get('finding', 0)}",
        f"  Error: {stats.get('error', 0)}",
        "",
        f"Tool-confirmed findings: {report.get('findings_count', 0)}",
        f"Gaps remaining: {report.get('gaps_remaining', 0)}",
    ]

    findings = report.get("findings", [])
    if findings:
        lines.append("")
        lines.append("### Findings")
        for f in findings:
            severity = f.get("severity", "medium").title()
            lines.append(
                f"- [{severity}] {f.get('title', 'Untitled')} "
                f"({f.get('file', '?')}:{f.get('line', '?')})"
            )

    unrecorded = report.get("unrecorded_reads", [])
    if unrecorded:
        total_funcs = sum(len(u["functions"]) for u in unrecorded)
        lines.append("")
        lines.append(f"### Unrecorded reads ({total_funcs} functions in "
                     f"{len(unrecorded)} files)")
        lines.append("Files you read but have functions without a record call.")
        lines.append("Use `--related-to <primary_file>:<primary_function>` "
                     "to record ancillary reviews.")
        for u in unrecorded[:10]:
            fn_list = ", ".join(u["functions"][:5])
            extra = len(u["functions"]) - 5
            suffix = f" (+{extra} more)" if extra > 0 else ""
            lines.append(f"  {u['file']}: {fn_list}{suffix}")
        if len(unrecorded) > 10:
            lines.append(f"  ... and {len(unrecorded) - 10} more files")

    return "\n".join(lines)
