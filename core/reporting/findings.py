"""Findings-specific report building — Layer 2 on top of generic primitives.

Translates vulnerability findings into ReportSpec for rendering.
Used by both /validate and /agentic pipelines.

Untrusted fields — anything sourced from a finding dict, including
SARIF text from external scanners (Semgrep, CodeQL, etc.) — pass
through ``sanitise_string`` / ``sanitise_code`` before landing in
the rendered output. Markdown allows raw HTML by default, so any
unescaped ``<script>`` / ``<img onerror>`` in a finding field would
execute when the report is opened in a browser-rendered viewer
(GitHub preview, MkDocs, gitlab, etc). Single choke point: render-time.
"""

from typing import Any, Dict, List, Optional, Tuple

from core.security.prompt_output_sanitise import sanitise_code, sanitise_string
from .formatting import get_display_status, title_case_type, truncate_path
from .spec import ReportSpec, ReportSection


def _sani(value: Any, *, max_chars: int = 200) -> str:
    """Cast + sanitise an untrusted finding field for rendered output.

    Returns ``"—"`` for None / empty so table cells stay tidy. All
    SARIF-sourced strings go through here on their way into the
    report — vuln_type, cwe_id, file path, function name, status,
    severity, CVSS string, etc. Numeric callers can rely on the
    str() cast.
    """
    if value is None or value == "":
        return "—"
    return sanitise_string(str(value), max_chars=max_chars)


def build_findings_rows(findings: List[Dict[str, Any]], filename_only: bool = False) -> List[Tuple]:
    """Build table rows from findings. One shared implementation for all pipelines.

    Args:
        findings: List of finding dicts
        filename_only: If True, show only filename (for console). If False, show full path (for markdown).

    Returns list of tuples: (index, type, cwe, file_loc, status, severity, cvss)
    """
    rows = []
    for i, f in enumerate(findings, 1):
        vtype = sanitise_string(title_case_type(f.get("vuln_type", "")), max_chars=80)
        cwe = _sani(f.get("cwe_id"), max_chars=20)

        fpath = f.get("file") or f.get("file_path") or ""
        if filename_only:
            fpath = fpath.rsplit("/", 1)[-1] if "/" in fpath else fpath
        fline = f.get("line") if f.get("line") is not None else f.get("start_line")
        loc = f"{fpath}:{fline}" if fline is not None else fpath
        loc = sanitise_string(truncate_path(loc), max_chars=80) if loc else "—"

        status = sanitise_string(get_display_status(f), max_chars=40)

        severity = str(f.get("severity") or f.get("severity_assessment") or "").lower()
        if severity == "none":
            severity = "Informational"
        elif severity and len(severity) <= 15:
            severity = severity.title()
        else:
            severity = "—"
        severity = sanitise_string(severity, max_chars=20)

        cvss = f.get("cvss_score_estimate")
        cvss_str = sanitise_string(str(cvss), max_chars=10) if cvss is not None else "—"

        rows.append((str(i), vtype, cwe, loc, status, severity, cvss_str))

    return rows


FINDINGS_COLUMNS = ["#", "Type", "CWE", "File", "Status", "Severity", "CVSS"]
_FILE_COLUMN_INDEX = FINDINGS_COLUMNS.index("File")


def _markdown_rows(rows: List[Tuple]) -> List[Tuple]:
    """Wrap file paths in backticks for markdown rendering."""
    return [
        tuple(
            f"`{c}`" if j == _FILE_COLUMN_INDEX and c and c != "—" else c
            for j, c in enumerate(row)
        )
        for row in rows
    ]

_CVSS_NOTE = "CVSS scores reflect **inherent vulnerability impact** — not binary mitigations."


def build_findings_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by status category."""
    counts = {"total": len(findings), "exploitable": 0, "confirmed": 0,
              "false_positive": 0, "ruled_out": 0, "error": 0, "other": 0}
    for f in findings:
        status = get_display_status(f)
        if status == "Exploitable":
            counts["exploitable"] += 1
        elif status.startswith("Confirmed"):
            counts["confirmed"] += 1
        elif status == "False Positive":
            counts["false_positive"] += 1
        elif status == "Ruled Out":
            counts["ruled_out"] += 1
        elif status.startswith("Error"):
            counts["error"] += 1
        else:
            counts["other"] += 1
    return counts


def findings_summary_line(counts: Dict[str, int], vuln_count: Optional[int] = None) -> str:
    """Build the one-line status summary from counts."""
    parts = []
    if counts["exploitable"]:
        parts.append(f"{counts['exploitable']} Exploitable")
    if counts["confirmed"]:
        parts.append(f"{counts['confirmed']} Confirmed")
    if counts["false_positive"]:
        parts.append(f"{counts['false_positive']} False Positive")
    if counts["ruled_out"]:
        parts.append(f"{counts['ruled_out']} Ruled Out")
    if counts["error"]:
        parts.append(f"{counts['error']} Error")
    if counts.get("other"):
        parts.append(f"{counts['other']} Uncategorised")
    total = counts['total']
    if vuln_count is not None and vuln_count != total:
        label = f"{vuln_count} findings"
    else:
        label = f"{total} findings"
    if not parts:
        return f"0 out of {label} categorised."
    return f"**{', '.join(parts)}** out of {label}."


def build_finding_detail(finding: Dict[str, Any], index: int) -> ReportSection:
    """Build a per-finding detail section."""
    fid = sanitise_string(
        str(finding.get("id") or finding.get("finding_id") or f"FIND-{index:04d}"),
        max_chars=80,
    )
    vtype = sanitise_string(title_case_type(finding.get("vuln_type", "unknown")), max_chars=80)
    fpath = finding.get("file") or finding.get("file_path") or "unknown"
    fline = finding.get("line") if finding.get("line") is not None else finding.get("start_line")
    loc = f"{fpath}:{fline}" if fline is not None else fpath
    loc = sanitise_string(loc, max_chars=200)

    title = f"{fid} — {vtype} in `{loc}`"

    lines = []
    lines.append("| Attribute | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Type | {vtype} |")

    func = finding.get("function")
    if func:
        lines.append(f"| Function | `{sanitise_string(str(func), max_chars=120)}` |")

    code = finding.get("proof", {}).get("vulnerable_code") if isinstance(finding.get("proof"), dict) else None
    code = code or finding.get("code") or ""
    if code:
        code_line = code.strip().split("\n")[0][:100]
        code_line = sanitise_string(code_line, max_chars=120).replace("|", "\\|")
        lines.append(f"| Code | `{code_line}` |")

    lines.append(f"| Final Status | {sanitise_string(get_display_status(finding), max_chars=40)} |")

    cwe = finding.get("cwe_id")
    if cwe:
        lines.append(f"| CWE | {sanitise_string(str(cwe), max_chars=20)} |")

    cvss = finding.get("cvss_score_estimate")
    cvss_vec = finding.get("cvss_vector")
    if cvss is not None:
        cvss_str = sanitise_string(str(cvss), max_chars=10)
        if cvss_vec:
            cvss_str += f" (`{sanitise_string(str(cvss_vec), max_chars=80)}`)"
        lines.append(f"| CVSS | {cvss_str} |")

    confidence = finding.get("confidence")
    if confidence:
        lines.append(f"| Confidence | {sanitise_string(str(confidence).title(), max_chars=40)} |")

    lines.append("")

    # Reasoning / analysis (from agentic or validate)
    reasoning = finding.get("reasoning") or finding.get("analysis")
    if reasoning:
        lines.append(f"\n**Analysis:**\n{sanitise_string(str(reasoning).strip(), max_chars=3000)}")

    # Attack scenario
    attack = finding.get("attack_scenario")
    if attack:
        lines.append(f"\n**Attack Scenario:**\n{sanitise_string(str(attack).strip(), max_chars=2000)}")

    # Remediation
    remediation = finding.get("remediation")
    patch_code = finding.get("patch_code")
    if remediation:
        lines.append(f"\n**Remediation:**\n{sanitise_string(str(remediation).strip(), max_chars=2000)}")
    if patch_code:
        lines.append(f"\n**Patch:**\n```\n{sanitise_code(str(patch_code).strip())}\n```")

    # Key findings from feasibility
    feasibility = finding.get("feasibility", {})
    if isinstance(feasibility, dict):
        if feasibility.get("verdict"):
            lines.append(f"\n**Feasibility:** {sanitise_string(str(feasibility['verdict']), max_chars=200)}")
        if feasibility.get("chain_breaks"):
            breaks = [sanitise_string(str(b), max_chars=200) for b in feasibility['chain_breaks'][:3]]
            lines.append(f"**Blockers:** {', '.join(breaks)}")

    # Dataflow
    dataflow = finding.get("dataflow_summary")
    if dataflow:
        lines.append(f"\n**Dataflow:** `{sanitise_string(str(dataflow), max_chars=500)}`")

    return ReportSection(title=title, content="\n".join(lines))


def build_findings_spec(
    findings: List[Dict[str, Any]],
    title: str = "Security Report",
    metadata: Dict[str, str] = None,
    extra_summary: Dict[str, Any] = None,
    warnings: List[str] = None,
    extra_sections: List[ReportSection] = None,
    output_files: List[str] = None,
    include_details: bool = True,
) -> ReportSpec:
    """Build a ReportSpec from findings data.

    This is the main entry point for both pipelines. Domain knowledge
    (what columns, how to count, what note to show) lives here.
    Pipeline-specific data goes in metadata, extra_summary, extra_sections.
    """
    rows = _markdown_rows(build_findings_rows(findings))
    counts = build_findings_summary(findings)

    # Build summary metrics — extra_summary first (caller controls order),
    # then append verdict counts
    summary = {}
    if extra_summary:
        summary.update(extra_summary)
    if counts["exploitable"]:
        summary["Exploitable"] = counts["exploitable"]
    if counts["confirmed"]:
        summary["Confirmed"] = counts["confirmed"]
    if counts["false_positive"]:
        summary["False Positive"] = counts["false_positive"]
    if counts["ruled_out"]:
        summary["Ruled Out"] = counts["ruled_out"]

    # Flag uncategorised findings — indicates pipeline bug
    all_warnings = list(warnings or [])
    if counts["other"]:
        all_warnings.append(f"{counts['other']} finding(s) have no final verdict — possible pipeline bug")

    # Build detail sections
    details = []
    if include_details:
        for i, f in enumerate(findings, 1):
            details.append(build_finding_detail(f, i))

    return ReportSpec(
        title=title,
        metadata=metadata or {},
        summary=summary,
        table_columns=FINDINGS_COLUMNS,
        table_rows=rows,
        table_note=_CVSS_NOTE,
        warnings=all_warnings,
        detail_title="Findings",
        detail_sections=details,
        sections=extra_sections or [],
        output_files=output_files or [],
    )


def findings_summary(findings: List[Dict[str, Any]]) -> str:
    """Generate the 'Results at a Glance' text: table + status line.

    Takes data directly — no file I/O.
    """
    rows = _markdown_rows(build_findings_rows(findings))
    counts = build_findings_summary(findings)

    try:
        from core.project.findings_utils import count_vulns
        vuln_count = count_vulns(findings)
    except Exception:
        vuln_count = None

    lines = []
    lines.append("| " + " | ".join(FINDINGS_COLUMNS) + " |")
    lines.append("|" + "|".join("---" for _ in FINDINGS_COLUMNS) + "|")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    lines.append("")
    lines.append(findings_summary_line(counts, vuln_count))

    return "\n".join(lines)
