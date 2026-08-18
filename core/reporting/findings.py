"""Findings-specific report building — Layer 2 on top of generic primitives.

Translates vulnerability findings into ReportSpec for rendering.
Used by both /validate and /agentic pipelines.
"""

from typing import Any

from core.security.prompt_output_sanitise import sanitise_code, sanitise_string

from .formatting import get_display_status, title_case_type, truncate_path
from .spec import ReportSection, ReportSpec


def build_findings_rows(findings: list[dict[str, Any]], filename_only: bool = False) -> list[tuple]:
    """Build table rows from findings. One shared implementation for all pipelines.

    Args:
        findings: List of finding dicts
        filename_only: If True, show only filename (for console). If False, show full path (for markdown).

    Returns list of tuples: (index, type, cwe, file_loc, status, severity, cvss)
    """
    rows = []
    for i, f in enumerate(findings, 1):
        vtype = title_case_type(f.get("vuln_type", ""))
        cwe = f.get("cwe_id") or "—"

        fpath = f.get("file") or f.get("file_path") or ""
        if filename_only:
            fpath = fpath.rsplit("/", 1)[-1] if "/" in fpath else fpath
        fline = f.get("line") if f.get("line") is not None else f.get("start_line")
        loc = f"{fpath}:{fline}" if fline is not None else fpath
        loc = truncate_path(loc) if loc else "—"

        status = get_display_status(f)

        severity = str(f.get("severity") or f.get("severity_assessment") or "").lower()
        if severity == "none":
            severity = "Informational"
        elif severity and len(severity) <= 15:
            severity = severity.title()
        else:
            severity = "—"

        cvss = f.get("cvss_score_estimate")
        cvss_str = str(cvss) if cvss is not None else "—"

        rows.append((str(i), vtype, cwe, loc, status, severity, cvss_str))

    return rows


FINDINGS_COLUMNS = ["#", "Type", "CWE", "File", "Status", "Severity", "CVSS"]
_FILE_COLUMN_INDEX = FINDINGS_COLUMNS.index("File")


def _markdown_rows(rows: list[tuple]) -> list[tuple]:
    """Escape cells and wrap file paths in backticks for markdown rendering.

    `build_findings_rows` output is shared with the console renderer
    (which does its own `escape_nonprintable` pass and must not show
    literal ``\\|`` / ``<br>``), so the markdown-specific escaping
    lives here — every cell goes through `_md_table_cell` so a
    finding-derived value (vuln_type, cwe, file:line, status) cannot
    split table columns or open an inline-code span. Matches the
    per-finding detail table, which already escapes via
    `_md_table_cell`.
    """
    return [
        tuple(
            f"`{_md_table_cell(c)}`" if j == _FILE_COLUMN_INDEX and c and c != "—"
            else _md_table_cell(c)
            for j, c in enumerate(row)
        )
        for row in rows
    ]

_CVSS_NOTE = "CVSS scores reflect **inherent vulnerability impact** — not binary mitigations."


def build_findings_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by status category.

    Splits the ``Confirmed`` family into three sub-counts so the
    summary line can show the operationally distinct outcomes
    separately (an operator triaging a report needs to see
    "real and reachable in production" vs "real but mitigated by
    a runtime control" vs "real but completely blocked by mitigations"
    as separate numbers, not one collapsed `Confirmed` count):

    * ``confirmed_unrestricted`` — `"Confirmed"` (plain): real,
      reachable, no notable mitigation
    * ``confirmed_constrained`` — `"Confirmed (Constrained)"`:
      real, reachable, but a runtime control narrows the
      exploit window (e.g. ASLR + partial overwrite needed)
    * ``confirmed_blocked`` — `"Confirmed (Blocked)"`: real,
      but mitigations make the path infeasible from the
      attacker's perspective (e.g. Full RELRO + non-writable
      .got blocks the only viable hijack target)

    The ``confirmed`` umbrella key is retained as a sum across the
    three sub-counts so older consumers that read just ``confirmed``
    still see the right total.
    """
    counts = {"total": len(findings),
              "exploitable": 0,
              "confirmed": 0,
              "confirmed_unrestricted": 0,
              "confirmed_constrained": 0,
              "confirmed_blocked": 0,
              "false_positive": 0,
              "ruled_out": 0, "error": 0, "other": 0}
    for f in findings:
        status = get_display_status(f)
        if status == "Exploitable":
            counts["exploitable"] += 1
        elif status == "Confirmed (Constrained)":
            counts["confirmed_constrained"] += 1
            counts["confirmed"] += 1
        elif status == "Confirmed (Blocked)":
            counts["confirmed_blocked"] += 1
            counts["confirmed"] += 1
        elif status.startswith("Confirmed"):
            counts["confirmed_unrestricted"] += 1
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


def findings_summary_line(counts: dict[str, int], vuln_count: int | None = None) -> str:
    """Build the one-line status summary from counts."""
    parts = []
    if counts["exploitable"]:
        parts.append(f"{counts['exploitable']} Exploitable")
    # Render the three Confirmed sub-buckets independently so an
    # operator sees "5 Confirmed, 2 Confirmed (Constrained), 1
    # Confirmed (Blocked)" rather than a collapsed "8 Confirmed"
    # that hides the operational distinction. Older callers passing
    # legacy `counts` dicts without the sub-keys still render via
    # `counts.get(..., 0)` (zero falls through the truthy guards).
    if counts.get("confirmed_unrestricted"):
        parts.append(f"{counts['confirmed_unrestricted']} Confirmed")
    elif counts["confirmed"] and not (
        counts.get("confirmed_constrained") or counts.get("confirmed_blocked")
    ):
        # Legacy summary: only the umbrella key was populated.
        parts.append(f"{counts['confirmed']} Confirmed")
    if counts.get("confirmed_constrained"):
        parts.append(f"{counts['confirmed_constrained']} Confirmed (Constrained)")
    if counts.get("confirmed_blocked"):
        parts.append(f"{counts['confirmed_blocked']} Confirmed (Blocked)")
    if counts["false_positive"]:
        parts.append(f"{counts['false_positive']} False Positive")
    if counts["ruled_out"]:
        parts.append(f"{counts['ruled_out']} Ruled Out")
    if counts["error"]:
        parts.append(f"{counts['error']} Error")
    if counts.get("other"):
        parts.append(f"{counts['other']} Uncategorised")
    # Denominator clarity: when a `vuln_count` is passed AND it
    # disagrees with `counts['total']`, the two numbers represent
    # different things (`vuln_count` is the count of underlying
    # vulnerability records before per-finding rendering;
    # `counts['total']` is the count of findings actually scored).
    # Pre-fix the line read `**X Confirmed** out of Y findings.`
    # where Y was `vuln_count` — but the buckets in `parts` summed
    # to `counts['total']`, not `vuln_count`. An operator doing
    # arithmetic on the line ("X Confirmed + Z FP = Y findings?")
    # got numbers that didn't add up. Disambiguate by labelling the
    # mismatched-vuln_count case explicitly so the reader sees the
    # ratio's denominator without needing to read the source.
    total = counts['total']
    if vuln_count is not None and vuln_count != total:
        label = f"{total} scored findings (from {vuln_count} vulnerability records)"
    else:
        label = f"{total} findings"
    if not parts:
        return f"0 out of {label} categorised."
    return f"**{', '.join(parts)}** out of {label}."


def _md_table_cell(s: str) -> str:
    """Escape characters that break out of a markdown table cell.

    Pre-fix only `|` was escaped, and only at one site
    (`build_finding_detail`'s code-line). Other cells interpolated
    raw — a `vtype` containing `|` rendered as a column split,
    a `function` name with backtick injection broke `code` cell
    rendering, and any cell starting with a `-` or `+` could
    de-stabilise downstream markdown processors that try to
    re-parse the table as a list.

    Escapes:
      * `|` → `\\|` (table column separator)
      * `` ` `` → `\\` ` (inline-code fence)
      * Newlines → `<br>` (rows must be one line)

    Also strips autofetch markup (image/`<img>`/`<iframe>` tags,
    `javascript:`/`data:` links) via the shared prompt-envelope
    helper. The LLM-output sanitiser (`sanitise_string`) already
    does this; without the same strip here, a finding-derived value
    (file path, function name, scanner message) carrying `![](url)`
    rendered as a live autofetch in the report — same exfil class,
    different door. Parens/brackets are deliberately NOT escaped
    (function cells legitimately contain them); the targeted strip
    removes the markup family instead.
    """
    if s is None:
        return ""
    from core.security.prompt_envelope import _strip_autofetch_markup
    s = str(s)
    s = _strip_autofetch_markup(s)
    s = s.replace("\\", "\\\\")
    s = s.replace("|", "\\|")
    s = s.replace("`", "\\`")
    s = s.replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")
    return s


def build_finding_detail(finding: dict[str, Any], index: int) -> ReportSection:
    """Build a per-finding detail section."""
    fid = finding.get("id") or finding.get("finding_id") or f"FIND-{index:04d}"
    vtype = title_case_type(finding.get("vuln_type", "unknown"))
    fpath = finding.get("file") or finding.get("file_path") or "unknown"
    fline = finding.get("line") if finding.get("line") is not None else finding.get("start_line")
    loc = f"{fpath}:{fline}" if fline is not None else fpath

    # Section titles render as one heading line — collapse and sanitise
    # the finding-derived pieces (id, type, file:line) so a crafted value
    # cannot inject extra heading lines or live markup. Same policy as
    # core.project.report._md_heading.
    title = sanitise_string(
        " ".join(f"{fid} — {vtype} in `{loc}`".split()), max_chars=300,
    )

    lines = []
    lines.append("| Attribute | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Type | {_md_table_cell(vtype)} |")

    func = finding.get("function")
    if func:
        # SCA findings stuff the dependency name into the ``function``
        # slot (the finding shape is shared across tools, and SCA has
        # no code function to attribute against). Labelling that as
        # "Function" is operator-misleading — they see ``urllib3`` and
        # assume there's a Python function literally called urllib3.
        # Tool-aware label fixes the report without forcing every
        # producer to reshape its output.
        slot_label = "Dependency" if finding.get("tool") == "sca" else "Function"
        lines.append(f"| {slot_label} | `{_md_table_cell(func)}` |")

    code = finding.get("proof", {}).get("vulnerable_code") if isinstance(finding.get("proof"), dict) else None
    code = code or finding.get("code") or ""
    if code:
        code_line = code.strip().split("\n")[0][:100]
        lines.append(f"| Code | `{_md_table_cell(code_line)}` |")

    lines.append(f"| Final Status | {_md_table_cell(get_display_status(finding))} |")

    cwe = finding.get("cwe_id")
    if cwe:
        lines.append(f"| CWE | {_md_table_cell(cwe)} |")

    cvss = finding.get("cvss_score_estimate")
    cvss_vec = finding.get("cvss_vector")
    if cvss is not None:
        cvss_str = _md_table_cell(str(cvss))
        if cvss_vec:
            cvss_str += f" (`{_md_table_cell(cvss_vec)}`)"
        lines.append(f"| CVSS | {cvss_str} |")

    confidence = finding.get("confidence")
    if confidence is not None:
        lines.append(f"| Confidence | {_md_table_cell(str(confidence).title())} |")

    lines.append("")

    # Reasoning / analysis (from agentic or validate)
    reasoning = (
        finding.get("reasoning")
        or finding.get("candidate_reasoning")
        or finding.get("analysis")
    )
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

    # Mechanical patch-gate annotations (packages/llm_analysis/patch_gate).
    # Values come from the gate's closed vocabulary, but the dict shape is
    # finding-supplied — sanitise like every other rendered field.
    patch_gate = finding.get("patch_gate")
    if patch_code and isinstance(patch_gate, dict):
        gate_summary = ", ".join(
            f"{key}: {patch_gate[key]}"
            for key in ("format", "scope", "detector", "control", "compile")
            if patch_gate.get(key)
        )
        if gate_summary:
            if patch_gate.get("reliable") is False:
                gate_summary += " (unreliable — see patch artifact)"
            lines.append(
                f"\n**Patch gate:** {sanitise_string(gate_summary, max_chars=400)}"
            )

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
    findings: list[dict[str, Any]],
    title: str = "Security Report",
    metadata: dict[str, str] | None = None,
    extra_summary: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
    extra_sections: list[ReportSection] | None = None,
    output_files: list[str] | None = None,
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


def findings_summary(findings: list[dict[str, Any]]) -> str:
    """Generate the 'Results at a Glance' text: table + status line.

    Takes data directly — no file I/O.
    """
    rows = _markdown_rows(build_findings_rows(findings))
    counts = build_findings_summary(findings)

    try:
        from core.project.findings_utils import count_vulns
        vuln_count = count_vulns(findings)
    except Exception:  # noqa: BLE001
        vuln_count = None

    lines = []
    lines.append("| " + " | ".join(FINDINGS_COLUMNS) + " |")
    lines.append("|" + "|".join("---" for _ in FINDINGS_COLUMNS) + "|")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    lines.append("")
    lines.append(findings_summary_line(counts, vuln_count))

    return "\n".join(lines)
