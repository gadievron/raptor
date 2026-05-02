"""Project report — merged view across all runs."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List


_CONFIRMED_STATUSES = {
    "exploitable",
    "confirmed",
    "confirmed_unverified",
    "confirmed_constrained",
    "confirmed_blocked",
    "poc_success",
}

_RULED_OUT_STATUSES = {
    "ruled_out",
    "disproven",
    "false_positive",
    "test_code",
    "dead_code",
    "mitigated",
    "unreachable",
}


_FIELD_LABELS = (
    ("severity", "Severity"),
    ("confidence", "Confidence"),
    ("status", "Status"),
    ("final_status", "Final status"),
    ("file", "File"),
    ("function", "Function"),
    ("line", "Line"),
    ("vuln_type", "Type"),
    ("source", "Source"),
    ("tool", "Tool"),
)


_DETAIL_FIELDS = (
    ("description", "Description"),
    ("reasoning", "Reasoning"),
    ("exploitability", "Exploitability"),
    ("exploitability_rationale", "Exploitability rationale"),
    ("evidence", "Evidence"),
    ("proof", "Proof"),
    ("poc", "PoC"),
    ("poc_path", "PoC path"),
    ("patch", "Patch"),
    ("patch_path", "Patch path"),
    ("recommendation", "Recommendation"),
)

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "moderate": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
    "unknown": 5,
}


def _finding_status(finding: Dict[str, Any]) -> str:
    """Return the normalized validation status for a finding."""
    return (
        str(finding.get("final_status") or finding.get("status") or "needs_review")
        .strip()
        .lower()
    )


def _finding_bucket(finding: Dict[str, Any]) -> str:
    """Map validation status to a stable findings/ subdirectory."""
    status = _finding_status(finding)
    if status in _CONFIRMED_STATUSES:
        return "confirmed"
    if status in _RULED_OUT_STATUSES:
        return "ruled-out"
    return "needs-review"


def _finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Return a stable short fingerprint for filenames and cross-references."""
    payload = {
        "id": finding.get("id") or finding.get("finding_id"),
        "file": finding.get("file"),
        "function": finding.get("function"),
        "line": finding.get("line"),
        "type": finding.get("vuln_type") or finding.get("type"),
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:12]


def _slug(value: Any, *, fallback: str = "finding") -> str:
    """Return a filesystem-friendly slug with no path separators."""
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    text = text.strip(".-_")
    return text[:80] or fallback


def _finding_title(finding: Dict[str, Any]) -> str:
    for key in ("title", "name", "summary", "vuln_type", "type"):
        value = finding.get(key)
        if value:
            return str(value)
    location = finding.get("file") or finding.get("function")
    if location:
        return f"Finding in {location}"
    return "Finding"


def _finding_stem(finding: Dict[str, Any], index: int) -> str:
    finding_id = finding.get("id") or finding.get("finding_id") or f"finding-{index:03d}"
    title = _finding_title(finding)
    return (
        f"{_slug(finding_id, fallback=f'finding-{index:03d}')}-"
        f"{_slug(title)}-{_finding_fingerprint(finding)}"
    )


def _format_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    return str(value)


def _md_escape_inline(value: Any) -> str:
    text = _format_value(value).replace("\n", " ").strip()
    return text.replace("|", "\\|")


def _render_detail(label: str, value: Any) -> str:
    rendered = _format_value(value).strip()
    if not rendered:
        return ""
    if "\n" in rendered or rendered.startswith(("{", "[")):
        return f"## {label}\n\n```\n{rendered}\n```\n"
    return f"## {label}\n\n{rendered}\n"


def render_finding_markdown(finding: Dict[str, Any], *, index: int = 1) -> str:
    """Render one finding as a portable Markdown handoff artifact."""
    fingerprint = _finding_fingerprint(finding)
    lines: List[str] = [f"# {_finding_title(finding)}", ""]
    lines.append(f"Stable fingerprint: `{fingerprint}`")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    finding_id = finding.get("id") or finding.get("finding_id") or f"finding-{index:03d}"
    lines.append(f"| ID | {_md_escape_inline(finding_id)} |")
    for key, label in _FIELD_LABELS:
        value = finding.get(key)
        if value not in (None, "", [], {}):
            lines.append(f"| {label} | {_md_escape_inline(value)} |")
    lines.append("")

    for key, label in _DETAIL_FIELDS:
        detail = _render_detail(label, finding.get(key))
        if detail:
            lines.append(detail.rstrip())
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _severity_key(finding: Dict[str, Any]) -> tuple[int, str]:
    severity = str(finding.get("severity") or "unknown").strip().lower()
    return (_SEVERITY_ORDER.get(severity, _SEVERITY_ORDER["unknown"]), severity)


def render_grouped_findings_markdown(findings: Iterable[Dict[str, Any]], project_name: str) -> str:
    """Render all findings into one project-level Markdown report."""
    findings = sorted(
        list(findings),
        key=lambda item: (*_severity_key(item), _finding_title(item).lower()),
    )
    lines = [f"# {project_name} findings", ""]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").strip().lower() or "unknown"
        grouped.setdefault(severity, []).append(finding)

    for severity in sorted(
        grouped,
        key=lambda item: (_SEVERITY_ORDER.get(item, _SEVERITY_ORDER["unknown"]), item),
    ):
        lines.append(f"## {severity.title()}")
        lines.append("")
        for finding in grouped[severity]:
            finding_id = (
                finding.get("id")
                or finding.get("finding_id")
                or _finding_fingerprint(finding)
            )
            location = finding.get("file") or finding.get("function") or "unknown location"
            status = _finding_status(finding).replace("_", "-")
            lines.append(
                f"- **{_finding_title(finding)}** (`{finding_id}`) — "
                f"{location} — {status}"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _clear_generated_findings_dir(findings_dir: Path) -> None:
    """Remove prior generated per-finding artifacts without following symlinks."""
    import shutil

    if findings_dir.is_symlink() or findings_dir.is_file():
        findings_dir.unlink()
        return
    if findings_dir.is_dir():
        shutil.rmtree(findings_dir)


def export_findings_directory(
    findings: Iterable[Dict[str, Any]], output_dir: Path, *, project_name: str = "project"
) -> Dict[str, Any]:
    """Write grouped Markdown/JSON findings under ``output_dir/findings``.

    The directory is intended for handoff to issue trackers, disclosure notes,
    and audits. It is regenerated from merged findings each time project report
    runs, so stale findings are not retained after they disappear from inputs.
    """
    findings = list(findings)
    output_dir = Path(output_dir)
    findings_dir = output_dir / "findings"
    _clear_generated_findings_dir(findings_dir)
    findings_dir.mkdir(parents=True, exist_ok=True)

    counts = {"confirmed": 0, "needs-review": 0, "ruled-out": 0}
    manifest = {"findings": []}
    jsonl_records = []
    aggregate_path = findings_dir / f"{_slug(project_name, fallback='project')}.md"
    aggregate_path.write_text(
        render_grouped_findings_markdown(findings, project_name),
        encoding="utf-8",
    )

    for index, finding in enumerate(findings, start=1):
        bucket = _finding_bucket(finding)
        counts[bucket] += 1
        bucket_dir = findings_dir / bucket
        bucket_dir.mkdir(parents=True, exist_ok=True)
        stem = _finding_stem(finding, index)
        markdown_path = bucket_dir / f"{stem}.md"
        json_path = bucket_dir / f"{stem}.json"

        markdown_path.write_text(render_finding_markdown(finding, index=index), encoding="utf-8")
        json_path.write_text(
            json.dumps(finding, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )

        record = {
            "id": finding.get("id") or finding.get("finding_id") or f"finding-{index:03d}",
            "title": _finding_title(finding),
            "status": _finding_status(finding),
            "bucket": bucket,
            "fingerprint": _finding_fingerprint(finding),
            "markdown": str(markdown_path.relative_to(output_dir)),
            "json": str(json_path.relative_to(output_dir)),
        }
        manifest["findings"].append(record)
        jsonl_records.append({**record, "finding": finding})

    (findings_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    (findings_dir / "findings.jsonl").write_text(
        "".join(
            json.dumps(record, sort_keys=True, ensure_ascii=False, default=str) + "\n"
            for record in jsonl_records
        ),
        encoding="utf-8",
    )
    return {
        "findings_dir": str(findings_dir),
        "aggregate_markdown": str(aggregate_path),
        "counts": counts,
        "files": len(jsonl_records) * 2 + 3,
    }


def generate_project_report(project) -> Dict[str, Any]:
    """Generate a merged report across all runs in _report/ directory.

    Non-destructive — runs preserved.
    """
    from core.project.merge import merge_findings
    from core.json import save_json

    report_dir = project.output_path / "_report"
    report_dir.mkdir(parents=True, exist_ok=True)

    run_dirs = project.get_run_dirs(sweep=True)
    if not run_dirs:
        return {"findings": 0, "runs": 0}

    # Merge findings
    merged = merge_findings(run_dirs)
    save_json(report_dir / "findings.json", {"findings": merged})
    findings_export = export_findings_directory(
        merged,
        project.output_path,
        project_name=project.name,
    )

    return {
        "findings": len(merged),
        "runs": len(run_dirs),
        "report_dir": str(report_dir),
        "findings_dir": findings_export["findings_dir"],
        "aggregate_markdown": findings_export["aggregate_markdown"],
        "finding_buckets": findings_export["counts"],
    }
