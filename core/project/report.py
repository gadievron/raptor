"""Project report — merged view across all runs."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import dumps_artifact, dumps_display, save_json
from core.security.prompt_output_sanitise import (
    sanitise_code,
    sanitise_inline,
    sanitise_string,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Iterable

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


def _finding_status(finding: dict[str, Any]) -> str:
    """Return the normalized validation status for a finding."""
    return (
        str(finding.get("final_status") or finding.get("status") or "needs_review")
        .strip()
        .lower()
    )


def _finding_bucket(finding: dict[str, Any]) -> str:
    """Map validation status to a stable findings/ subdirectory."""
    status = _finding_status(finding)
    if status in _CONFIRMED_STATUSES:
        return "confirmed"
    if status in _RULED_OUT_STATUSES:
        return "ruled-out"
    return "needs-review"


def _finding_fingerprint(finding: dict[str, Any]) -> str:
    """Return a stable short fingerprint for filenames and cross-references."""
    payload = {
        "id": finding.get("id") or finding.get("finding_id"),
        "file": finding.get("file"),
        "function": finding.get("function"),
        "line": finding.get("line") or finding.get("line_start"),
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


def _finding_title(finding: dict[str, Any]) -> str:
    for key in ("title", "name", "summary", "vuln_type", "type"):
        value = finding.get(key)
        if value:
            return str(value)
    location = finding.get("file") or finding.get("function")
    if location:
        return f"Finding in {location}"
    return "Finding"


def _finding_stem(finding: dict[str, Any], index: int) -> str:
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
        return dumps_display(value, sort_keys=True)
    return str(value)


def _md_escape_inline(value: Any) -> str:
    # Table cells are one line each; finding-derived values are
    # sanitised (markdown control chars defanged, ANSI/BIDI escaped)
    # before the pipe escape so a cell can neither split columns nor
    # render as live markup. Same policy as core.reporting.findings'
    # `_md_table_cell` — the two report surfaces agree on escaping.
    text = _format_value(value).replace("\n", " ").strip()
    text = sanitise_string(text, max_chars=2000)
    return text.replace("|", "\\|")


def _md_heading(value: Any) -> str:
    """Collapse a finding-derived string to a single sanitised heading line.

    Newlines become spaces so a multi-line title cannot inject extra
    heading/list lines below the real one; `sanitise_string` defangs
    line-leading markdown and control bytes.
    """
    text = " ".join(_format_value(value).split()).strip()
    return sanitise_string(text, max_chars=500)


def _render_detail(label: str, value: Any) -> str:
    rendered = _format_value(value).strip()
    if not rendered:
        return ""
    if "\n" in rendered or rendered.startswith(("{", "[")):
        # `sanitise_code` neutralises embedded ``` runs (zero-width
        # space after the second backtick) so a finding value cannot
        # terminate the wrapping fence early and spill live markdown
        # into the report.
        return f"## {label}\n\n```\n{sanitise_code(rendered)}\n```\n"
    return f"## {label}\n\n{sanitise_string(rendered, max_chars=10_000)}\n"


def render_finding_markdown(finding: dict[str, Any], *, index: int = 1) -> str:
    """Render one finding as a portable Markdown handoff artifact."""
    fingerprint = _finding_fingerprint(finding)
    lines: list[str] = [f"# {_md_heading(_finding_title(finding))}", ""]
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


def _severity_key(finding: dict[str, Any]) -> tuple[int, str]:
    severity = str(finding.get("severity") or "unknown").strip().lower()
    return (_SEVERITY_ORDER.get(severity, _SEVERITY_ORDER["unknown"]), severity)


def render_grouped_findings_markdown(
    findings: Iterable[dict[str, Any]],
    project_name: str,
    *,
    sca_findings: Iterable[dict[str, Any]] = (),
    readjudication: Iterable[dict[str, Any]] = (),
) -> str:
    """Render all findings into one project-level Markdown report.

    Code findings are grouped by severity. SCA / dependency findings
    (``sca_findings``) render in their own "Supply chain / dependencies
    (SCA)" section below — they're dep-level (no source file:line), so bucketing them
    separately keeps the severity-grouped code view clean. Mirrors the
    interactive ``/project findings`` view.

    ``readjudication`` — queue records from
    :mod:`core.project.readjudication` — render in their own section:
    recorded disproofs that a later independent signal contradicts.
    The section states counts and per-site pairs only; it never
    changes a finding's rendered status (re-adjudication is a
    validation-lane task).
    """
    findings = sorted(
        findings,
        key=lambda item: (*_severity_key(item), _finding_title(item).lower()),
    )
    sca_findings = sorted(
        sca_findings,
        key=lambda item: (*_severity_key(item), _finding_title(item).lower()),
    )
    readjudication = [r for r in readjudication if isinstance(r, dict)]
    lines = [f"# {project_name} findings", ""]
    if not findings and not sca_findings and not readjudication:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").strip().lower() or "unknown"
        grouped.setdefault(severity, []).append(finding)

    for severity in sorted(
        grouped,
        key=lambda item: (_SEVERITY_ORDER.get(item, _SEVERITY_ORDER["unknown"]), item),
    ):
        # severity/status are finding-derived strings: route them
        # through the same heading sanitiser as every other
        # interpolation — a "high\n# evil" severity injected a live
        # heading line pre-fix.
        lines.append(f"## {_md_heading(severity.title())}")
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
                f"- **{_md_heading(_finding_title(finding))}** "
                f"(`{_md_heading(finding_id)}`) — "
                f"{_md_heading(location)} — {_md_heading(status)}"
            )
        lines.append("")

    if sca_findings:
        lines.append("## Supply chain / dependencies (SCA)")
        lines.append("")
        for finding in sca_findings:
            finding_id = (
                finding.get("id")
                or finding.get("finding_id")
                or _finding_fingerprint(finding)
            )
            sca = finding.get("sca") or {}
            name = sca.get("name") or finding.get("function") or "unknown package"
            eco = sca.get("ecosystem", "")
            package = f"{eco}:{name}" if eco else name
            severity = str(finding.get("severity") or "unknown").strip().lower() or "unknown"
            lines.append(
                f"- **{_md_heading(_finding_title(finding))}** "
                f"(`{_md_heading(finding_id)}`) — "
                f"{_md_heading(package)} — {_md_heading(severity)}"
            )
            evidence = sca.get("evidence") or {}
            reasons = evidence.get("escalation_reasons") or []
            if isinstance(reasons, list):
                lines.extend(f"  - escalated: {_md_heading(reason)}" for reason in reasons)
        lines.append("")

    queued = [r for r in readjudication if r.get("action") == "queued"]
    if queued:
        from core.project.readjudication import (
            QUEUE_FILENAME,
            contradicted_disproof_count,
            suppressed_count,
        )
        n_disproofs = contradicted_disproof_count(queued)
        lines.append("## Re-adjudication queue")
        lines.append("")
        lines.append(
            f"{n_disproofs} recorded disproof(s) contradicted by new "
            f"signals — re-adjudication queue ({len(queued)} queued "
            f"signal(s); full records in `{QUEUE_FILENAME}`). Nothing "
            f"is auto-overturned: adjudicate with a scoped /validate "
            f"on the queued sites."
        )
        n_suppressed = suppressed_count(readjudication)
        if n_suppressed:
            # A capped queue must never read as complete — restate the
            # truncation marker wherever the count renders.
            lines.append("")
            lines.append(
                f"⚠️ {n_suppressed} further contradiction(s) not "
                f"recorded (record caps) — the listing below is a "
                f"bounded sample, not the full set."
            )
        lines.append("")
        for record in queued:
            # Every rendered value is finding-derived (LLM-authored or
            # import-restored) — same _md_heading sanitiser as the
            # finding sections above.
            site = record.get("site")
            site = site if isinstance(site, dict) else {}
            claim = record.get("new_claim")
            claim = claim if isinstance(claim, dict) else {}
            disproof = record.get("disproof")
            disproof = disproof if isinstance(disproof, dict) else {}
            location = str(site.get("file") or "?")
            if site.get("function"):
                location += f"::{site.get('function')}"
            claim_mech = ", ".join(
                str(m) for m in claim.get("mechanism") or []) or "?"
            lines.append(
                f"- **{_md_heading(location)}** — new "
                f"{_md_heading(claim_mech)} claim from "
                f"{_md_heading(claim.get('source') or '?')} vs recorded "
                f"{_md_heading(disproof.get('status') or 'disproof')} from "
                f"{_md_heading(disproof.get('source') or '?')}"
            )
            if record.get("mechanism_match") is False:
                lines.append(
                    f"  - {_md_heading(record.get('mechanism_note') or 'mechanism mismatch')}")
            reconsider = disproof.get("would_reconsider_if")
            if reconsider:
                lines.append(
                    f"  - disproof's own reconsideration condition: "
                    f"{_md_heading(reconsider)}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _clear_generated_findings_dir(findings_dir: Path) -> None:
    """Remove prior generated per-finding artifacts without following symlinks."""
    import shutil

    if findings_dir.is_symlink():
        # rmtree refuses symlinks with OSError (uncaught it crashed
        # the whole report pass); unlinking the LINK honours the
        # no-follow contract — the pointed-to tree is not ours.
        findings_dir.unlink(missing_ok=True)
        return
    try:
        shutil.rmtree(findings_dir)
    except NotADirectoryError:
        findings_dir.unlink(missing_ok=True)
    except FileNotFoundError:
        pass


def export_findings_directory(
    findings: Iterable[dict[str, Any]], output_dir: Path, *,
    project_name: str = "project",
    sca_findings: Iterable[dict[str, Any]] = (),
    readjudication: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Write grouped Markdown/JSON findings under ``output_dir/findings``.

    The directory is intended for handoff to issue trackers, disclosure notes,
    and audits. It is regenerated from merged findings each time project report
    runs, so stale findings are not retained after they disappear from inputs.

    ``sca_findings`` (dependency findings from each run's ``sca/`` subdir)
    appear in their own section of the aggregate Markdown. The per-finding
    file/JSONL artefacts below remain code-finding-only for now.
    """
    findings = list(findings)
    sca_findings = list(sca_findings)
    output_dir = Path(output_dir)
    findings_dir = output_dir / "findings"
    _clear_generated_findings_dir(findings_dir)
    findings_dir.mkdir(parents=True, exist_ok=True)

    counts = {"confirmed": 0, "needs-review": 0, "ruled-out": 0}
    manifest: dict[str, Any] = {"findings": []}
    jsonl_records = []
    aggregate_path = findings_dir / f"{_slug(project_name, fallback='project')}.md"
    aggregate_path.write_text(
        render_grouped_findings_markdown(
            findings, project_name, sca_findings=sca_findings,
            readjudication=readjudication,
        ),
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
        save_json(json_path, finding, sort_keys=True)

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

    save_json(findings_dir / "manifest.json", manifest, sort_keys=True)
    (findings_dir / "findings.jsonl").write_text(
        "".join(
            dumps_artifact(record, indent=None, sort_keys=True) + "\n"
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


def gather_project_annotations(project) -> list[dict[str, Any]]:
    """Walk every run dir's ``annotations/`` subdir plus the project's
    own top-level ``annotations/`` dir, dedup on (file, function),
    project-level wins. Returns a list of dicts with ``file``,
    ``function``, ``status``, ``source``, ``body``, ``metadata``.

    Used by the project report (counts + annotations.md section)
    and reused by ``raptor project annotations``-style consumers.
    """
    from core.annotations import iter_all_annotations

    from .findings_utils import safe_run_mtime

    roots = []
    for rd in project.get_run_dirs(sweep=False):
        ann_dir = rd / "annotations"
        if ann_dir.exists():
            # safe_run_mtime: the run dir can vanish between the
            # exists() probe and the stat (`/project clean` racing this
            # report) — a vanished dir sorts oldest instead of crashing.
            roots.append((safe_run_mtime(rd), ann_dir))
    project_ann = project.output_path / "annotations"
    if project_ann.exists():
        roots.append((float("inf"), project_ann))

    if not roots:
        return []

    roots.sort(key=lambda r: r[0])
    by_pair = {}
    for _mt, root in roots:
        for ann in iter_all_annotations(root):
            by_pair[(ann.file, ann.function)] = ann

    out = [{
            "file": ann.file,
            "function": ann.function,
            "status": ann.metadata.get("status"),
            "source": ann.metadata.get("source"),
            "body": ann.body,
            "metadata": dict(ann.metadata),
        } for ann in by_pair.values()]
    out.sort(key=lambda r: (r["file"], r["function"]))
    return out


def render_annotations_markdown(records: list[dict[str, Any]],
                                project_name: str) -> str:
    """Render the deduped project-level annotation list as markdown
    suitable for ``annotations.md`` in the report dir."""
    lines: list[str] = [f"# Annotations — {project_name}", ""]
    if not records:
        lines.append("_No annotations._")
        return "\n".join(lines) + "\n"

    # Status counts up top.
    status_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for r in records:
        s = r.get("status") or "—"
        src = r.get("source") or "—"
        status_counts[s] = status_counts.get(s, 0) + 1
        source_counts[src] = source_counts.get(src, 0) + 1

    lines.append(f"_{len(records)} unique annotation(s) "
                 f"(deduped, project-level wins)._")
    lines.append("")
    # Bucket keys are the same agent-written fields as the headings
    # below — sanitise for the same reason.
    lines.append("**By status:** " + ", ".join(
        f"{sanitise_inline(k, max_chars=32)}={v}"
        for k, v in sorted(status_counts.items())
    ))
    lines.append("")
    lines.append("**By source:** " + ", ".join(
        f"{sanitise_inline(k, max_chars=32)}={v}"
        for k, v in sorted(source_counts.items())
    ))
    lines.append("")
    lines.append("## Per-function entries")
    lines.append("")
    for r in records:
        # Header line: file:function (status, source). Annotation
        # fields are agent-written (and import-restorable) — the
        # backtick spans do not stop ANSI bytes or a backtick
        # breakout, so the values are sanitised like the bodies
        # below (sanitise_inline entity-escapes in-span backticks).
        title = (f"### `{sanitise_inline(r['file'], max_chars=200)}` :: "
                 f"`{sanitise_inline(r['function'], max_chars=120)}`")
        meta = []
        if r["status"]:
            meta.append(f"status=`{sanitise_inline(r['status'], max_chars=32)}`")
        if r["source"]:
            meta.append(f"source=`{sanitise_inline(r['source'], max_chars=32)}`")
        lines.append(title)
        if meta:
            lines.append(" · ".join(meta))
        if r["body"]:
            # Annotation bodies are free-form prose (operator- or
            # LLM-authored); sanitise so a body cannot inject live
            # headings/fences/HTML into the aggregate report.
            lines.append("")
            lines.append(sanitise_string(r["body"], max_chars=20_000))
        lines.append("")
    return "\n".join(lines) + "\n"


def generate_project_report(project) -> dict[str, Any]:
    """Generate a merged report across all runs in _report/ directory.

    Non-destructive — runs preserved.
    """
    from core.json import save_json
    from core.project.findings_utils import merge_sca_findings
    from core.project.merge import merge_findings

    report_dir = project.output_path / "_report"
    report_dir.mkdir(parents=True, exist_ok=True)

    run_dirs = project.get_run_dirs(sweep=True)
    if not run_dirs:
        return {"findings": 0, "runs": 0, "annotations": 0}

    # Merge findings — code findings + SCA dependency findings (the
    # latter discovered from each run's sca/ subdir; surfaced in their
    # own section of the report, see render_grouped_findings_markdown).
    # get_run_dirs returns NEWEST-first; both merge folds take
    # later-overrides-earlier order, so pass oldest-first or the
    # oldest run wins every tie (inverting the latest-wins contract).
    oldest_first = list(reversed(run_dirs))
    merged = merge_findings(oldest_first)
    sca_findings = merge_sca_findings(oldest_first)
    save_json(
        report_dir / "findings.json",
        {"findings": merged, "sca_findings": sca_findings},
    )

    # Re-adjudication queue: recorded disproofs a LATER run's signal
    # contradicts. The merge fold above (correctly) let the disproof
    # win the merged view; the queue preserves the contradiction as an
    # additive artifact + report section — never a verdict change.
    # Best-effort: the report must not fail on the additive trail.
    readj_records: list[dict[str, Any]] = []
    try:
        from core.project.readjudication import (
            detect_project_contradictions,
            queued_count,
            write_queue,
        )
        readj_records = detect_project_contradictions(oldest_first)
        write_queue(report_dir, readj_records)
        readjudication_queued = queued_count(readj_records)
    except Exception:  # noqa: BLE001 — additive trail, never report-fatal
        logger.warning("re-adjudication detection failed", exc_info=True)
        readjudication_queued = 0

    findings_export = export_findings_directory(
        merged,
        project.output_path,
        project_name=project.name,
        sca_findings=sca_findings,
        readjudication=readj_records,
    )

    # Aggregate annotations across runs + project-level overrides.
    annotations = gather_project_annotations(project)
    save_json(report_dir / "annotations.json", {"annotations": annotations})
    annotations_md = render_annotations_markdown(annotations, project.name)
    annotations_md_path = report_dir / "annotations.md"
    annotations_md_path.write_text(annotations_md, encoding="utf-8")

    # Per-run provenance — what produced each run (framework SHA + dirty flag,
    # environment, engines, models that fired, reproducibility). Honest about
    # runs with no/unavailable manifest rather than inventing current state.
    from core.run.metadata import load_run_metadata
    from core.run.provenance import format_manifest_block
    prov_lines = [f"# Provenance — {project.name}", ""]
    for d in run_dirs:
        raw_meta = load_run_metadata(d)
        meta = raw_meta if isinstance(raw_meta, dict) else {}
        # timestamp is child-writable like `command`, and a run-dir
        # name is operator/child-chosen on --out runs — both land in
        # markdown an LLM pass later reads, so heading-sanitise them
        # (newlines collapsed: a crafted name cannot mint extra
        # headings below the real one).
        ts = _md_heading(str(meta.get("timestamp") or "")[:19])
        prov_lines.append(f"## {_md_heading(d.name)}")
        # `command` is child-writable run metadata restored verbatim by
        # /project import — defang before it lands in provenance.md.
        prov_lines.append(
            f"{sanitise_string(str(meta.get('command', '?')), max_chars=200)}"
            f" · {ts}")
        block = format_manifest_block(meta.get("manifest"), indent="- ")
        prov_lines.append(block or "- (no provenance manifest)")
        prov_lines.append("")
    provenance_md_path = report_dir / "provenance.md"
    provenance_md_path.write_text("\n".join(prov_lines), encoding="utf-8")

    return {
        "findings": len(merged),
        "sca_findings": len(sca_findings),
        "readjudication_queued": readjudication_queued,
        "runs": len(run_dirs),
        "annotations": len(annotations),
        "report_dir": str(report_dir),
        "findings_dir": findings_export["findings_dir"],
        "aggregate_markdown": findings_export["aggregate_markdown"],
        "finding_buckets": findings_export["counts"],
        "annotations_markdown": str(annotations_md_path),
        "provenance_markdown": str(provenance_md_path),
    }
