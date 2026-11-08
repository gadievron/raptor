"""Text/CSV presentation and original-byte notice export; no HTML dependency."""
from __future__ import annotations

import csv
from dataclasses import replace
import hashlib
import io
from pathlib import Path

from core.atomic_fs import write_bytes_atomically, write_text_atomically, publish_new_directory
from core.run.scratch import scratch_dir
from core.json import save_json
from core.security.capped_read import path_may_exist
from core.security.markdown_render import md_inline
from core.security.log_sanitisation import escape_nonprintable


def csv_chunks(records):
    """Yield bounded rows; spreadsheet formula protection applies to every cell."""
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(("id", "scope", "name", "version", "kind", "purl", "declarations", "notice_status", "notice_sha256"))
    yield out.getvalue()
    for row in records:
        out.seek(0)
        out.truncate()
        values = (row.id, row.scope, row.name, row.version, row.kind, row.purl,
                  "; ".join(row.declarations), row.notice_status, "; ".join(n.sha256 for n in row.notices))
        values = tuple(escape_nonprintable(v) for v in values)
        writer.writerow("'" + v if v.lstrip().startswith(("=", "+", "-", "@")) or v.startswith(("\t", "\r", "\n"))
                        else v for v in values)
        yield out.getvalue()


def csv_inventory(records):
    """Compatibility string renderer; CLI and file exports use csv_chunks."""
    return "".join(csv_chunks(records))


def record_chunks(inventory, records, *, jsonl=False):
    """Selected records only: an explicit export, never a full audit snapshot."""
    import json
    from dataclasses import asdict
    if not jsonl:
        yield '{"format":"raptor-sbom-selected-records","schema_version":1,"source_sha256":' + json.dumps(inventory.source_sha256) + ',"selection_only":true,"records":['
    for index, row in enumerate(records):
        value = asdict(row)
        if jsonl:
            value = {"format": "raptor-sbom-selected-record", "schema_version": 1,
                     "source_sha256": inventory.source_sha256, "selection_only": True, "record": value}
        elif index:
            yield ','
        yield json.dumps(value, ensure_ascii=True, allow_nan=False)
        if jsonl:
            yield '\n'
    if not jsonl:
        yield ']}\n'


def markdown(inventory, records, *, limit=50, offset=0):
    lines = ["# SBOM inventory and evidence", "", "Source: " + md_inline(inventory.source_format),
             "Subject: " + md_inline(inventory.subject or "not declared"), "", "| Check | Count |", "|---|---:|"]
    for key, value in inventory.summary().items():
        lines.append("| " + md_inline("package declarations unresolved" if key == "unresolved_declarations" else key.replace("_", " ")) + " | " + md_inline("not assessed" if value is None else value) + " |")
    lines.extend(["", "Counts describe the supplied package/source/subject records and file totals; the table below contains the selection.",
                  "Source candidates are not confirmed installed components. Notice text is not legal review."])
    if inventory.coverage:
        metrics = inventory.coverage.get("metrics") or {}
        count = metrics.get("unidentified_executables")
        lines.append("Executable ownership checks outstanding: " + md_inline("not assessed" if count is None else count) + ".")
        lines.append("Source/build assessments with warnings: " + md_inline(metrics.get("source_gap_packages", "not assessed")) + ".")
    lines.extend(["", "## Selected inventory", "", "| Scope | Package | Version | Licence declarations | Notice evidence |",
                  "|---|---|---|---|---|"])
    for row in records[offset:offset + limit]:
        lines.append("| " + " | ".join(md_inline(v) for v in (row.scope, row.name, row.version,
                                                                  "; ".join(row.declarations) or "not declared", row.notice_status)) + " |")
    if len(records) > limit or offset:
        lines.append("\nShowing rows " + str(min(offset + 1, len(records))) + "–" + str(min(offset + limit, len(records))) + " of " + str(len(records)) + " selected records; CSV/JSONL and selected-record JSON contain the full selection. Inventory JSON retains all records plus selection references.")
    if inventory.diagnostics:
        lines.extend(["", "## Coverage notes", ""])
        lines.extend("- " + md_inline(note, max_chars=1500) for note in inventory.diagnostics[:50])
    return "\n".join(lines) + "\n"


def inventory_document(inventory, records):
    result = inventory.to_dict()
    result["summary"] = inventory.summary()
    result["selection"] = [{"scope": p.scope, "id": p.id} for p in records]
    return result


def inventory_chunks(inventory, records):
    """Stream the full portable snapshot with one copied record at a time."""
    from dataclasses import asdict, fields
    from core.json import dumps_artifact

    def array(values):
        yield '['
        for index, value in enumerate(values):
            if index:
                yield ','
            yield dumps_artifact(value, indent=None, ensure_ascii=True)
        yield ']'

    yield '{'
    for index, field in enumerate(fields(inventory)):
        if index:
            yield ','
        yield dumps_artifact(field.name, ensure_ascii=True) + ':'
        value = getattr(inventory, field.name)
        if field.name in {"records", "notice_files"}:
            yield from array(asdict(row) for row in value)
        else:
            yield dumps_artifact(value, indent=None, ensure_ascii=True)
    yield ',"summary":' + dumps_artifact(inventory.summary(), indent=None, ensure_ascii=True)
    yield ',"selection":'
    yield from array({"scope": row.scope, "id": row.id} for row in records)
    yield '}\n'


def write_inventory(out, inventory, records):
    """Write portable audit data and views only after input validation succeeds."""
    out.mkdir(parents=True, exist_ok=True)
    write_bytes_atomically(out / "inventory.json", (part.encode("utf-8") for part in inventory_chunks(inventory, records)))
    write_bytes_atomically(out / "inventory.csv", (part.encode("utf-8") for part in csv_chunks(records)))
    write_text_atomically(out / "summary.md", markdown(inventory, records))


def export_notices(out, inventory, records, source, embedded, *, include_unassociated):
    """Atomically publish a new notice directory; never use foreign paths as output paths."""
    out = Path(out)
    if path_may_exist(out):
        raise ValueError("notice output already exists; choose a new directory")
    refs = [notice for row in records for notice in row.notices]
    if include_unassociated:
        refs += inventory.notice_files
    notices = list({(n.sha256, n.path, n.origin, n.layer_id): n for n in refs}.values())
    selected_inventory = replace(inventory, records=records, notice_files=notices, coverage=None,
                                 diagnostics=inventory.diagnostics + ["Notice export contains the selected records and retained texts only; it is not a new scan."])
    out.parent.mkdir(parents=True, exist_ok=True)
    with scratch_dir("raptor-sca-notices-", dir=out.parent, keepalive=True) as workspace:
        staging = workspace / "bundle"
        staging.mkdir()
        blobs = staging / "prepared/notices/sha256"
        blobs.mkdir(parents=True)
        for sha in dict.fromkeys(n.sha256 for n in notices):
            raw = embedded[sha] if sha in embedded else source.blob(sha)
            if hashlib.sha256(raw).hexdigest() != sha:
                raise ValueError("notice bytes disagree with their fingerprint")
            write_bytes_atomically(blobs / sha, raw)
        save_json(staging / "notice-index.json", {"format": "raptor-sbom-notice-bundle", "schema_version": 1,
                                                "inventory": selected_inventory.to_dict()}, stream=True)
        write_text_atomically(staging / "README.md", "# Collected licence and notice texts\n\n"
                              "Original bytes are stored under `prepared/notices/sha256/`, named by SHA-256.\n"
                              "`notice-index.json` retains original paths, origins, package associations and selection scope.\n"
                              "Use `raptor-sca sbom inspect` on this directory to inspect it.\n"
                              "Standard reference texts and distributor notices remain distinct from upstream notices.\n")
        # A private staging directory prevents partially written exports from
        # looking complete when a late blob is corrupt or missing.
        publish_new_directory(staging, out)
    return {"notice_records": len(notices), "unique_texts": len({n.sha256 for n in notices})}


def upgrade_plan_markdown(report, *, limit=50):
    """Present proposals and unavailable evidence without asserting build safety."""
    lines = ["# SBOM upgrade plan", "", "Mode: " + md_inline(report["mode"]), "",
             "Proposals require review. A missing finding is not proof of complete advisory coverage.", "",
             "| Check | Count |", "|---|---:|"]
    for key, value in report["summary"].items():
        lines.append("| " + md_inline(key.replace("_", " ")) + " | " + md_inline(value) + " |")
    rows = [row for row in report["packages"] if row["advisories"] or row["gaps"]]
    shown = rows if limit is None else rows[:limit]
    lines.extend(["", "| Package | Installed | Proposed | Target scope | Status |", "|---|---|---|---|---|"])
    for row in shown:
        lines.append("| " + " | ".join(md_inline(value) for value in (
            row["name"], row["installed_version"], row["proposed_version"] or "unavailable",
            row["target_scope"], row["status"])) + " |")
    for row in shown:
        lines.extend(["", "## " + md_inline(row["name"]) + " " + md_inline(row["installed_version"]), ""])
        lines.extend("- " + md_inline(gap) for gap in row["gaps"])
        for candidate in row["candidates"]:
            checked = candidate["status"] not in {"not_checked", "lookup_unavailable"}
            empty = "none recorded" if checked else "not assessed"
            lines.append("- " + md_inline(candidate["version"]) + ": " + md_inline(candidate["status"]) +
                         "; resolved: " + md_inline(", ".join(candidate["resolved"]) or empty) +
                         "; remaining: " + md_inline(", ".join(candidate["remaining"]) or empty) +
                         "; introduced: " + md_inline(", ".join(candidate["introduced"]) or empty))
            lines.extend("  - " + md_inline(gap) for gap in candidate["gaps"])
    if len(shown) < len(rows):
        lines.extend(["", "Showing " + str(len(shown)) + " of " + str(len(rows)) + " actionable/uncertain groups; saved JSON and Markdown contain the full plan."])
    lines.extend(["", "## Coverage gaps", ""])
    lines.extend("- " + md_inline(row["reason"]) for row in [*report["unmatched_findings"], *report["scan_gaps"]])
    lines.extend(["", "## Scope", ""])
    lines.extend("- " + md_inline(value) for value in report["limitations"])
    return "\n".join(lines) + "\n"


def write_upgrade_plan(out, report):
    """Commit both report files together into a new directory."""
    if path_may_exist(out):
        raise ValueError("plan output already exists; choose a new directory")
    out.parent.mkdir(parents=True, exist_ok=True)
    with scratch_dir("raptor-sca-plan-", dir=out.parent, keepalive=True) as workspace:
        staging = workspace / "bundle"
        staging.mkdir()
        save_json(staging / "upgrade-plan.json", report, stream=True)
        write_text_atomically(staging / "upgrade-plan.md", upgrade_plan_markdown(report, limit=None))
        publish_new_directory(staging, out)


def verification_markdown(report, *, limit=50):
    """Render observed changes and explicitly unverified advisory absences."""
    lines = ["# SBOM upgrade verification", "", "Outcome: " + md_inline(report["status"].replace("_", " ")), "",
             "| Check | Count |", "|---|---:|"]
    for key, value in report["summary"].items():
        lines.append("| " + md_inline(key.replace("_", " ")) + " | " + md_inline(value) + " |")
    packages = [row for row in report["packages"] if limit is None or row["proposed_version"] is not None
                or row["status"] in {"not_observed", "unavailable", "ambiguous"}]
    shown = packages if limit is None else packages[:limit]
    lines.extend(["", "## Planned targets", "", "| Package | Target scope | Planned | Observed | Outcome |", "|---|---|---|---|---|"])
    for row in shown:
        actual = []
        for current in row["current"]:
            value = current["version"]
            if row["target_scope"] == "source_package":
                value += " / source " + str((current["query"] or {}).get("version") or "unavailable")
            actual.append(value)
        lines.append("| " + " | ".join(md_inline(value) for value in (
            row["name"], row["target_scope"].replace("_", " "), row["proposed_version"] or "not proposed",
            ", ".join(actual) or "not listed", row["status"].replace("_", " "))) + " |")
    for row in shown:
        lines.extend("\n" + md_inline(row["name"]) + ": " + md_inline(note) for note in row["notes"])
    if len(shown) < len(packages):
        lines.extend(["", "Additional package outcomes are retained in the saved reports."])
    if report.get("ambiguous_groups"):
        lines.extend(["", "## Ambiguous package groups", ""])
        groups = report["ambiguous_groups"] if limit is None else report["ambiguous_groups"][:limit]
        for group in groups:
            lines.append("- " + md_inline(str(group["identity"])) + ": " + str(len(group["baseline_occurrences"])) +
                         " baseline occurrences; " + str(len(group["current"])) + " current version groups (not uniquely paired).")
            current = group["current"] if limit is None else group["current"][:limit]
            lines.extend("  - " + md_inline(row["version"]) + " (" + str(len(row["occurrences"])) + " occurrences)" for row in current)
    for key, events in report["advisories"].items():
        lines.extend(["", "## " + md_inline(key.replace("_", " ").capitalize()) + " advisories", ""])
        for event in events if limit is None else events[:limit]:
            line = "- " + md_inline(event["name"]) + ": " + md_inline(event["id"])
            if event["suppressed"]:
                line += " (suppressed)"
            if event["reason"]:
                line += " — " + md_inline(event["reason"])
            lines.append(line)
        if limit is not None and len(events) > limit:
            lines.append("Additional advisory events are retained in the saved reports.")
    lines.extend(["", "## Unavailable coverage", ""])
    lines.extend("- " + md_inline(error) for error in report["coverage"]["errors"])
    gaps = [*report["coverage"]["uncovered_packages"], *report["coverage"]["current_scan_gaps"], *report["unmatched_findings"], *report["coverage"]["baseline_unmatched_findings"]]
    for row in gaps if limit is None else gaps[:limit]:
        lines.append("- " + md_inline(row.get("name") or row.get("finding_id") or "scan") + ": " + md_inline(row["reason"]))
    lines.extend(["", "## Scope", ""])
    lines.extend("- " + md_inline(value) for value in report["limitations"])
    return "\n".join(lines) + "\n"


def write_verification(out, report):
    if path_may_exist(out):
        raise ValueError("verification output already exists; choose a new directory")
    out.parent.mkdir(parents=True, exist_ok=True)
    with scratch_dir("raptor-sca-verification-", dir=out.parent, keepalive=True) as workspace:
        staging = workspace / "bundle"
        staging.mkdir()
        save_json(staging / "upgrade-verification.json", report, stream=True)
        write_text_atomically(staging / "upgrade-verification.md", verification_markdown(report, limit=None))
        publish_new_directory(staging, out)
