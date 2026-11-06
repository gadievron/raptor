"""Text/CSV presentation and original-byte notice export; no HTML dependency."""
from __future__ import annotations

import csv
from dataclasses import replace
import hashlib
import io
from pathlib import Path
import tempfile

from core.atomic_fs import write_bytes_atomically, write_text_atomically
from core.json import save_json
from core.security.capped_read import path_may_exist
from core.security.markdown_render import md_inline
from core.security.log_sanitisation import escape_nonprintable


def csv_inventory(records):
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(("id", "scope", "name", "version", "kind", "purl", "declarations", "notice_status", "notice_sha256"))
    for row in records:
        values = (row.id, row.scope, row.name, row.version, row.kind, row.purl,
                  "; ".join(row.declarations), row.notice_status, "; ".join(n.sha256 for n in row.notices))
        # Quoting CSV syntax does not prevent spreadsheet formula execution.
        values = tuple(escape_nonprintable(v) for v in values)
        writer.writerow("'" + v if v.lstrip().startswith(("=", "+", "-", "@")) or v.startswith(("\t", "\r", "\n"))
                        else v for v in values)
    return out.getvalue()


def markdown(inventory, records, *, limit=50):
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
    for row in records[:limit]:
        lines.append("| " + " | ".join(md_inline(v) for v in (row.scope, row.name, row.version,
                                                                  "; ".join(row.declarations) or "not declared", row.notice_status)) + " |")
    if len(records) > limit:
        lines.append("\nShowing " + str(limit) + " of " + str(len(records)) + " selected records; CSV/JSON contain the full selection.")
    if inventory.diagnostics:
        lines.extend(["", "## Coverage notes", ""])
        lines.extend("- " + md_inline(note, max_chars=1500) for note in inventory.diagnostics[:50])
    return "\n".join(lines) + "\n"


def inventory_document(inventory, records):
    result = inventory.to_dict()
    result["summary"] = inventory.summary()
    result["selection"] = [{"scope": p.scope, "id": p.id} for p in records]
    return result


def write_inventory(out, inventory, records):
    """Write portable audit data and views only after input validation succeeds."""
    out.mkdir(parents=True, exist_ok=True)
    save_json(out / "inventory.json", inventory_document(inventory, records), stream=True)
    write_text_atomically(out / "inventory.csv", csv_inventory(records))
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
    with tempfile.TemporaryDirectory(prefix="raptor-sca-notices-", dir=out.parent) as temporary:
        staging = Path(temporary)
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
        staging.rename(out)
    return {"notice_records": len(notices), "unique_texts": len({n.sha256 for n in notices})}
