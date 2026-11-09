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
    from .reporting import render_sbom_markdown
    return render_sbom_markdown("inspect", inventory=inventory, records=records, limit=limit, offset=offset)


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
    from .reporting import render_sbom_markdown
    return render_sbom_markdown("plan", payload=report, limit=limit)


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
    from .reporting import render_sbom_markdown
    return render_sbom_markdown("verify-plan", payload=report, limit=limit)


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
