#!/usr/bin/env python3
"""Write inspectable, non-blocking container license and notice coverage reports."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import hashlib
import html
import json
from pathlib import Path
import re
import sys


MAX_BYTES = 64 * 1024 * 1024
LIMITATIONS = [
    "Coverage describes catalogued packages and retained notice candidates.",
    "Standard license reference copies remain distinct from upstream-authored notices.",
    "Source/build notes cover only explicitly assessed packages.",
    "Nested payload completeness, legal review and exact build-source correspondence are separate checks.",
    "Gaps and unavailable audit evidence are warnings; they do not block publication.",
]


@dataclass
class Metrics:
    packages: int
    unresolved_declarations: int
    notice_gap_packages: int
    captured_notice_files: int
    source_gap_packages: int
    source_assessed_packages: int = 0


@dataclass
class Issue:
    package_id: str
    name: str
    version: str
    ecosystem: str
    missing_declaration: bool
    notice_gaps: list[str]


@dataclass
class Report:
    image_digest: str
    status: str = "unavailable"
    schema_version: int = 1
    metrics: Metrics | None = None
    issues: list[Issue] = field(default_factory=list)
    source_gaps: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=lambda: list(LIMITATIONS))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _document(path):
    from core.security.capped_read import read_capped
    raw = read_capped(path, MAX_BYTES, raise_on_refusal=True)
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8")
    del raw
    result = json.loads(text, object_pairs_hook=_unique)
    del text
    if not isinstance(result, dict):
        raise ValueError("audit document must be an object")
    return result, digest


def _records(rows, identifiers, *, complete=True):
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("invalid package coverage records")
    indexed = {row["id"]: row for row in rows}
    if (len(indexed) != len(rows) or not set(indexed) <= identifiers
            or (complete and set(indexed) != identifiers)):
        raise ValueError("incomplete or duplicate package coverage inventory")
    return indexed


def collect(audit, image_digest):
    """Accept only complete evidence bound to the exact inventory and image."""
    from core.oci.evidence import subject
    from core.oci.license_declarations import catalogue_declaration_missing
    report = Report(image_digest)
    try:
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest):
            raise ValueError("invalid exported image digest")
        native, native_sha = _document(audit / "syft.json")
        provenance, _ = _document(audit / "prepared/provenance.json")
        image, _ = subject(native)
        notices = provenance["notice_evidence"]
        if image["manifest_digest"] != image_digest or notices["subject"] != image:
            raise ValueError("audit subject differs from the image being published")
        if not any(row.get("sha256") == native_sha for row in provenance["inputs"]):
            raise ValueError("prepared evidence is not bound to this inventory")
        artifacts = native["artifacts"]
        identifiers = {row["id"] for row in artifacts}
        if not identifiers or len(identifiers) != len(artifacts):
            raise ValueError("empty or duplicate package inventory")
        records = _records(notices["packages"], identifiers)
        sources = _records(provenance["packages"], identifiers, complete=False)
        files = set()
        for artifact in artifacts:
            row = records[artifact["id"]]
            gaps = row["gaps"]
            if (row["status"] not in {"notice_candidate_captured", "metadata_only", "no_associated_evidence"}
                    or not isinstance(gaps, list) or any(not isinstance(gap, str) for gap in gaps)):
                raise ValueError("invalid notice coverage status")
            if row["status"] != "notice_candidate_captured" and not gaps:
                raise ValueError("missing notice evidence has no recorded gap")
            if row["status"] == "notice_candidate_captured" and not any(
                    item["content_kind"] == "notice_candidate" for item in row["files"]):
                raise ValueError("captured notice status has no retained notice file")
            recovered = row.get("recovered_component_license") or row.get("recovered_distribution_license")
            missing = catalogue_declaration_missing(artifact) and not recovered
            if missing or gaps:
                report.issues.append(Issue(artifact["id"], artifact["name"], artifact.get("version", ""),
                                           artifact["type"], missing, gaps))
            files.update((item["path"], item["catalogue_layer_diff_id"], item["sha256"])
                         for item in row["files"] if item["content_kind"] == "notice_candidate")
        files.update((item["path"], item["catalogue_layer_diff_id"], item["sha256"])
                     for item in notices.get("unassociated_files", []) if item["content_kind"] == "notice_candidate")
        report.source_gaps = [sources[key] for key in sorted(sources) if sources[key]["gaps"]]
        report.metrics = Metrics(len(artifacts), sum(item.missing_declaration for item in report.issues),
                                 sum(bool(item.notice_gaps) for item in report.issues), len(files), len(report.source_gaps), len(sources))
        report.status = "gaps" if report.issues else "complete_for_catalogued_packages"
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        # Partial results must never look like a clean or complete audit.
        report.metrics = None
        report.issues = []
        report.source_gaps = []
        report.errors = [str(exc)]
    return report


def _cell(value):
    return html.escape(str(value)).replace("|", "&#124;").replace("`", "&#96;").replace("\n", " ").replace("\r", " ")


def markdown(report):
    lines = ["## Container licenses and notices", "", f"Image: `{report.image_digest}`", ""]
    if report.metrics is None:
        lines += ["**Audit unavailable or incomplete. Coverage is unknown. Publication is not blocked.**", ""]
        lines.extend("- " + _cell(error) for error in report.errors)
    else:
        metrics = report.metrics
        lines += ["| Check | Count |", "| --- | ---: |", f"| Catalogued packages | {metrics.packages} |",
                  f"| Unresolved license declarations | {metrics.unresolved_declarations} |",
                  f"| Packages with notice evidence gaps | {metrics.notice_gap_packages} |",
                  f"| Retained notice/text files | {metrics.captured_notice_files} |",
                  f"| Source/build packages explicitly assessed | {metrics.source_assessed_packages} |",
                  f"| Recorded source/build warnings | {metrics.source_gap_packages} |", ""]
        if report.issues:
            lines += ["| Package | Missing evidence |", "| --- | --- |"]
            for issue in report.issues:
                details = (["license declaration"] if issue.missing_declaration else []) + issue.notice_gaps
                lines.append(f"| {_cell(issue.name)}@{_cell(issue.version)} | {_cell('; '.join(details))} |")
            lines.append("")
    lines += ["Download the **container-sbom** artifact for `license-report.json`, this report, paired SBOMs,",
              "provenance, original inventories, and the collected license and notice files.", ""]
    lines.extend("- " + text for text in report.limitations)
    return "\n".join(lines) + "\n"


def _command(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotations(report):
    if report.metrics is None:
        return ["::warning title=Container license audit unavailable::" + _command("; ".join(report.errors))]
    if not report.issues:
        return []
    messages = [f"::warning title=Container license evidence::{len(report.issues)} package(s) have evidence gaps. See the job summary and container-sbom artifact."]
    for issue in report.issues[:9]:
        gaps = (["missing license declaration"] if issue.missing_declaration else []) + issue.notice_gaps
        message = f"{issue.name}@{issue.version}: " + "; ".join(gaps)
        messages.append("::warning title=Container license evidence::" + _command(message[:1500]))
    return messages


def main():
    from core.json import save_json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-dir", type=Path, required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--emit-annotations", action="store_true")
    parser.add_argument("--audit-status", default="success")
    args = parser.parse_args()
    report = (collect(args.audit_dir, args.image_digest) if args.audit_status == "success"
              else Report(args.image_digest, errors=["Evidence preparation outcome: " + args.audit_status]))
    args.audit_dir.mkdir(parents=True, exist_ok=True)
    save_json(args.audit_dir / "license-report.json", asdict(report))
    (args.audit_dir / "license-report.md").write_text(markdown(report), encoding="utf-8")
    if args.emit_annotations:
        for line in annotations(report):
            print(line)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    main()
