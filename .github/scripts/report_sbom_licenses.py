#!/usr/bin/env python3
"""Write inspectable, non-blocking container license and notice coverage reports."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import html
from pathlib import Path
import sys


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from packages.sca.sbom_inventory import coverage as _coverage
from packages.sca.sbom_inventory.coverage import Issue as Issue, Metrics as Metrics, Report, LIMITATIONS as LIMITATIONS

MAX_BYTES = _coverage.MAX_BYTES


def collect(audit, image_digest):
    return _coverage.collect(audit, image_digest, max_bytes=MAX_BYTES)


def match_inventory_ownership(native, candidates):
    return _coverage.match_inventory_ownership(native, candidates)


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
                  f"| Recorded source/build warnings | {metrics.source_gap_packages} |",
                  f"| Executables without scanner package identification | {metrics.scanner_unidentified_executables if metrics.scanner_unidentified_executables is not None else 'unknown'} |",
                  f"| Files matched to package records by SHA-256 | {metrics.checksum_matched_executables if metrics.checksum_matched_executables is not None else 'unknown'} |",
                  f"| Files matched to collected native identities by SHA-256 | {metrics.native_identity_matched_executables if metrics.native_identity_matched_executables is not None else 'unknown'} |",
                  f"| Files associated through installed build declarations | {metrics.build_declared_executables if metrics.build_declared_executables is not None else 'unknown'} |",
                  f"| Files identified by release targets and version signatures | {metrics.version_identified_executables if metrics.version_identified_executables is not None else 'unknown'} |",
                  f"| Executable files needing ownership checks | {metrics.unidentified_executables if metrics.unidentified_executables is not None else 'unknown'} |", ""]
        if report.issues:
            lines += ["| Package | Missing evidence |", "| --- | --- |"]
            for issue in report.issues:
                details = (["license declaration"] if issue.missing_declaration else []) + issue.notice_gaps
                lines.append(f"| {_cell(issue.name)}@{_cell(issue.version)} | {_cell('; '.join(details))} |")
            lines.append("")
    if report.source_assessments:
        labels = {"verified_interpreted_source": "Source and metadata matched upstream",
                  "verified_source_payload": "Python sources and signed driver matched",
                  "verified_publisher_release_binary": "Binary matches publisher-signed release"}
        lines += ["### Source and build evidence", "",
                  "| Package | Version | Evidence | Files matched | Remaining warnings |",
                  "| --- | --- | --- | ---: | --- |"]
        rows = sorted(report.source_assessments, key=lambda row: (
            not bool(row["gaps"]), str(row["name"]), str(row["version"]), row["id"]))
        for row in rows[:20]:
            evidence = labels.get(row["status"], "Source correspondence not verified")
            count = row["matched_files"] if row["matched_files"] is not None else "unknown"
            warnings = "; ".join(row["gaps"]) or "None recorded"
            lines.append("| " + " | ".join(_cell(value) for value in (
                row["name"], row["version"], evidence, count, warnings)) + " |")
        lines += ["", "Only the listed assessments are shown; these results do not establish build provenance for every catalogued package.",
                  "Full assessment scopes, limitations and per-file evidence are retained in `prepared/provenance.json`.", ""]
    if report.native_notice_collections:
        lines += ["### Native tool release notices", "", "| Tool | Version | Collection |", "| --- | --- | --- |"]
        for receipt in report.native_notice_collections:
            lines.append("| " + _cell(receipt.get("name", "unknown")) + " | " +
                         _cell(receipt.get("version", "unknown")) + " | " + _cell(receipt["status"]) + " |")
        lines += ["", "Release texts do not establish bundled dependency completeness or exact build-source correspondence.", ""]
    dependencies = [row for row in report.native_notice_collections if row.get("dependency_notices")]
    if dependencies:
        lines += ["### Native dependency notice candidates", "",
                  "These are external source-lock entries, including build, development and other-platform dependencies. They are not confirmed installed components.", "",
                  "| Tool | External entries | Source notice candidates | Distributor notices | Metadata only | Unavailable |",
                  "| --- | ---: | ---: | ---: | ---: | ---: |"]
        for row in dependencies:
            counts = row["dependency_notices"]
            lines.append("| " + " | ".join(_cell(value) for value in (
                row.get("name", "unknown"), counts["candidates"], counts["captured"] - counts.get("distributor_notices", 0), counts.get("distributor_notices", 0), counts["metadata_only"], counts["unavailable"])) + " |")
        lines += ["", "The collected source inventory records package names, versions, archive checksums, publisher license declarations and notice origins. Distributor notices remain distinct from upstream-authored text and include their source checksum or source-file matching evidence. Runtime membership and Rust standard-library completeness require separate evidence.", ""]
    toolchains = [row for row in report.native_notice_collections if row.get("toolchain_notices")]
    if toolchains:
        lines += ["### Rust standard-library notice candidates", "",
                  "These original release texts follow the toolchain declared in the tool's source. They do not establish the compiler used for the installed executable or its compiled dependency membership.", "",
                  "| Tool | Rust release | Notice files | Collection |", "| --- | --- | ---: | --- |"]
        for row in toolchains:
            rust = row["toolchain_notices"]
            lines.append("| " + " | ".join(_cell(value) for value in (
                row.get("name", "unknown"), rust.get("version", "unknown"), rust.get("notice_files", "unknown"), rust["status"])) + " |")
        lines += ["", "The collected library copyright document includes the release's third-party standard-library notices. Release metadata, archive checksums and source declarations are retained with the notice provenance.", ""]
    if report.inventory_candidates:
        lines += ["### Unexplained executable files", "",
                  "These files need ownership checks; they are not necessarily separate packages or missing licenses.", "",
                  "| Path |", "| --- |"]
        lines.extend("| " + _cell(row["path"]) + " |" for row in report.inventory_candidates[:20])
        lines += ["", "The JSON report contains unresolved candidates, package ownership proofs and native binary identity matches. File identity and package membership do not establish bundled dependency completeness.", ""]
    lines.extend("- " + _cell(error) for error in report.inventory_errors)
    lines += ["Download the **container-sbom** artifact for `license-report.json`, this report, paired SBOMs,",
              "provenance, original inventories, and the collected license and notice files.", ""]
    lines.extend("- " + text for text in report.limitations)
    return "\n".join(lines) + "\n"


def _command(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotations(report):
    if report.metrics is None:
        return ["::warning title=Container license audit unavailable::" + _command("; ".join(report.errors))]
    inventory = []
    if report.inventory_candidates:
        inventory.append("::warning title=Container executable inventory::" +
                         str(len(report.inventory_candidates)) +
                         " executable file(s) remain unexplained after package and native-identity checksum matching; ownership and bundled notices need checking. See container-sbom/license-report.json.")
    failed_collections = sum(row["status"] == "unavailable" for row in report.native_notice_collections)
    if failed_collections:
        inventory.append("::warning title=Native tool release notices::" + str(failed_collections) +
                         " native tool notice collection(s) unavailable. See the report and retained provenance.")
    inventory.extend("::warning title=Container executable inventory::" + _command(error)
                     for error in report.inventory_errors)
    if report.source_gaps:
        level = "warning" if any((row.get("source_check") or {}).get("status") == "unverified"
                                 for row in report.source_gaps) else "notice"
        inventory.append("::" + level + " title=Container source/build evidence::" +
                         str(len(report.source_gaps)) +
                         " assessed package(s) have source/build warnings. See Source and build evidence in the job summary and prepared/provenance.json in the container-sbom artifact.")
    missing_toolchains = sum((row.get("toolchain_notices") or {}).get("status") == "unavailable"
                             for row in report.native_notice_collections)
    if missing_toolchains:
        inventory.append("::warning title=Rust standard-library notice candidates::" + str(missing_toolchains) +
                         " source-declared Rust release notice collection(s) unavailable. See the report and retained provenance.")
    for receipt in report.native_notice_collections:
        counts = receipt.get("dependency_notices")
        if counts and (counts["metadata_only"] or counts["unavailable"]):
            level = "warning" if counts["unavailable"] else "notice"
            inventory.append("::" + level + " title=Native dependency notice candidates::" +
                             str(counts["metadata_only"] + counts["unavailable"]) +
                             " external source-lock candidates lack collected notice text. These are not confirmed installed components. See the source inventory in the container-sbom artifact.")
    if not report.issues:
        return inventory[:10]
    messages = [f"::warning title=Container license evidence::{len(report.issues)} package(s) have evidence gaps. See the job summary and container-sbom artifact."]
    messages = inventory + messages
    for issue in report.issues[:max(0, 10 - len(messages))]:
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
    main()
