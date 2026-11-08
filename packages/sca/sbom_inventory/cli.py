"""Inspect, compare, explain and collect SBOM evidence without generating HTML."""
from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys
import zipfile

from core.tar import TarOpenError
from core.json import dumps_artifact, save_json
from core.logging import configure_cli_logging
from core.security.log_sanitisation import sanitise_for_terminal, escape_nonprintable
from .compare import compare
from .inventory import read_inventory
from .model import selected
from .output import inventory_chunks, csv_chunks, record_chunks, export_notices, markdown, write_inventory
from .source import Source
from .relationships import explain


def parser():
    result = argparse.ArgumentParser(prog="raptor-sca sbom", description=__doc__,
        epilog="Examples:\n  raptor-sca sbom inspect sbom.cdx.json --out inventory\n  raptor-sca sbom diff baseline/inventory.json current/inventory.json",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = result.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="inspect an SBOM or collected evidence", description="Inspect declarations, supplied dependency links and retained notice/ownership evidence. No network or image code is executed.",
        epilog="Examples:\n  raptor-sca sbom inspect container-sbom.zip --out inventory\n  raptor-sca sbom inspect sbom.spdx.json --license MIT --format csv",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    notices = commands.add_parser("notices", help="export original licence and notice bytes", description="Export retained original bytes and a portable index to a new directory. External licence URLs are never fetched.",
        epilog="Examples:\n  raptor-sca sbom notices container-sbom.zip --out notices\n  raptor-sca sbom notices sbom.cdx.json --license MIT --out mit-notices",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    stats = commands.add_parser("stats", help="summarise licence, ecosystem and evidence distributions offline",
        description="Print JSON distributions from supplied inventory records, separated by scope. No network, source execution or notice-byte verification occurs.",
        epilog="Examples:\n  raptor-sca sbom stats container-sbom.zip --scope packages\n  raptor-sca sbom stats release.cdx.json --license GPL-3.0-only --out statistics.json",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    for sub in (inspect, notices, stats):
        sub.add_argument("input", type=Path, help="CycloneDX 1.5 / SPDX 2.3 JSON, audit snapshot, evidence ZIP or directory")
        sub.add_argument("--license", dest="license_id", help="exact declaration operand, including AND/OR expressions (default: all)")
        sub.add_argument("--package", help="exact package name, occurrence ID or Package URL (default: all)")
        sub.add_argument("--scope", choices=("packages", "source-candidates", "subjects"), help="inventory scope (default: all, kept separate)")
    for sub in (inspect, stats):
        sub.add_argument("--ecosystem", help="exact Package URL type, for example npm or deb")
        sub.add_argument("--unresolved", action="store_true", help="select records with missing or unknown licence declarations")
        sub.add_argument("--notice-status", help="exact recorded notice status")
    stats.add_argument("--out", type=Path, help="also save statistics JSON")
    inspect.add_argument("--limit", type=int, default=50, help="text display rows; does not truncate saved inventories or machine exports")
    inspect.add_argument("--offset", type=int, default=0, help="text display starting row")
    inspect.add_argument("--records-only", action="store_true", help="JSON contains selected records only, not a portable full inventory snapshot")
    inspect.add_argument("--format", choices=("text", "json", "csv", "jsonl"), default="text", help="stdout format (default: text)")
    inspect.add_argument("--out", type=Path, help="also write inventory.json, inventory.csv and summary.md (default: stdout only)")
    notices.add_argument("--out", type=Path, required=True, help="new export directory; existing paths are refused")
    diff = commands.add_parser("diff", help="compare two inventories or audit snapshots", description="Compare packages, declarations, notice fingerprints, supplied dependencies and recorded executable ownership. Ambiguous matches remain explicit; notice text updates are informational.",
        epilog="Examples:\n  raptor-sca sbom diff old.cdx.json new.cdx.json\n  raptor-sca sbom diff old/inventory.json new/inventory.json --out changes.json",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    diff.add_argument("baseline", type=Path)
    diff.add_argument("current", type=Path)
    diff.add_argument("--out", type=Path, help="also save comparison JSON (default: stdout only)")
    why = commands.add_parser("why", help="explain supplied dependency paths", description="Trace retained parent relationships for a package. Missing graph data remains explicit; no source code or image is executed.",
        epilog="Examples:\n  raptor-sca sbom why inventory.json example\n  raptor-sca sbom why sbom.cdx.json example --root application",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    why.add_argument("input", type=Path)
    why.add_argument("package", help="exact name, occurrence ID or Package URL")
    why.add_argument("--root", help="optional explicit root name/ID/PURL (default: show supplied ancestor boundaries)")
    why.add_argument("--max-paths", type=int, default=20, help="paths per occurrence (default: 20, maximum: 1000)")
    why.add_argument("--max-depth", type=int, default=32, help="path depth budget (default: 32, maximum: 128)")
    why.add_argument("--out", type=Path, help="also save path JSON (default: stdout only)")
    collect = commands.add_parser("collect", help="collect original container notice evidence", description="Collect from a native Syft 16.x image catalogue and an OCI layout or explicit digest-pinned registry. The image is never executed.",
        epilog="Examples:\n  raptor-sca sbom collect --syft syft.json --oci-layout image-layout --out evidence\n  raptor-sca sbom collect --syft syft.json --registry-ref example/image@sha256:DIGEST --out evidence",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    collect.add_argument("--syft", type=Path, required=True, help="native Syft 16.x image JSON, including file hashes and image metadata")
    origin = collect.add_mutually_exclusive_group(required=True)
    origin.add_argument("--oci-layout", type=Path, help="offline OCI blob store")
    origin.add_argument("--registry-ref", help="explicit IMAGE@sha256:PLATFORM_MANIFEST_DIGEST; enables registry network access")
    collect.add_argument("--identify", action="append", default=[], help="catalogued image path to hash without retaining executable bytes (repeatable)")
    collect.add_argument("--out", type=Path, required=True, help="new evidence directory; existing paths are refused")
    plan = commands.add_parser("plan", help="plan upgrades from an SBOM scan's findings",
        description="Build read-only upgrade proposals from an inventory and saved SCA findings. Candidate advisory rechecks are explicit; this does not rewrite manifests or rebuild images.",
        epilog="Examples:\n  raptor-sca sbom plan scan/sbom.cdx.json --findings scan/findings.json --out plan\n  raptor-sca sbom plan release.spdx.json --findings scan/findings.json --check-candidates --format json\n\nExit codes: saved plan: 0 on success; candidate recheck: 0 with an advisory-clear option per affected package, 1 without one, 2 for unavailable evidence or invalid input.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    plan.add_argument("input", type=Path, help="SBOM, inventory snapshot or evidence bundle used for the scan")
    plan.add_argument("--findings", type=Path, required=True, help="RAPTOR findings.json from that SBOM scan")
    plan.add_argument("--check-candidates", action="store_true", help="recheck installed and candidate versions with the advisory client (default: saved findings only)")
    plan.add_argument("--offline", action="store_true", help="candidate checks use cached advisories only; missing entries remain unknown")
    plan.add_argument("--cache-root", type=Path, help="advisory cache directory (default: normal SCA cache)")
    plan.add_argument("--max-candidates", type=int, default=5, help="candidates per package (default: 5, maximum: 20)")
    plan.add_argument("--max-queries", type=int, default=1000, help="total unique installed/candidate coordinates (default: 1000, maximum: 10000)")
    plan.add_argument("--format", choices=("text", "json"), default="text", help="stdout format (default: text)")
    plan.add_argument("--out", type=Path, help="new directory for upgrade-plan.json and upgrade-plan.md (default: stdout only)")
    verify = commands.add_parser("verify-plan", help="verify an upgrade plan against a rebuilt SBOM scan",
        description="Compare planned targets and advisory outcomes using local artifacts. Positive query coverage is required to confirm resolved findings; no network, source rewrite or image execution occurs.",
        epilog="Examples:\n  raptor-sca sbom verify-plan upgrade-plan/upgrade-plan.json rebuilt/sbom.cdx.json --findings rebuilt/findings.json\n  raptor-sca sbom verify-plan plan.json rebuilt.spdx.json --findings findings.json --coverage advisory-coverage.json --out verification\n\nExit codes: 0 verified within recorded coverage; 1 unmet targets or advisory concerns; 2 unavailable or inconsistent evidence.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    verify.add_argument("plan", type=Path, help="saved upgrade-plan.json")
    verify.add_argument("current", type=Path, help="rebuilt scan's CycloneDX 1.5 or SPDX 2.3 JSON SBOM")
    verify.add_argument("--findings", type=Path, required=True, help="rebuilt scan's findings.json")
    verify.add_argument("--coverage", type=Path, help="advisory coverage receipt (default: advisory-coverage.json alongside findings)")
    verify.add_argument("--max-coverage-age-hours", type=float, help="require a coverage receipt generated within this many hours; does not establish feed freshness")
    verify.add_argument("--format", choices=("text", "json"), default="text", help="stdout format (default: text)")
    verify.add_argument("--out", type=Path, help="new directory for upgrade-verification.json and upgrade-verification.md")
    return result


def _emit(value):
    # JSON escapes controls and BIDI/non-ASCII for terminal-safe machine output.
    print(dumps_artifact(value, ensure_ascii=True))


def main(argv=None):
    args = parser().parse_args(argv)
    configure_cli_logging(logging.WARNING)
    try:
        if args.command == "verify-plan":
            from .verification import read_plan, verify_plan
            from .advisory_coverage import read_coverage
            from .plan_inputs import read_findings
            from .output import verification_markdown, write_verification
            plan, plan_sha = read_plan(args.plan)
            with Source(args.current) as source:
                inventory, _ = read_inventory(source, require_scan_document=True, verify_notices=False)
            findings, findings_sha = read_findings(args.findings)
            coverage, coverage_sha, errors = read_coverage(
                args.coverage or args.findings.parent / "advisory-coverage.json", inventory.source_sha256, findings_sha, max_age_hours=args.max_coverage_age_hours)
            report = verify_plan(plan, plan_sha, inventory, findings, findings_sha,
                                 coverage=coverage, coverage_sha=coverage_sha, coverage_errors=errors)
            report["limitations"].append("Notice bytes were not re-verified; upgrade verification uses package/query evidence only.")
            if args.out:
                write_verification(args.out, report)
            if args.format == "json":
                _emit(report)
            else:
                print(escape_nonprintable(verification_markdown(report), preserve_newlines=True))
            return report["exit_code"]
        if args.command == "plan":
            from .plan import build_plan
            from .plan_inputs import read_findings
            from .output import upgrade_plan_markdown, write_upgrade_plan
            with Source(args.input) as source:
                inventory, _ = read_inventory(source, verify_notices=False)
            findings, sha = read_findings(args.findings)
            osv = None
            if args.check_candidates:
                from .. import default_client, sca_cache_root
                from ..osv import OsvClient
                from core.json import JsonCache
                cache = JsonCache(root=args.cache_root or sca_cache_root())
                osv = OsvClient(default_client(offline=args.offline), cache, offline=args.offline)
            report = build_plan(inventory, findings, sha, osv=osv,
                                max_candidates=args.max_candidates, max_queries=args.max_queries)
            report["limitations"].append("Notice bytes were not re-verified; notice status is supplied metadata only.")
            if args.out:
                write_upgrade_plan(args.out, report)
            if args.format == "json":
                _emit(report)
            else:
                print(escape_nonprintable(upgrade_plan_markdown(report), preserve_newlines=True))
            return report["exit_code"]
        if args.command == "collect":
            from .collection import collect_image
            _emit(collect_image(args.syft, args.out, oci_layout=args.oci_layout,
                                registry_ref=args.registry_ref, identify=args.identify))
            return 0
        if args.command == "why":
            with Source(args.input) as source:
                inventory, _ = read_inventory(source, verify_notices=False)
            result = explain(inventory, args.package, root=args.root, max_paths=args.max_paths, max_depth=args.max_depth)
            result["notice_verification"] = inventory.notice_verification
            if args.out:
                save_json(args.out, result, stream=True)
            _emit(result)
            return 0
        if args.command == "diff":
            with Source(args.baseline) as source:
                before, _ = read_inventory(source)
            with Source(args.current) as source:
                after, _ = read_inventory(source)
            result = compare(before, after)
            if args.out:
                save_json(args.out, result, stream=True)
            _emit(result)
            return 0
        with Source(args.input) as source:
            inventory, embedded = read_inventory(source, verify_notices=args.command != "stats")
            records = selected(inventory, license_id=args.license_id, package=args.package, scope=args.scope)
            if args.command in {"inspect", "stats"}:
                from .statistics import ecosystem
                records = [row for row in records if (not args.ecosystem or ecosystem(row) == args.ecosystem)
                           and (not args.unresolved or row.declaration_missing)
                           and (not args.notice_status or row.notice_status == args.notice_status)]
            if args.command == "stats":
                from .statistics import statistics
                report = statistics(inventory, records)
                if args.out:
                    if args.out.resolve() == args.input.resolve() or (args.out.exists() and args.out.samefile(args.input)):
                        raise ValueError("statistics output must differ from the input")
                    save_json(args.out, report, stream=True)
                _emit(report)
                return 0
            if args.command == "inspect" and (args.limit < 1 or args.offset < 0):
                raise ValueError("display limit must be positive and offset nonnegative")
            if args.command == "inspect" and args.records_only and args.format != "json":
                raise ValueError("--records-only applies to --format json; JSONL always exports selected records")
            if args.command == "notices":
                result = export_notices(args.out, inventory, records, source, embedded,
                                        include_unassociated=not any((args.license_id, args.package, args.scope)))
                _emit(result)
            else:
                if args.out:
                    write_inventory(args.out, inventory, records)
                if (args.format == "json" and args.records_only) or args.format == "jsonl":
                    for part in record_chunks(inventory, records, jsonl=args.format == "jsonl"):
                        sys.stdout.write(part)
                elif args.format == "json":
                    for part in inventory_chunks(inventory, records):
                        sys.stdout.write(part)
                elif args.format == "csv":
                    for part in csv_chunks(records):
                        sys.stdout.write(part)
                else:
                    print(escape_nonprintable(markdown(inventory, records, limit=args.limit, offset=args.offset), preserve_newlines=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError, zipfile.BadZipFile, TarOpenError) as error:
        print("raptor-sca sbom: " + sanitise_for_terminal(str(error)), file=sys.stderr)
        return 2
