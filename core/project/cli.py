"""CLI entry point for `raptor project` subcommands.

Called directly from bin/raptor when `project` is the first argument.
No Claude Code, no LLM — pure Python.
"""

import argparse
import os
import sys
from pathlib import Path

from core.run.output import unique_run_suffix

from .project import ProjectManager


def _c(text, code):
    """Colour text if stdout is a terminal."""
    if not os.isatty(1):
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(text): return _c(text, "32")
def _red(text): return _c(text, "31")
def _yellow(text): return _c(text, "33")


class _Fmt(argparse.HelpFormatter):
    """Wider help alignment for subcommand option lists."""
    def __init__(self, prog):
        super().__init__(prog, max_help_position=34)


def main():
    parser = argparse.ArgumentParser(
        prog="raptor project",
        usage="raptor project <command> [args]",
        description="Manage RAPTOR projects. Run 'raptor project help <command>' for details.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=20),
    )
    sub = parser.add_subparsers(dest="subcommand", title="commands", metavar="")
    _F = {"formatter_class": _Fmt}  # shorthand for subparsers

    # create
    p_create = sub.add_parser("create", help="Create a new project",
                              usage="raptor project create <name> --target <path> [-d <desc>] [--output-dir <dir>]", **_F)
    p_create.add_argument("name", help="Project name")
    p_create.add_argument("--target", required=True, metavar="<path>", help="Path to target codebase")
    p_create.add_argument("-d", "--description", default="", metavar="<text>", help="One-line description")
    p_create.add_argument("--output-dir", default=None, metavar="<dir>", help="Custom output directory")

    # use
    p_use = sub.add_parser("use", help="Set the active project (no arg = show current)",
                           usage="raptor project use [<name>]", **_F)
    p_use.add_argument("name", nargs="?", help="Project name, 'none' to clear")

    # none (alias for "use none")
    sub.add_parser("none", help="Clear the active project (alias for 'use none')", **_F)

    # list
    sub.add_parser("list", help="Show all projects",
                   usage="raptor project list", **_F)

    # status
    p_status = sub.add_parser("status", help="Show project summary",
                              usage="raptor project status [<name>]", **_F)
    p_status.add_argument("name", nargs="?", help="Project name")

    # coverage
    p_cov = sub.add_parser(
        "coverage",
        help="Show coverage summary",
        usage="raptor project coverage [<name>] [--detailed] [--fail-under <pct>]",
        **_F,
    )
    p_cov.add_argument("name", nargs="?", help="Project name")
    p_cov.add_argument("--detailed", action="store_true", help="Per-file breakdown")
    p_cov.add_argument(
        "--fail-under",
        type=float,
        metavar="<pct>",
        help="Exit non-zero unless LLM item coverage is at least this percentage",
    )

    # findings
    p_findings = sub.add_parser("findings", help="Show merged findings across all runs",
                                usage="raptor project findings [<name>] [--detailed]", **_F)
    p_findings.add_argument("name", nargs="?", help="Project name")
    p_findings.add_argument("--detailed", action="store_true", help="Per-finding detail (reasoning, proof, PoC)")

    # delete
    p_delete = sub.add_parser("delete", help="Delete a project",
                              usage="raptor project delete <name> [--purge] [--yes]", **_F)
    p_delete.add_argument("name", help="Project name")
    p_delete.add_argument("--purge", action="store_true", help="Also delete output directory")
    p_delete.add_argument("--yes", action="store_true", help="Skip confirmation")

    # rename
    p_rename = sub.add_parser("rename", help="Rename a project",
                              usage="raptor project rename <old> <new>", **_F)
    p_rename.add_argument("old", help="Current name")
    p_rename.add_argument("new", help="New name")

    # notes
    p_notes = sub.add_parser("notes", help="View or update project notes",
                             usage="raptor project notes <name> [<text>] [--file <path>] [--edit]", **_F)
    p_notes.add_argument("name", help="Project name")
    p_notes.add_argument("text", nargs="?", help="New notes text")
    if os.isatty(0):
        p_notes.add_argument("--edit", action="store_true", help="Open in $EDITOR")
    p_notes.add_argument("--file", default=None, metavar="<path>", help="Read notes from file")

    # description
    p_desc = sub.add_parser("description", help="View or update project description",
                            usage="raptor project description <name> [<text>]", **_F)
    p_desc.add_argument("name", help="Project name")
    p_desc.add_argument("text", nargs="?", help="New description text")

    # add
    p_add = sub.add_parser("add", help="Add existing runs to a project",
                           usage="raptor project add <name> <directory> [--target <path>] [--output-dir <dir>]", **_F)
    p_add.add_argument("name", help="Project name")
    p_add.add_argument("directory", help="Directory containing runs")
    p_add.add_argument("--target", metavar="<path>", help="Target path (creates project if needed)")
    p_add.add_argument("--output-dir", default=None, metavar="<dir>", help="Custom output directory")

    # remove
    p_remove = sub.add_parser("remove", help="Move a run out of the project",
                              usage="raptor project remove <name> <run> --to <path>", **_F)
    p_remove.add_argument("name", help="Project name")
    p_remove.add_argument("run", help="Run directory name")
    p_remove.add_argument("--to", required=True, metavar="<path>", help="Destination path")

    # report
    p_report = sub.add_parser("report", help="Generate merged report across all runs",
                              usage="raptor project report [<name>]", **_F)
    p_report.add_argument("name", nargs="?", help="Project name")

    # diff
    p_diff = sub.add_parser("diff", help="Compare findings between two runs",
                            usage="raptor project diff <name> <run1> <run2>", **_F)
    p_diff.add_argument("name", help="Project name")
    p_diff.add_argument("run1", help="Baseline run")
    p_diff.add_argument("run2", help="Comparison run")

    # merge
    p_merge = sub.add_parser("merge", help="Merge runs per command type (destructive)",
                             usage="raptor project merge [<name>] [--type <type>] [--yes]", **_F)
    p_merge.add_argument("name", nargs="?", help="Project name")
    p_merge.add_argument("--type", default="all", metavar="<type>", help="scan|validate|agentic|all")
    p_merge.add_argument("--yes", action="store_true", help="Skip confirmation")

    # clean
    p_clean = sub.add_parser("clean", help="Delete old runs, keep latest n",
                             usage="raptor project clean [<name>] [--keep <n>] [--dry-run] [--yes]", **_F)
    p_clean.add_argument("name", nargs="?", help="Project name")
    p_clean.add_argument("--keep", type=int, default=1, metavar="<n>", help="Runs to keep per type (default: 1)")
    p_clean.add_argument("--dry-run", action="store_true", help="Show what would be deleted")
    p_clean.add_argument("--yes", action="store_true", help="Skip confirmation")

    # correlate
    p_correlate = sub.add_parser("correlate", help="Cross-run finding correlation",
                                 usage="raptor project correlate [<name>] [--json]", **_F)
    p_correlate.add_argument("name", nargs="?", help="Project name")
    p_correlate.add_argument("--json", dest="json_out", action="store_true",
                             help="Output raw JSON instead of formatted table")

    # export
    p_export = sub.add_parser("export", help="Export project as zip",
                              usage="raptor project export <name> <path> [--force]", **_F)
    p_export.add_argument("name", help="Project name")
    p_export.add_argument("path", help="Destination zip path")
    p_export.add_argument("--force", action="store_true", help="Overwrite existing file")

    # import
    p_import = sub.add_parser("import", help="Import project from zip",
                              usage="raptor project import <path> [--force] [--sha256 <hash>]", **_F)
    p_import.add_argument("path", help="Zip file path")
    p_import.add_argument("--force", action="store_true", help="Overwrite existing project")
    p_import.add_argument("--sha256", default=None, metavar="<hash>", help="Expected SHA-256 hash to verify")

    # help
    p_help = sub.add_parser("help", help="Show help",
                            usage="raptor project help [<subcommand>]", **_F)
    p_help.add_argument("topic", nargs="?", help="Subcommand name")

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        return

    # Alias: "project none" → "project use none"
    if args.subcommand == "none":
        args.subcommand = "use"
        args.name = "none"

    mgr = ProjectManager()

    try:
        if args.subcommand == "help":
            if args.topic:
                # Find the subparser and print its help
                if args.topic in sub.choices:
                    sub.choices[args.topic].print_help()
                else:
                    print(f"Unknown subcommand: {args.topic}")
            else:
                parser.print_help()

        elif args.subcommand == "create":
            p = mgr.create(args.name, args.target, description=args.description,
                           output_dir=args.output_dir)
            print(f"Created project '{p.name}' → {p.output_dir}")

        elif args.subcommand == "list":
            projects = mgr.list_projects()
            if not projects:
                print("No projects.")
                return
            active = mgr.get_active()
            # Compute column width from actual names (+ 2 for "* " marker)
            max_name = max(len(p.name) for p in projects)
            col = max(max_name + 2, 12)
            for p in projects:
                marker = "* " if p.name == active else "  "
                desc = f"  {p.description}" if p.description else ""
                print(f"{marker}{p.name:<{col}s}{desc:30s}  {p.target}")

        elif args.subcommand == "status":
            name = args.name or _get_active_project()
            if not name:
                print("No project specified. Use: raptor project status <name>")
                return
            p = mgr.load(name)
            if not p:
                print(f"Project '{name}' not found.")
                return
            _print_status(p)

        elif args.subcommand == "coverage":
            name = args.name or _get_active_project()
            if not name:
                print("No project specified.")
                return
            p = mgr.load(name)
            if not p:
                print(f"Project '{name}' not found.")
                return
            result = _print_coverage(p, detailed=args.detailed, fail_under=args.fail_under)
            if result is False:
                sys.exit(1)

        elif args.subcommand == "findings":
            name = args.name or _get_active_project()
            if not name:
                print("No project specified.")
                return
            p = mgr.load(name)
            if not p:
                print(f"Project '{name}' not found.")
                return
            _print_findings(p, detailed=args.detailed)

        elif args.subcommand == "use":
            if args.name is None:
                # No argument — show current active project
                active = mgr.get_active()
                if active:
                    p = mgr.load(active)
                    if p:
                        print(f"Active project: {p.name} ({p.target})")
                    else:
                        print(f"Active project: {active} (project file missing)")
                else:
                    print("No active project.")
                return
            if args.name == "none":
                prev = mgr.get_active()
                mgr.set_active(None)
                if prev:
                    print(f"Cleared active project: {prev}")
                else:
                    print("No active project.")
                return
            p = mgr.load(args.name)
            if not p:
                print(f"Project '{args.name}' not found.")
                return
            mgr.set_active(args.name)
            print(f"Active project: {p.name} ({p.target})")
            print(f"  Output dir: {p.output_dir}")

        elif args.subcommand == "delete":
            p = mgr.load(args.name)
            if not p:
                print(f"Project '{args.name}' not found.")
                return
            if args.purge and not args.yes and p.output_path.exists():
                size = sum(f.stat().st_size for f in p.output_path.rglob("*") if f.is_file())
                if size >= 1024 * 1024:
                    size_str = f"{size / 1024 / 1024:.1f}MB"
                elif size >= 1024:
                    size_str = f"{size / 1024:.1f}KB"
                else:
                    size_str = f"{size}B"
                print(f"This will delete {args.name} and its output ({size_str})")
                if input("Proceed? [y/N] ").lower() != "y":
                    print("Cancelled.")
                    return
            output_dir = p.output_dir
            mgr.delete(args.name, purge=args.purge)
            if args.purge:
                print(f"Deleted project '{args.name}' and its output")
            else:
                print(f"Deleted project '{args.name}' (output retained at {output_dir})")

        elif args.subcommand == "rename":
            mgr.rename(args.old, args.new)
            print(f"Renamed '{args.old}' → '{args.new}'")

        elif args.subcommand == "notes":
            sources = bool(args.text) + bool(args.file) + bool(getattr(args, "edit", False))
            if sources > 1:
                print("Specify only one of: text, --file, --edit")
                return
            if args.file:
                p = mgr.load(args.name)
                if not p:
                    print(f"Project '{args.name}' not found.")
                    return
                path = Path(args.file)
                if not path.exists():
                    print(f"File not found: {args.file}")
                    return
                mgr.update_notes(args.name, path.read_text().strip())
                print("Notes updated.")
            elif getattr(args, "edit", False):
                if not os.isatty(0):
                    print("--edit requires an interactive terminal. Use --file or pass text directly.")
                    return
                import shlex, tempfile, subprocess
                p = mgr.load(args.name)
                if not p:
                    print(f"Project '{args.name}' not found.")
                    return
                editor = os.environ.get("EDITOR", os.environ.get("VISUAL", "vi"))
                # Capture tf_path BEFORE tf.write so a failing write (disk
                # full, etc.) still leaves tf_path set and the finally can
                # unlink the stub. Keep tempfile creation inside the try so
                # finally covers the whole create+write+use lifetime.
                tf_path = None
                try:
                    with tempfile.NamedTemporaryFile(
                        suffix=".md", mode="w", delete=False,
                    ) as tf:
                        tf_path = tf.name
                        tf.write(p.notes or "")
                    result = subprocess.run(shlex.split(editor) + [tf_path])
                    if result.returncode != 0:
                        print("Editor exited with error. Notes unchanged.")
                        return
                    new_notes = Path(tf_path).read_text().strip()
                    mgr.update_notes(args.name, new_notes)
                    print("Notes updated.")
                finally:
                    if tf_path:
                        Path(tf_path).unlink(missing_ok=True)
            elif args.text:
                mgr.update_notes(args.name, args.text)
                print("Notes updated.")
            else:
                p = mgr.load(args.name)
                if p:
                    print(p.notes or "(no notes)")
                else:
                    print(f"Project '{args.name}' not found.")

        elif args.subcommand == "description":
            if args.text:
                mgr.update_description(args.name, args.text)
                print("Description updated.")
            else:
                p = mgr.load(args.name)
                if p:
                    print(p.description or "(no description)")
                else:
                    print(f"Project '{args.name}' not found.")

        elif args.subcommand == "add":
            added = mgr.add_directory(args.name, args.directory, target=args.target,
                                       output_dir=args.output_dir)
            if added:
                print(f"Added {added} run(s) to project '{args.name}'")
            else:
                print(f"No new runs added (already present or none found in {args.directory})")

        elif args.subcommand == "remove":
            mgr.remove_run(args.name, args.run, to_path=args.to)
            print(f"Removed '{args.run}' from project '{args.name}'")

        elif args.subcommand == "correlate":
            name = args.name or _get_active_project()
            if not name:
                print("No project specified.")
                return
            p = mgr.load(name)
            if not p:
                print(f"Project '{name}' not found.")
                return
            _do_correlate(p, json_out=args.json_out)

        elif args.subcommand == "diff":
            from .diff import diff_runs
            p = mgr.load(args.name)
            if not p:
                print(f"Project '{args.name}' not found.")
                return
            dir1 = p.output_path / args.run1
            dir2 = p.output_path / args.run2
            if not dir1.exists():
                print(f"Run not found: {args.run1}")
                return
            if not dir2.exists():
                print(f"Run not found: {args.run2}")
                return
            result = diff_runs(dir1, dir2)
            print(f"Diff: {args.run1} (baseline) → {args.run2}")
            _print_diff(result)

        elif args.subcommand == "report":
            name = args.name or _get_active_project()
            if not name:
                print("No project specified.")
                return
            p = mgr.load(name)
            if not p:
                print(f"Project '{name}' not found.")
                return
            from .report import generate_project_report
            stats = generate_project_report(p)
            print(f"Report generated: {stats.get('report_dir', p.output_path / '_report')}")
            if stats.get("findings_dir"):
                print(f"  Findings directory: {stats['findings_dir']}")
            print(f"  Merged findings: {stats['findings']}")

        elif args.subcommand == "export":
            from .export import export_project
            p = mgr.load(args.name)
            if not p:
                print(f"Project '{args.name}' not found.")
                return
            p.sweep_stale_runs(keep_latest=True)
            project_json = mgr.projects_dir / f"{args.name}.json"
            result = export_project(p.output_path, Path(args.path),
                                    project_json_path=project_json,
                                    force=args.force)
            print(f"Exported to {result['path']}")
            print(f"  sha256: {result['sha256']}")

        elif args.subcommand == "import":
            from .export import import_project
            from core.hash import sha256_file
            zip_path = Path(args.path)
            if args.sha256:
                actual = sha256_file(zip_path)
                if actual != args.sha256.lower():
                    print(f"Hash mismatch: expected {args.sha256.lower()}, got {actual}",
                          file=sys.stderr)
                    sys.exit(1)
            result = import_project(zip_path, mgr.projects_dir,
                                    force=args.force)
            print(f"Imported project '{result['name']}'")
            if result.get("orphaned_output"):
                print(f"  Note: previous output retained at {result['orphaned_output']}")

        elif args.subcommand == "clean":
            name = args.name or _get_active_project()
            if not name:
                print("No project specified.")
                return
            p = mgr.load(name)
            if not p:
                print(f"Project '{name}' not found.")
                return
            _do_clean(p, args.keep, args.dry_run, args.yes)

        elif args.subcommand == "merge":
            name = args.name or _get_active_project()
            if not name:
                print("No project specified.")
                return
            p = mgr.load(name)
            if not p:
                print(f"Project '{name}' not found.")
                return
            _do_merge(p, args.type, args.yes)

    except (ValueError, FileExistsError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)


def _get_active_project():
    """Get the active project name from .active symlink or env var."""
    mgr = ProjectManager()
    return mgr.get_active()


def _count_sarif_results(run_dir):
    """Count total results across all SARIF files in a run directory."""
    from core.json import load_json
    count = 0
    for sarif_path in run_dir.glob("*.sarif"):
        data = load_json(sarif_path)
        if not data or not isinstance(data, dict):
            continue
        for run in data.get("runs", []):
            count += len(run.get("results", []))
    return count


def _get_output_summary(run_dir, meta):
    """Get findings/results string for a run, using cached summary when available.

    On first access for a completed run, computes the summary and writes it
    back to .raptor-run.json so subsequent calls are instant.
    """
    from core.json import save_json
    from core.run.metadata import RUN_METADATA_FILE

    # Use cached summary if present
    cached = (meta or {}).get("output_summary")
    if cached:
        return cached

    # Compute from findings or SARIF
    from .findings_utils import load_findings_from_dir, count_vulns
    findings = load_findings_from_dir(run_dir)
    if findings:
        vuln_count = count_vulns(findings)
        if vuln_count != len(findings):
            result = f"{vuln_count} findings"
        else:
            result = f"{len(findings)} findings"
    else:
        sarif_count = _count_sarif_results(run_dir)
        result = f"{sarif_count} results" if sarif_count else ""

    # Cache in metadata for completed/failed runs (won't change)
    status = (meta or {}).get("status", "")
    if result and status in ("completed", "failed"):
        meta_path = run_dir / RUN_METADATA_FILE
        if meta_path.exists() and meta:
            meta["output_summary"] = result
            save_json(meta_path, meta)

    return result


def _print_status(project):
    """Print project status."""
    from core.run import load_run_metadata

    print(f"Project: {project.name}")
    if project.description:
        print(f"Description: {project.description}")
    print(f"Target: {project.target}")
    print(f"Output: {project.output_dir}")
    print(f"Created: {project.created[:10] if project.created else 'unknown'}")
    if project.notes:
        print(f"Notes: {project.notes}")

    runs = project.get_run_dirs(sweep=False)
    if runs:
        print(f"\nRuns: {len(runs)}")
        name_col = max(max(len(d.name) for d in runs) + 2, 20)
        for d in runs:
            meta = load_run_metadata(d)
            cmd = meta.get("command", "?") if meta else "?"
            status = meta.get("status", "?") if meta else "?"
            findings_str = _get_output_summary(d, meta)
            if status == "completed":
                status_str = _green(status)
            elif status == "failed":
                status_str = _red(status)
            elif status == "running":
                status_str = _yellow(status)
            else:
                status_str = status
            print(f"  {d.name:<{name_col}s}  {cmd:12s}  {findings_str:24s}  {status_str}")
        # Disk usage — skip symlinks to avoid following outside the project
        total_size = 0
        for d in runs:
            for f in d.rglob("*"):
                if f.is_file() and not f.is_symlink():
                    try:
                        total_size += f.stat().st_size
                    except OSError:
                        pass
        if total_size >= 1024 * 1024:
            print(f"\nDisk usage: {total_size / 1024 / 1024:.1f}MB")
        elif total_size >= 1024:
            print(f"\nDisk usage: {total_size / 1024:.1f}KB")
        else:
            print(f"\nDisk usage: {total_size}B")

    else:
        print("\nNo runs.")


def _print_coverage(project, detailed=False, fail_under=None):
    """Print project coverage summary or detailed view."""
    from core.coverage.summary import (
        compute_project_summary,
        coverage_threshold_met,
        format_detailed,
        format_summary,
        format_threshold_result,
    )
    summary = compute_project_summary(project)
    if not summary:
        print("No coverage data (no checklist or coverage records found).")
        return False if fail_under is not None else None
    if detailed:
        print(format_detailed(summary))
    else:
        print(format_summary(summary))
    if fail_under is not None:
        print()
        print(format_threshold_result(summary, fail_under))
        return coverage_threshold_met(summary, fail_under)
    return None


def _print_findings(project, detailed=False):
    """Print merged findings across all runs, grouped by vuln."""
    from .merge import merge_findings
    from .findings_utils import count_vulns, group_findings
    from core.reporting.findings import build_findings_summary, findings_summary_line
    from core.reporting.formatting import get_display_status, title_case_type, truncate_path

    run_dirs = project.get_run_dirs(sweep=False)
    merged = merge_findings(run_dirs)

    if not merged:
        print("No findings.")
        return

    vuln_count = count_vulns(merged)
    counts = build_findings_summary(merged)
    groups = group_findings(merged)

    # Summary line
    print(findings_summary_line(counts, vuln_count).replace("**", ""))
    print()

    # Build grouped rows: one row per vuln
    grouped_rows = []  # (file_loc, type, status, cvss, findings_list)
    for key, findings in groups.items():
        # Use the first finding for display, pick best status/cvss across group
        rep = findings[0]  # representative finding
        fpath = rep.get("file", "")
        fname = fpath.rsplit("/", 1)[-1] if "/" in fpath else fpath

        # Lines: show all lines in the group
        lines_in_group = sorted(set(f.get("line", 0) for f in findings))
        if len(lines_in_group) == 1:
            loc = f"{fname}:{lines_in_group[0]}"
        else:
            loc = f"{fname}:{','.join(str(l) for l in lines_in_group)}"
        loc = truncate_path(loc) if loc else "—"

        vtype = title_case_type(rep.get("vuln_type", ""))
        status = get_display_status(rep)

        cvss = rep.get("cvss_score_estimate")
        cvss_str = str(cvss) if cvss is not None else "—"

        grouped_rows.append((loc, vtype, status, cvss_str, findings, fpath))

    grouped_rows.sort(key=lambda r: (r[5], min(f.get("line", 0) for f in r[4])))

    # Compact table
    headers = ("File", "Type", "Status", "CVSS")
    widths = [len(h) for h in headers]
    for row in grouped_rows:
        for i, cell in enumerate(row[:4]):
            widths[i] = max(widths[i], len(cell))

    fmt = f"  {{:<{widths[0]}s}}  {{:<{widths[1]}s}}  {{:<{widths[2]}s}}  {{:>{widths[3]}s}}"
    print(fmt.format(*headers))
    print(f"  {'-' * widths[0]}  {'-' * widths[1]}  {'-' * widths[2]}  {'-' * widths[3]}")
    for row in grouped_rows:
        print(fmt.format(*row[:4]))

    if not detailed:
        return

    # Detailed view: per-vuln reasoning, proof, PoC
    print()
    pad = len(str(len(grouped_rows)))
    indent = " " * (pad + 5)  # aligns with text after "  [XX] "
    for i, (loc, vtype, status, cvss_str, findings, _) in enumerate(grouped_rows, 1):
        print(f"  [{i:0{pad}d}] {loc} — {vtype} ({status})")

        # Use representative finding for details
        rep = findings[0]

        # Reasoning (stage summaries or analysis)
        reasoning = (
            rep.get("stage_d_summary")
            or rep.get("stage_b_summary")
            or rep.get("candidate_reasoning")
            or rep.get("reasoning")
        )
        if reasoning and isinstance(reasoning, str):
            rlines = reasoning.strip().split("\n")[:2]
            for ln in rlines:
                print(f"{indent}{ln.strip()}")

        # Proof
        proof_source = rep.get("proof_source")
        proof_sink = rep.get("proof_sink")
        if proof_source or proof_sink:
            parts = []
            if proof_source:
                parts.append(f"source: {proof_source}")
            if proof_sink:
                parts.append(f"sink: {proof_sink}")
            print(f"{indent}Proof: {', '.join(parts)}")

        print()


def _finding_label(f):
    """Location-based label for a finding."""
    return f"{f.get('file', '?')}:{f.get('function', '?')}:{f.get('line', '?')}"


def _print_diff(result):
    """Print diff results."""
    if result["new"]:
        print(f"New ({len(result['new'])}):")
        for f in result["new"]:
            print(_green(f"  + {_finding_label(f)}"))
    if result["removed"]:
        print(f"Removed ({len(result['removed'])}):")
        for f in result["removed"]:
            print(_red(f"  - {_finding_label(f)}"))
    if result["changed"]:
        print(f"Changed ({len(result['changed'])}):")
        for c in result["changed"]:
            print(_yellow(f"  ~ {c['label']} ({c.get('status_before', '?')} → {c.get('status_after', '?')})"))
    print(f"Unchanged: {result['unchanged']}")


def _do_correlate(project, json_out=False):
    """Cross-run finding correlation — action-oriented output."""
    import json
    from .correlate import correlate_project

    result = correlate_project(project)
    summary = result["summary"]

    if json_out:
        print(json.dumps(result, indent=2))
        return

    print(f"Project: {project.name}")
    parts = [f"Runs: {summary['runs']}", f"Findings: {summary['total_unique_findings']}"]
    if summary["disagreements"]:
        parts.append(f"Disagreements: {summary['disagreements']}")
    if summary["new_findings"]:
        parts.append(f"New: {summary['new_findings']}")
    if summary["potentially_resolved"]:
        parts.append(f"Resolved?: {summary['potentially_resolved']}")
    print(f"  {' | '.join(parts)}")

    # --- Actions (primary output) ---
    actions = result["actions"]
    if actions:
        _SIGILS = {
            "disagreement": "[!]",
            "new_finding": "[+]",
            "resolved": "[~]",
            "tool_gap": "[>]",
        }
        print(f"\n  Actions ({len(actions)})")
        print(f"  {'─' * 60}")
        for a in actions[:10]:
            sigil = _SIGILS.get(a["category"], "[?]")
            label = a["category"].upper().replace("_", " ")
            print(f"  {sigil} {label}  {a['summary']}")
            detail = a.get("detail", {})
            if a["category"] == "disagreement":
                for v in detail.get("verdicts", []):
                    m = f" ({v['model']})" if v.get("model") else ""
                    print(f"      {v['run']}: {v['status']}{m}")
            elif a["category"] == "resolved":
                absent = detail.get("absent_from", [])
                if absent:
                    print(f"      absent from: {', '.join(absent)}")
        if len(actions) > 10:
            print(f"  ... and {len(actions) - 10} more (use --json for full list)")
    else:
        print("\n  No actions — findings are consistent across runs.")

    # --- Suggested next runs ---
    suggested = result.get("tool_gaps", {}).get("suggested_next_runs", [])
    if suggested:
        print(f"\n  Next steps:")
        for cmd in suggested:
            print(f"    → {cmd}")

    # --- Persistent findings (compact) ---
    persistent = result["persistent_findings"]
    if persistent:
        display = persistent[:10]
        rows = []
        for pf in display:
            models = ", ".join(pf.get("models", [])) or "—"
            rows.append((
                f"{pf['file']}:{pf['line']}" if pf.get("file") else "?",
                pf.get("vuln_type", ""),
                pf.get("status", ""),
                f"{pf['runs_seen']} runs",
                models,
            ))
        headers = ("Location", "Type", "Status", "Seen", "Models")
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(cell))
        fmt = (f"  {{:<{widths[0]}s}}  {{:<{widths[1]}s}}  {{:<{widths[2]}s}}"
               f"  {{:>{widths[3]}s}}  {{:<{widths[4]}s}}")
        print(f"\n  Persistent ({len(persistent)}):")
        print(fmt.format(*headers))
        print(f"  {'-' * widths[0]}  {'-' * widths[1]}  {'-' * widths[2]}  {'-' * widths[3]}  {'-' * widths[4]}")
        for row in rows:
            print(fmt.format(*row))
        if len(persistent) > 10:
            print(f"  ... and {len(persistent) - 10} more")

    # --- Tool coverage (one line) ---
    tool_cov = result["tool_coverage"]
    if tool_cov:
        cov_parts = [f"{tool}: {len(files)}" for tool, files in tool_cov.items()]
        print(f"\n  Coverage: {', '.join(cov_parts)} files")


def _do_clean(project, keep, dry_run, yes):
    """Clean old runs from a project."""
    from .clean import plan_clean, execute_clean

    plan = plan_clean(project, keep=keep)

    if not plan["deleted"]:
        print("Nothing to clean.")
        return

    # Per-type breakdown
    for cmd_type, info in plan["by_type"].items():
        if info["delete"] == 0:
            continue
        freed = info["freed_bytes"] / 1024 / 1024
        print(f"  {cmd_type}: {info['total']} → {info['keep']} ({freed:.1f}MB to free)")

    freed_mb = plan['freed_bytes'] / 1024 / 1024
    total_runs = len(plan['deleted']) + len(plan['kept'])
    print(f"\n  Total: {total_runs} runs → {len(plan['kept'])} runs ({freed_mb:.1f}MB to free)")

    if dry_run:
        print("\n(dry run — no changes)")
        return

    if not yes:
        if input("\nProceed? [y/N] ").lower() != "y":
            print("Cancelled.")
            return

    # Execute the exact plan that was shown — no re-query
    execute_clean(plan)
    for name in plan["deleted"]:
        print(_red(f"  Deleted: {name}"))
    print(f"Done. {len(plan['deleted'])} runs deleted ({freed_mb:.1f}MB freed)")


def _do_merge(project, merge_type, yes):
    """Merge runs per command type."""
    import shutil
    import time
    from datetime import datetime, timezone
    from .merge import merge_runs
    from core.json import save_json
    from core.run.metadata import RUN_METADATA_FILE

    groups = project.get_run_dirs_by_type()

    if merge_type != "all":
        groups = {k: v for k, v in groups.items() if k == merge_type}

    # Filter to groups that actually have something to merge
    mergeable = {k: v for k, v in groups.items() if len(v) >= 2}

    if not mergeable:
        print("Nothing to merge.")
        return

    # Show plan
    for cmd_type, dirs in mergeable.items():
        print(f"  {cmd_type}: {len(dirs)} runs → 1")

    if not yes:
        if input("\nProceed? [y/N] ").lower() != "y":
            print("Cancelled.")
            return

    groups = mergeable

    for cmd_type, dirs in groups.items():
        # Collision-prevention via unique_run_suffix — see core/run/output.py.
        merged_dir = project.output_path / f"{cmd_type}-{unique_run_suffix('-')}"

        try:
            stats = merge_runs(dirs, merged_dir)
        except Exception as e:
            print(f"  {cmd_type}: merge failed — {e}")
            print("  Source runs preserved.")
            continue

        try:
            save_json(merged_dir / RUN_METADATA_FILE, {
                "version": 1,
                "command": cmd_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "completed",
                "extra": {"merged_from": len(dirs), "unique_findings": stats["unique_findings"]},
            })
        except Exception as e:
            print(f"  {cmd_type}: warning — metadata write failed ({e}), proceeding anyway")

        # Delete source runs (continue on individual failures)
        failed_deletes = []
        for d in dirs:
            try:
                shutil.rmtree(d)
            except Exception as e:
                failed_deletes.append(f"{d.name}: {e}")
        if failed_deletes:
            for msg in failed_deletes:
                print(f"  {cmd_type}: warning — failed to delete {msg}")

        vuln_count = stats.get("unique_vulns", stats["unique_findings"])
        if vuln_count != stats["unique_findings"]:
            findings_label = f"{vuln_count} findings"
        else:
            findings_label = f"{stats['unique_findings']} findings"
        print(f"  {cmd_type}: merged {stats['runs_merged']} runs ({findings_label})")
