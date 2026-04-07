"""CLI entry point for `raptor project` subcommands.

Called directly from bin/raptor when `project` is the first argument.
No Claude Code, no LLM — pure Python.
"""

import argparse
import os
import sys
from pathlib import Path

from .findings_utils import get_finding_id
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

    # list
    sub.add_parser("list", help="Show all projects",
                   usage="raptor project list", **_F)

    # status
    p_status = sub.add_parser("status", help="Show project summary",
                              usage="raptor project status [<name>]", **_F)
    p_status.add_argument("name", nargs="?", help="Project name")

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
                print(f"This will delete {args.name} and its output ({size / 1024 / 1024:.1f}MB)")
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
                with tempfile.NamedTemporaryFile(suffix=".md", mode="w", delete=False) as tf:
                    tf.write(p.notes or "")
                    tf_path = tf.name
                try:
                    result = subprocess.run(shlex.split(editor) + [tf_path])
                    if result.returncode != 0:
                        print("Editor exited with error. Notes unchanged.")
                        return
                    new_notes = Path(tf_path).read_text().strip()
                    mgr.update_notes(args.name, new_notes)
                    print("Notes updated.")
                finally:
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
            print(f"  Merged findings: {stats['findings']}")

        elif args.subcommand == "export":
            from .export import export_project
            p = mgr.load(args.name)
            if not p:
                print(f"Project '{args.name}' not found.")
                return
            project_json = mgr.projects_dir / f"{args.name}.json"
            result = export_project(p.output_path, Path(args.path),
                                    project_json_path=project_json,
                                    force=args.force)
            print(f"Exported to {result['path']}")
            print(f"  sha256: {result['sha256']}")

        elif args.subcommand == "import":
            from .export import import_project, _sha256_file
            zip_path = Path(args.path)
            if args.sha256:
                actual = _sha256_file(zip_path)
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

    # 1. .active symlink (current truth — reflects mid-session `use` changes)
    active = mgr.get_active()
    if active:
        return active

    # 2. RAPTOR_PROJECT_NAME env var (launch-time, from bin/raptor -p)
    name = os.environ.get("RAPTOR_PROJECT_NAME", "")
    if name:
        return name

    # 3. RAPTOR_PROJECT_DIR reverse-lookup (legacy/manual use)
    project_dir = os.environ.get("RAPTOR_PROJECT_DIR", "")
    if project_dir:
        resolved = str(Path(project_dir).resolve())
        for p in mgr.list_projects():
            if str(Path(p.output_dir).resolve()) == resolved:
                return p.name
        return Path(project_dir).name

    return None


def _print_status(project):
    """Print project status."""
    from core.run import load_run_metadata
    from .findings_utils import load_findings_from_dir

    print(f"Project: {project.name}")
    if project.description:
        print(f"Description: {project.description}")
    print(f"Target: {project.target}")
    print(f"Output: {project.output_dir}")
    print(f"Created: {project.created[:10] if project.created else 'unknown'}")
    if project.notes:
        print(f"Notes: {project.notes}")

    runs = project.get_run_dirs()
    if runs:
        print(f"\nRuns: {len(runs)}")
        name_col = max(max(len(d.name) for d in runs) + 2, 20)
        for d in runs:
            meta = load_run_metadata(d)
            cmd = meta.get("command", "?") if meta else "?"
            status = meta.get("status", "?") if meta else "?"
            findings = load_findings_from_dir(d)
            findings_str = f"{len(findings)} findings" if findings else ""
            if status == "completed":
                status_str = _green(status)
            elif status == "failed":
                status_str = _red(status)
            elif status == "running":
                status_str = _yellow(status)
            else:
                status_str = status
            print(f"  {d.name:<{name_col}s}  {cmd:12s}  {findings_str:15s}  {status_str}")
        # Disk usage — skip symlinks to avoid following outside the project
        total_size = 0
        for d in runs:
            for f in d.rglob("*"):
                if f.is_file() and not f.is_symlink():
                    try:
                        total_size += f.stat().st_size
                    except OSError:
                        pass
        print(f"\nDisk usage: {total_size / 1024 / 1024:.1f}MB")
    else:
        print("\nNo runs.")


def _print_diff(result):
    """Print diff results."""
    if result["new"]:
        print(f"New ({len(result['new'])}):")
        for f in result["new"]:
            fid = get_finding_id(f) or "?"
            print(_green(f"  + {fid}"))
    if result["removed"]:
        print(f"Removed ({len(result['removed'])}):")
        for f in result["removed"]:
            fid = get_finding_id(f) or "?"
            print(_red(f"  - {fid}"))
    if result["changed"]:
        print(f"Changed ({len(result['changed'])}):")
        for c in result["changed"]:
            # Changed entries have their own "id" field from the diff wrapper
            print(_yellow(f"  ~ {c['id']} ({c.get('status_before', '?')} → {c.get('status_after', '?')})"))
    print(f"Unchanged: {result['unchanged']}")


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
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        merged_dir = project.output_path / f"{cmd_type}-{timestamp}"

        try:
            stats = merge_runs(dirs, merged_dir)
        except Exception as e:
            print(f"  {cmd_type}: merge failed — {e}")
            print(f"  Source runs preserved.")
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

        print(f"  {cmd_type}: merged {stats['runs_merged']} runs "
              f"({stats['unique_findings']} findings)")
