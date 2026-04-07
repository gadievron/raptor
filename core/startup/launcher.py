"""RAPTOR launcher — resolves active project and launches Claude Code.

Called by bin/raptor. Handles argument parsing, project resolution
(active symlink, auto-detect from cwd, -p flag), mismatch prompts,
and environment setup before exec-ing Claude Code.

Also routes `raptor project <subcommand>` directly to the project CLI.
"""

import os
import sys
from pathlib import Path

from . import REPO_ROOT as RAPTOR_DIR, PROJECTS_DIR, ACTIVE_LINK, get_active_name, sync_project_env_file

USAGE = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣀⣀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠿⠿⠟
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣤⣴⣶⣶⣶⣤⣿⡿⠁
⣀⠤⠴⠒⠒⠛⠛⠛⠛⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⣿⣿⣿⡟⠻⢿⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⢿⣿⠟⠀⠸⣊⡽
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⣿⡁⠀⠀⠀⠉⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠿⣿⣧

Usage: raptor [options] [target]
       raptor project <subcommand> [args]

Arguments:
  target             Path or URL to scan (optional)

Options:
  -c, --continue     Resume last RAPTOR session
  -m, --model MODEL  Choose model (opus, sonnet, haiku)
  -p, --project NAME Set the active project
  -v, --verbose      Verbose output
  -h, --help         Show this help

Projects:
  raptor project list              Show all projects
  raptor project create <name>     Create a new project
  raptor project status [<name>]   Show project summary
  raptor project use [<name>]      Set/show active project
  raptor project help              Full subcommand list

Any additional flags are passed through to claude.
""".strip()


# ---------------------------------------------------------------------------
# Project helpers
# ---------------------------------------------------------------------------

def _load_project_fields(name):
    """Read output_dir and target from a project JSON. Returns (dir, target) or None."""
    from core.json import load_json
    data = load_json(PROJECTS_DIR / f"{name}.json")
    if not data:
        return None
    return data.get("output_dir", ""), data.get("target", "")


def _activate(name):
    """Activate a project: set symlink, env vars, and sync CLAUDE_ENV_FILE.

    Returns True on success, False if project not found.
    """
    fields = _load_project_fields(name)
    if not fields:
        return False
    output_dir, target = fields

    # Set symlink
    if ACTIVE_LINK.is_symlink() or ACTIVE_LINK.exists():
        ACTIVE_LINK.unlink()
    ACTIVE_LINK.symlink_to(f"{name}.json")

    # Set env vars
    os.environ["RAPTOR_PROJECT_DIR"] = output_dir
    os.environ["RAPTOR_PROJECT_NAME"] = name
    os.environ["RAPTOR_PROJECT_TARGET"] = target

    sync_project_env_file()
    return True


def _deactivate():
    """Clear active project: remove symlink, env vars, and sync CLAUDE_ENV_FILE."""
    if ACTIVE_LINK.is_symlink() or ACTIVE_LINK.exists():
        ACTIVE_LINK.unlink()

    for var in ("RAPTOR_PROJECT_DIR", "RAPTOR_PROJECT_NAME", "RAPTOR_PROJECT_TARGET"):
        os.environ.pop(var, None)

    sync_project_env_file()


def _find_project_for(directory, exclude=None):
    """Find a project whose target matches directory. Returns name or None."""
    from core.project import ProjectManager
    project = ProjectManager().find_project_for_target(directory)
    if project and project.name != exclude:
        return project.name
    return None


# ---------------------------------------------------------------------------
# Mismatch prompt
# ---------------------------------------------------------------------------

def _check_mismatch(caller_dir):
    """If cwd doesn't match active project and another project does, prompt."""
    project_target = os.environ.get("RAPTOR_PROJECT_TARGET", "")
    project_name = os.environ.get("RAPTOR_PROJECT_NAME", "")
    if not project_target:
        return

    try:
        resolved_caller = Path(caller_dir).resolve()
        resolved_target = Path(project_target).resolve()
    except OSError:
        return

    if resolved_caller == resolved_target:
        return

    other = _find_project_for(caller_dir, exclude=project_name)
    if not other:
        return

    print(f"""
  Active project is {project_name} ({project_target})
  You are in {other}'s target directory ({caller_dir})

  Continue with:
    1) {project_name}
    2) {other}
    3) no project

  or enter anything else to quit
""")
    try:
        choice = input("  Choice [1]: ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)

    if choice == "1":
        pass
    elif choice == "2":
        if _activate(other):
            print(f"  Switched to {other}")
    elif choice == "3":
        _deactivate()
        print("  No active project")
    else:
        sys.exit(0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]

    # --- Route `raptor project` to Python CLI ---
    if args and args[0] == "project":
        from core.project.cli import main as project_main
        sys.argv = ["raptor-project"] + args[1:]
        project_main()
        return

    # --- Parse arguments ---
    claude_args = ["-n", "RAPTOR"]
    initial_prompt = "/raptor"
    target = ""

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-h", "--help", "help"):
            print(USAGE)
            return
        elif arg in ("-c", "--continue"):
            claude_args.append("--continue")
            initial_prompt = ""
        elif arg in ("-m", "--model"):
            if i + 1 >= len(args):
                print("  -m requires a model name", file=sys.stderr)
                sys.exit(1)
            claude_args.extend(["--model", args[i + 1]])
            i += 1
        elif arg in ("-v", "--verbose"):
            claude_args.append("--verbose")
        elif arg in ("-p", "--project"):
            if i + 1 >= len(args):
                print("  -p requires a project name", file=sys.stderr)
                sys.exit(1)
            if not _activate(args[i + 1]):
                print(f"  Project '{args[i + 1]}' not found", file=sys.stderr)
                sys.exit(1)
            i += 1
        elif arg.startswith("-"):
            claude_args.append(arg)
        else:
            target = f"{target} {arg}".strip() if target else arg
        i += 1

    if target and initial_prompt:
        initial_prompt = f"/raptor {target}"

    # --- Resolve active project ---
    caller_dir = os.environ.get("RAPTOR_CALLER_DIR", str(Path.cwd()))
    auto_activated = False

    if not os.environ.get("RAPTOR_PROJECT_DIR"):
        # Try .active symlink
        active_name = get_active_name()
        if active_name:
            _activate(active_name)
        else:
            # Auto-detect from cwd
            auto_name = _find_project_for(caller_dir)
            if auto_name and _activate(auto_name):
                os.environ["RAPTOR_PROJECT_AUTO"] = "1"
                auto_activated = True

    # --- Mismatch prompt ---
    if os.environ.get("RAPTOR_PROJECT_DIR") and not auto_activated:
        _check_mismatch(caller_dir)

    # --- Add bin/ to PATH ---
    bin_dir = str(RAPTOR_DIR / "bin")
    path = os.environ.get("PATH", "")
    if bin_dir not in path:
        os.environ["PATH"] = f"{path}:{bin_dir}"

    # --- Launch Claude Code ---
    if initial_prompt:
        os.execvp("claude", ["claude", initial_prompt] + claude_args)
    else:
        os.execvp("claude", ["claude"] + claude_args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"raptor: {e}", file=sys.stderr)
        sys.exit(1)
