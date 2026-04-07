"""CLI entry point for run lifecycle commands.

Usage:
    python3 -m core.run start <command>          # prints output dir path
    python3 -m core.run complete <path>
    python3 -m core.run fail <path> [message]
    python3 -m core.run cancel <path>

Reads RAPTOR_PROJECT_DIR from env or .active symlink to determine
where to create the run directory. Prints the output path to stdout
for the caller to capture.
"""

import sys
from pathlib import Path

# core/run/__main__.py → core/ → raptor/ (repo root)
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.run.output import get_output_dir
from core.run.metadata import start_run, complete_run, fail_run, cancel_run


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(1)

    action = sys.argv[1]

    if action == "start":
        if len(sys.argv) < 3:
            print("Usage: python3 -m core.run start <command>", file=sys.stderr)
            sys.exit(1)
        command = sys.argv[2]
        out_dir = get_output_dir(command)
        start_run(out_dir, command)
        # Print path for caller to capture
        print(out_dir)

    elif action == "complete":
        if len(sys.argv) < 3:
            print("Usage: python3 -m core.run complete <path>", file=sys.stderr)
            sys.exit(1)
        complete_run(Path(sys.argv[2]))

    elif action == "fail":
        if len(sys.argv) < 3:
            print("Usage: python3 -m core.run fail <path> [message]", file=sys.stderr)
            sys.exit(1)
        error = sys.argv[3] if len(sys.argv) > 3 else None
        fail_run(Path(sys.argv[2]), error=error)

    elif action == "cancel":
        if len(sys.argv) < 3:
            print("Usage: python3 -m core.run cancel <path>", file=sys.stderr)
            sys.exit(1)
        cancel_run(Path(sys.argv[2]))

    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
