#!/usr/bin/env python3
"""
Automate extraction of execution trace before crash using rr.
Supports both regular crashes and ASAN faults.
"""

import sys
import subprocess
import argparse

from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[5]))
import core.startup.process_init  # noqa: E402,F401
from packages.binary_analysis.rr_replay import replay  # noqa: E402
from core.sandbox import SandboxSetupError  # noqa: E402


def extract_trace(trace_dir, steps: int=100, output_format: str="source", asan: bool=False) -> int:
    """
    Extract execution trace from rr recording.
    
    Args:
        trace_dir: Path to rr trace directory (or None for latest)
        steps: Number of steps to go back before crash
        output_format: 'source' or 'assembly'
        asan: True if dealing with ASAN crash
    """
    
    # Build gdb commands
    gdb_commands = []
    
    if asan:
        # ASAN workflow: backtrace, find app frame, set breakpoint, reverse-continue
        gdb_commands.extend([
            "set pagination off",
            "set height 0",
            "run",  # Run to the crash
            "bt",   # Show backtrace
            # User must identify the last app frame manually, this is a template
            "echo \\n=== Navigate up to last app frame before ASAN runtime ===\\n",
            "frame",
        ])
    else:
        # Regular crash workflow: reverse-next N steps
        gdb_commands.extend([
            "set pagination off",
            "set height 0",
            "run",  # Run to the crash
            f"reverse-next {steps}",  # Go back N steps
        ])
    
    # Set display options
    if output_format == "assembly":
        gdb_commands.append("set disassemble-next-line on")
    
    # Add forward stepping commands to capture trace
    gdb_commands.extend([
        "echo \\n=== Execution trace (step forward to crash) ===\\n",
    ])
    
    for i in range(steps):
        if output_format == "source":
            gdb_commands.extend([
                f"echo \\n--- Step {i+1} ---\\n",
                "frame",
                "list",
                "info locals",
                "next",
            ])
        else:  # assembly
            gdb_commands.extend([
                f"echo \\n--- Step {i+1} ---\\n",
                "frame",
                "disassemble",
                "info registers",
                "nexti",
            ])
    
    # Create gdb batch commands
    gdb_batch = "\n".join(gdb_commands)
    
    try:
        gdb_batch_safe = (
            "set auto-load no\nset auto-load python-scripts off\n"
            + gdb_batch
        )
        result = replay(trace_dir, commands=gdb_batch_safe.encode(), timeout=60)

        output = result.stdout.decode('utf-8', errors='replace')
        print(output)
        
        if result.returncode != 0:
            print(f"Warning: gdb exited with code {result.returncode}", file=sys.stderr)
            print(result.stderr.decode('utf-8', errors='replace'), file=sys.stderr)
        return result.returncode

    except SandboxSetupError as error:
        print(f"rr replay refused: {error}", file=sys.stderr)
        raise SystemExit(3) from error
    except subprocess.TimeoutExpired:
        print("Error: Command timed out after 60 seconds", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract execution trace before crash from rr recording"
    )
    parser.add_argument(
        "trace_dir",
        nargs="?",
        default=None,
        help="Path to rr trace directory (default: latest recording)"
    )
    parser.add_argument(
        "-n", "--steps",
        type=int,
        default=100,
        help="Number of steps to trace (default: 100)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["source", "assembly"],
        default="source",
        help="Output format: source or assembly (default: source)"
    )
    parser.add_argument(
        "--asan",
        action="store_true",
        help="Handle ASAN crash (requires manual frame navigation)"
    )
    
    parser.add_argument('--interactive', action='store_true',
                        help='Open interactive GDB in the same contained rr replay')
    args = parser.parse_args()
    if args.interactive:
        try:
            result = replay(args.trace_dir, timeout=None)
        except SandboxSetupError as error:
            print(f"rr replay refused: {error}", file=sys.stderr)
            raise SystemExit(3) from error
        raise SystemExit(result.returncode)
    
    if args.asan:
        print("NOTE: For ASAN crashes, you must manually identify the last app frame.")
        print("This script provides a template. Consider running interactively.")
        print()
    
    raise SystemExit(extract_trace(args.trace_dir, args.steps, args.format, args.asan))


if __name__ == "__main__":
    main()
