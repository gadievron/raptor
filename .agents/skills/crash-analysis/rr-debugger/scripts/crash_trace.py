#!/usr/bin/env python3
"""
Automate extraction of execution trace before crash using rr.
Supports both regular crashes and ASAN faults.
"""

import sys
import subprocess
import argparse


def extract_trace(trace_dir, steps=100, output_format="source", asan=False):
    """
    Extract execution trace from rr recording.
    
    Args:
        trace_dir: Path to rr trace directory (or None for latest)
        steps: Number of steps to go back before crash
        output_format: 'source' or 'assembly'
        asan: True if dealing with ASAN crash
    """
    
    # Build rr replay command
    cmd = ["rr", "replay"]
    if trace_dir:
        cmd.append(trace_dir)
    
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
    
    # Run rr replay with gdb commands
    try:
        result = subprocess.run(
            cmd,
            input=gdb_batch.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60
        )
        
        output = result.stdout.decode('utf-8', errors='replace')
        print(output)
        
        if result.returncode != 0:
            print(f"Warning: gdb exited with code {result.returncode}", file=sys.stderr)
            print(result.stderr.decode('utf-8', errors='replace'), file=sys.stderr)
        
    except subprocess.TimeoutExpired:
        print("Error: Command timed out after 60 seconds", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
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
    
    args = parser.parse_args()
    
    if args.asan:
        print("NOTE: For ASAN crashes, you must manually identify the last app frame.")
        print("This script provides a template. Consider running interactively.")
        print()
    
    extract_trace(args.trace_dir, args.steps, args.format, args.asan)


if __name__ == "__main__":
    main()
