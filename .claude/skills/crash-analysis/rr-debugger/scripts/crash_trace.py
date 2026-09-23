#!/usr/bin/env python3
"""
Automate extraction of execution trace before crash using rr.
Supports both regular crashes and ASAN faults.
"""

import sys
import subprocess
import argparse


def extract_trace(trace_dir, steps: int=100, output_format: str="source", asan: bool=False) -> None:
    """
    Extract execution trace from rr recording.
    
    Args:
        trace_dir: Path to rr trace directory (or None for latest)
        steps: Number of steps to go back before crash
        output_format: 'source' or 'assembly'
        asan: True if dealing with ASAN crash
    """
    
    # Build rr replay command.  Everything after `--` is passed to
    # the debugger: real command-line hardening flags, applied BEFORE
    # gdb sources init files or loads any objfile.  Stdin-prepended
    # `set auto-load no` runs too late for startup-time auto-load
    # (gdb sources ~/.gdbinit and performs objfile auto-load —
    # including inlined .debug_gdb_scripts Python — before the first
    # stdin command executes). Modern gdb DOES apply the safe-path
    # check to embedded .debug_gdb_scripts (the objfile path is what
    # is vetted), so the default config declines them; these flags
    # matter for older gdb and for operator configs that widened
    # auto-load safe-path (the widening gdb's own decline warning
    # coaches users into) — belt-and-braces either way.
    gdb_hardening = [
        "-nx",                                   # no HOME/cwd init files
        "-iex", "set auto-load off",             # all auto-load kinds
        "-iex", "set auto-load python-scripts off",
        # Belt-and-braces: even if a later command re-enabled
        # auto-load, no directory is trusted (/dev/null can never
        # hold scripts).
        "-iex", "set auto-load safe-path /dev/null",
    ]
    cmd = ["rr", "replay"]
    if trace_dir:
        cmd.append(trace_dir)
    cmd.append("--")
    cmd.extend(gdb_hardening)

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
    
    # Run rr replay with gdb commands.
    #
    # Hardening in effect (this step runs UNSANDBOXED — rr needs
    # ptrace — so gdb's own auto-load surfaces are the containment):
    #   * `-nx` + the `-iex` auto-load-off flags above ride the gdb
    #     COMMAND LINE, so they apply before gdb sources any init
    #     file and before objfile auto-load (including inlined
    #     .debug_gdb_scripts Python from a hostile binary, which the
    #     safe-path check alone would not stop).  A stdin-prepended
    #     `set auto-load no` executes only after those startup steps
    #     and is kept purely as an in-session backstop.
    #   * Sanitised env: no LD_* / PYTHONPATH (gdb is a
    #     Python-extension host), and HOME points at a fresh empty
    #     directory, so no operator- or attacker-writable dotfiles
    #     are reachable even outside `-nx`'s coverage.
    #   * Neutral cwd: the same fresh directory — never a
    #     target-repo checkout that could carry `.gdbinit` or
    #     auto-loadable scripts.
    # Residual (documented, not mitigated here): the replayed target
    # code itself executes under this uid via rr; auto-load
    # hardening narrows gdb's script surfaces, it does not sandbox
    # the replay.
    try:
        # `import os` is module-level in the consumers but defensive
        # local import here keeps the script self-contained.
        import os as _os
        import tempfile as _tempfile
        neutral_dir = _tempfile.mkdtemp(prefix="rr-gdb-neutral-")
        safe_env = {
            k: v
            for k, v in _os.environ.items()
            if k in ("PATH", "USER", "TERM", "LANG", "LC_ALL")
        }
        # rr stores traces under $HOME/.local/share/rr by default —
        # keep the LOOKUP working when no trace_dir was given by
        # pointing _RR_TRACE_DIR at the real location while HOME
        # itself stays neutral.
        real_home = _os.environ.get("HOME", "")
        if real_home and "_RR_TRACE_DIR" not in _os.environ:
            safe_env["_RR_TRACE_DIR"] = _os.path.join(
                real_home, ".local", "share", "rr",
            )
        elif "_RR_TRACE_DIR" in _os.environ:
            safe_env["_RR_TRACE_DIR"] = _os.environ["_RR_TRACE_DIR"]
        safe_env["HOME"] = neutral_dir
        # In-session backstop only — startup-time suppression comes
        # from the command-line flags (see gdb_hardening above).
        gdb_batch_safe = (
            "set auto-load no\nset auto-load python-scripts off\n"
            + gdb_batch
        )
        result = subprocess.run(
            cmd,
            input=gdb_batch_safe.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            env=safe_env,
            cwd=neutral_dir,  # neutral, empty — never a repo checkout
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
    
    args = parser.parse_args()
    
    if args.asan:
        print("NOTE: For ASAN crashes, you must manually identify the last app frame.")
        print("This script provides a template. Consider running interactively.")
        print()
    
    extract_trace(args.trace_dir, args.steps, args.format, args.asan)


if __name__ == "__main__":
    main()
