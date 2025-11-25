#!/usr/bin/env python3
"""
RAPTOR Crash Analysis

Deep root-cause analysis for crashes from bug reports or fuzzing output.

Usage:
    # External bug mode
    python3 raptor_crash_analysis.py --bug-url <url> --git-url <repo_url>

    # Local crash mode (from fuzzing)
    python3 raptor_crash_analysis.py --crash-dir <path> --repo <path>

Examples:
    # Analyze a GitHub issue
    python3 raptor_crash_analysis.py \\
        --bug-url https://github.com/foo/bar/issues/123 \\
        --git-url https://github.com/foo/bar.git

    # Analyze crashes from fuzzing
    python3 raptor_crash_analysis.py \\
        --crash-dir out/fuzz_target/crashes \\
        --repo /path/to/source
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from packages.crash_analysis import CrashAnalysisOrchestrator
from packages.crash_analysis.orchestrator import CrashAnalysisConfig


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="RAPTOR Crash Analysis - Deep root-cause analysis for crashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a GitHub issue
  python3 raptor_crash_analysis.py \\
      --bug-url https://github.com/foo/bar/issues/123 \\
      --git-url https://github.com/foo/bar.git

  # Analyze a Trac ticket
  python3 raptor_crash_analysis.py \\
      --bug-url https://trac.example.org/ticket/456 \\
      --git-url https://github.com/example/project.git

  # Analyze crashes from fuzzing
  python3 raptor_crash_analysis.py \\
      --crash-dir out/fuzz_target_20241125/crashes \\
      --repo /path/to/source

  # Use custom build command
  python3 raptor_crash_analysis.py \\
      --bug-url https://github.com/foo/bar/issues/123 \\
      --git-url https://github.com/foo/bar.git \\
      --build-cmd "make CFLAGS='-fsanitize=address -g'"
        """
    )

    # Input mode: External bug
    external_group = parser.add_argument_group("External Bug Mode")
    external_group.add_argument(
        "--bug-url",
        type=str,
        help="URL to the bug report (GitHub issue, GitLab issue, Trac ticket, etc.)",
    )
    external_group.add_argument(
        "--git-url",
        type=str,
        help="Git repository URL to clone for analysis",
    )

    # Input mode: Local crashes
    local_group = parser.add_argument_group("Local Crash Mode")
    local_group.add_argument(
        "--crash-dir",
        type=str,
        help="Path to local crash directory (e.g., from raptor fuzz output)",
    )
    local_group.add_argument(
        "--repo",
        type=str,
        help="Path to existing source repository",
    )

    # Build options
    build_group = parser.add_argument_group("Build Options")
    build_group.add_argument(
        "--branch",
        type=str,
        default="main",
        help="Git branch to checkout (default: main)",
    )
    build_group.add_argument(
        "--build-cmd",
        type=str,
        help="Custom build command (overrides auto-detection)",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o", "--output",
        type=str,
        help="Output directory (default: out/crash-analysis-<timestamp>)",
    )

    # Analysis options
    analysis_group = parser.add_argument_group("Analysis Options")
    analysis_group.add_argument(
        "--no-tracing",
        action="store_true",
        help="Disable function call tracing",
    )
    analysis_group.add_argument(
        "--no-coverage",
        action="store_true",
        help="Disable gcov coverage collection",
    )
    analysis_group.add_argument(
        "--no-rr",
        action="store_true",
        help="Disable rr recording",
    )

    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    """Validate argument combinations."""
    has_external = bool(args.bug_url or args.git_url)
    has_local = bool(args.crash_dir or args.repo)

    if has_external and has_local:
        print("Error: Cannot mix external bug mode with local crash mode")
        print("Use either (--bug-url + --git-url) or (--crash-dir + --repo)")
        sys.exit(1)

    if not has_external and not has_local:
        print("Error: Must specify either:")
        print("  - External bug mode: --bug-url <url> --git-url <repo_url>")
        print("  - Local crash mode: --crash-dir <path> --repo <path>")
        sys.exit(1)

    if has_external:
        if not args.bug_url:
            print("Error: --bug-url is required for external bug mode")
            sys.exit(1)
        if not args.git_url:
            print("Error: --git-url is required for external bug mode")
            sys.exit(1)

    if has_local:
        if not args.crash_dir:
            print("Error: --crash-dir is required for local crash mode")
            sys.exit(1)
        if not args.repo:
            print("Error: --repo is required for local crash mode")
            sys.exit(1)

        if not Path(args.crash_dir).exists():
            print(f"Error: Crash directory does not exist: {args.crash_dir}")
            sys.exit(1)
        if not Path(args.repo).exists():
            print(f"Error: Repository path does not exist: {args.repo}")
            sys.exit(1)


def main() -> int:
    """Main entry point."""
    args = parse_args()
    validate_args(args)

    print(r"""
    ____  ___    ____  __________  ____
   / __ \/   |  / __ \/_  __/ __ \/ __ \
  / /_/ / /| | / /_/ / / / / / / / /_/ /
 / _, _/ ___ |/ ____/ / / / /_/ / _, _/
/_/ |_/_/  |_/_/     /_/  \____/_/ |_|

        Crash Analysis Module
    """)

    # Create configuration
    config = CrashAnalysisConfig(
        bug_url=args.bug_url,
        git_url=args.git_url,
        crash_dir=Path(args.crash_dir) if args.crash_dir else None,
        repo_path=Path(args.repo) if args.repo else None,
        branch=args.branch,
        build_cmd=args.build_cmd,
        output_dir=Path(args.output) if args.output else None,
        enable_function_tracing=not args.no_tracing,
        enable_coverage=not args.no_coverage,
        enable_rr_recording=not args.no_rr,
    )

    # Run analysis
    try:
        orchestrator = CrashAnalysisOrchestrator(config)
        result = orchestrator.run()

        print("\n" + "=" * 60)
        print("CRASH ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"Status: {result.status}")
        print(f"Output directory: {result.working_dir}")

        if result.bug_report:
            print(f"Bug title: {result.bug_report.title}")

        if result.crashes:
            print(f"Crashes analyzed: {len(result.crashes)}")

        if result.confirmed_hypothesis:
            print(f"Confirmed hypothesis: {result.confirmed_hypothesis}")

        print("\nNext steps:")
        print("1. Review the analysis context in the output directory")
        print("2. Use /crash-analysis Claude command for interactive analysis")
        print("3. Claude agents will generate and validate root-cause hypotheses")

        return 0

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
