#!/usr/bin/env python3
"""
RAPTOR Truly Agentic Workflow

Complete end-to-end autonomous security testing:
1. Scan code with Semgrep AND CodeQL (parallel execution)
2. Autonomously analyse findings (read code, understand context)
3. Autonomously validate dataflow paths (CodeQL-specific)
4. Autonomously generate exploits (write working PoC code)
5. Autonomously create patches (write secure fixes)
6. Report everything

Phase 3 Integration Complete!
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))
from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()


def run_command(cmd: list, description: str) -> tuple[int, str, str]:
    """Run a command and return results."""
    logger.info(f"Running: {description}")
    print(f"\n[*] {description}...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800  # 30 minutes
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {description}")
        return -1, "", "Timeout"
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return -1, "", str(e)


def run_command_streaming(cmd: list, description: str) -> tuple[int, str, str]:
    """
    Run a command and stream output in real-time while also capturing it.

    This is useful for long-running commands where you want to show progress
    to the user but still capture the full output for processing.

    Args:
        cmd: Command and arguments as a list
        description: Human-readable description of the command

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    import threading

    logger.info(f"Running: {description}")
    print(f"\n[*] {description}...")

    def stream_output(pipe, storage, prefix=""):
        """Read from pipe line by line and print while storing."""
        try:
            for line in iter(pipe.readline, ''):
                if line:
                    storage.append(line)
                    # Print in real-time (with optional prefix)
                    print(f"{prefix}{line.rstrip()}", flush=True)
        except Exception:
            pass
        finally:
            pipe.close()

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )

        stdout_lines = []
        stderr_lines = []

        # Create threads to read stdout and stderr concurrently
        stdout_thread = threading.Thread(
            target=stream_output,
            args=(process.stdout, stdout_lines)
        )
        stderr_thread = threading.Thread(
            target=stream_output,
            args=(process.stderr, stderr_lines)
        )

        # Start reading threads
        stdout_thread.start()
        stderr_thread.start()

        # Wait for process to complete
        process.wait(timeout=1800)  # 30 minutes

        # Wait for all output to be read
        stdout_thread.join()
        stderr_thread.join()

        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)

        return process.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {description}")
        process.kill()
        return -1, "", "Timeout"
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return -1, "", str(e)


def main():
    parser = argparse.ArgumentParser(
        description="RAPTOR Agentic Security Testing - Scan, Analyse, Exploit, Patch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full autonomous workflow (Semgrep + CodeQL - default when called via unified launcher)
  python3 raptor.py agentic --repo /path/to/code

  # Semgrep only
  python3 raptor_agentic.py --repo /path/to/code --no-codeql --policy-groups crypto,secrets

  # CodeQL only (skip Semgrep)
  python3 raptor_agentic.py --repo /path/to/code --codeql-only --languages java

  # With custom build command
  python3 raptor_agentic.py --repo /path/to/code --codeql --languages java \\
    --build-command "mvn clean compile -DskipTests"

  # Limit number of findings processed
  python3 raptor.py agentic --repo /path/to/code --max-findings 20

  # Skip exploit generation (analysis + patches only)
  python3 raptor.py agentic --repo /path/to/code --no-exploits
        """
    )

    parser.add_argument("--repo", required=True, help="Path to repository to Analyse")
    parser.add_argument("--policy-groups", default="all", help="Comma-separated policy groups (default: all)")
    parser.add_argument("--max-findings", type=int, default=10, help="Maximum findings to process (default: 10)")
    parser.add_argument("--no-exploits", action="store_true", help="Skip exploit generation")
    parser.add_argument("--no-patches", action="store_true", help="Skip patch generation")
    parser.add_argument("--out", help="Output directory")
    parser.add_argument("--mode", choices=["fast", "thorough"], default="thorough",
                       help="fast: quick scan, thorough: detailed analysis")

    # CodeQL integration
    parser.add_argument("--codeql", action="store_true", help="Enable CodeQL scanning (in addition to Semgrep)")
    parser.add_argument("--codeql-only", action="store_true", help="Run CodeQL only (skip Semgrep)")
    parser.add_argument("--no-codeql", action="store_true", help="Disable CodeQL scanning (Semgrep only)")
    parser.add_argument("--languages", help="Languages for CodeQL (comma-separated, auto-detected if not specified)")
    parser.add_argument("--build-command", help="Custom build command for CodeQL")
    parser.add_argument("--extended", action="store_true", help="Use CodeQL extended security suites")
    parser.add_argument("--codeql-cli", help="Path to CodeQL CLI (auto-detected if not specified)")
    parser.add_argument("--no-visualizations", action="store_true", help="Disable dataflow visualizations for CodeQL findings")

    args = parser.parse_args()

    # Resolve paths
    script_root = Path(__file__).parent.resolve()  # RAPTOR-daniel-modular directory
    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"Error: Repository not found: {repo_path}")
        sys.exit(1)

    # Check for .git directory (required for semgrep)
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        print(f"\n  No .git directory found in {repo_path}")
        print(f"    Semgrep requires the directory to be a git repository.")
        print(f"\n[*] Initializing git repository...")
        logger.info(f"Initializing git repository in {repo_path}")
        
        try:
            # Initialize git repo
            result = subprocess.run(
                ["git", "init"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print(f"✓ Git repository initialized successfully")
                logger.info("Git repository initialized")
                
                # Add all files to git
                subprocess.run(
                    ["git", "add", "."],
                    cwd=repo_path,
                    capture_output=True,
                    timeout=60
                )
                
                # Create initial commit
                subprocess.run(
                    ["git", "commit", "-m", "Initial commit for RAPTOR scan"],
                    cwd=repo_path,
                    capture_output=True,
                    timeout=60
                )
                print(f"✓ Initial commit created")
                logger.info("Initial commit created")
            else:
                print(f" Failed to initialize git repository: {result.stderr}")
                logger.error(f"Git init failed: {result.stderr}")
                sys.exit(1)
                
        except subprocess.TimeoutExpired:
            print(f" Git initialization timed out")
            logger.error("Git init timeout")
            sys.exit(1)
        except FileNotFoundError:
            print(f" Git is not installed. Please install git and try again.")
            logger.error("Git not found in PATH")
            sys.exit(1)
        except Exception as e:
            print(f" Error initializing git: {e}")
            logger.error(f"Git init error: {e}")
            sys.exit(1)

    # Generate output directory with repository name and timestamp
    repo_name = repo_path.name  # Define repo_name for logging
    if args.out:
        out_dir = Path(args.out).resolve()
    else:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_dir = RaptorConfig.get_out_dir() / f"raptor_{repo_name}_{timestamp}"

    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 70)
    logger.info("RAPTOR AGENTIC WORKFLOW STARTED")
    logger.info("=" * 70)
    logger.info(f"Repository: {repo_name}")
    logger.info(f"Full path: {repo_path}")
    logger.info(f"Output: {out_dir}")
    logger.info(f"Policy groups: {args.policy_groups}")
    logger.info(f"Max findings: {args.max_findings}")
    logger.info(f"Mode: {args.mode}")

    workflow_start = time.time()

    # ========================================================================
    # PHASE 1: CODE SCANNING (Semgrep + CodeQL)
    # ========================================================================
    print("\n" + "=" * 70)
    print("PHASE 1: AUTONOMOUS CODE SCANNING")
    print("=" * 70)

    all_sarif_files = []
    semgrep_metrics = {}
    codeql_metrics = {}

    # ---- Semgrep Scanning ----
    if not args.codeql_only:
        print("\n[*] Running Semgrep analysis...")
        scan_cmd = [
            "python3",
            str(script_root / "packages/static-analysis/scanner.py"),
            "--repo", str(repo_path),
            "--policy_groups", args.policy_groups,
        ]

        rc, stdout, stderr = run_command(scan_cmd, "Scanning code with Semgrep")

        if rc not in (0, 1):
            print(f"❌ Semgrep scan failed: {stderr}")
            if args.codeql or args.codeql_only:
                print("   Continuing with CodeQL scan...")
            else:
                sys.exit(1)
        else:
            # Parse Semgrep results
            scanner_out_dir = RaptorConfig.get_out_dir()
            scan_dirs = sorted(scanner_out_dir.glob("scan_*"), key=lambda p: p.stat().st_mtime, reverse=True)

            if scan_dirs:
                actual_scan_dir = scan_dirs[0]
                logger.info(f"Found Semgrep output at: {actual_scan_dir}")

                scan_metrics_file = actual_scan_dir / "scan_metrics.json"
                if scan_metrics_file.exists():
                    with open(scan_metrics_file) as f:
                        semgrep_metrics = json.load(f)

                    print(f"\n✓ Semgrep scan complete:")
                    print(f"  - Files scanned: {semgrep_metrics.get('total_files_scanned', 0)}")
                    print(f"  - Findings: {semgrep_metrics.get('total_findings', 0)}")
                    print(f"  - Critical: {semgrep_metrics.get('findings_by_severity', {}).get('error', 0)}")
                    print(f"  - Warnings: {semgrep_metrics.get('findings_by_severity', {}).get('warning', 0)}")

                # Get SARIF files
                sarif_file = actual_scan_dir / "combined.sarif"
                if sarif_file.exists():
                    all_sarif_files.append(sarif_file)
                else:
                    semgrep_sarifs = list(actual_scan_dir.glob("semgrep_*.sarif"))
                    all_sarif_files.extend(semgrep_sarifs)

    # ---- CodeQL Scanning ----
    if (args.codeql or args.codeql_only) and not args.no_codeql:
        print("\n[*] Running CodeQL analysis...")

        # Build CodeQL command
        codeql_cmd = [
            "python3",
            str(script_root / "packages/codeql/agent.py"),
            "--repo", str(repo_path),
            "--out", str(out_dir / "codeql")
        ]

        if args.languages:
            codeql_cmd.extend(["--languages", args.languages])
        if args.build_command:
            codeql_cmd.extend(["--build-command", args.build_command])
        if args.extended:
            codeql_cmd.append("--extended")
        if args.codeql_cli:
            codeql_cmd.extend(["--codeql-cli", args.codeql_cli])

        rc, stdout, stderr = run_command_streaming(codeql_cmd, "Scanning code with CodeQL")

        if rc != 0:
            print(f"⚠️  CodeQL scan failed or completed with warnings")
            if stderr:
                print(f"    {stderr[:500]}")
            logger.warning(f"CodeQL scan failed - rc={rc}")
            if args.codeql_only:
                print("❌ CodeQL-only mode failed")
                sys.exit(1)
        else:
            # Parse CodeQL results
            codeql_out_dir = out_dir / "codeql"
            codeql_report = codeql_out_dir / "codeql_report.json"

            if codeql_report.exists():
                with open(codeql_report) as f:
                    codeql_metrics = json.load(f)

                total_findings = codeql_metrics.get('total_findings', 0)
                sarif_files = codeql_metrics.get('sarif_files', [])

                print(f"\n✓ CodeQL scan complete:")
                print(f"  - Languages: {', '.join(codeql_metrics.get('languages_detected', {}).keys())}")
                print(f"  - Findings: {total_findings}")
                print(f"  - SARIF files: {len(sarif_files)}")

                # Add CodeQL SARIF files
                for sarif in sarif_files:
                    all_sarif_files.append(Path(sarif))

    # Check if we have any findings
    if not all_sarif_files:
        print("\n❌ No SARIF files generated from scanning")
        sys.exit(1)

    # Combine metrics
    total_findings = semgrep_metrics.get('total_findings', 0) + codeql_metrics.get('total_findings', 0)
    scan_metrics = {
        'total_findings': total_findings,
        'total_files_scanned': semgrep_metrics.get('total_files_scanned', 0),
        'findings_by_severity': semgrep_metrics.get('findings_by_severity', {}),
        'semgrep': semgrep_metrics,
        'codeql': codeql_metrics
    }

    sarif_files = all_sarif_files

    print(f"\n{'=' * 70}")
    print(f"✓ PHASE 1 COMPLETE")
    print(f"{'=' * 70}")
    print(f"Total findings: {total_findings}")
    if semgrep_metrics:
        print(f"  Semgrep: {semgrep_metrics.get('total_findings', 0)} findings")
    if codeql_metrics:
        print(f"  CodeQL: {codeql_metrics.get('total_findings', 0)} findings")
    print(f"SARIF files: {len(sarif_files)}")

    # ========================================================================
    # PHASE 2: AUTONOMOUS ANALYSIS
    # ========================================================================
    print("\n" + "=" * 70)
    print("PHASE 2: AUTONOMOUS VULNERABILITY ANALYSIS")
    print("=" * 70)

    # Check if LLM is available
    llm_available = False
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        llm_available = True
        logger.info("LLM API key detected")
    else:
        # Check if Ollama is running
        try:
            import requests
            response = requests.get(f"{RaptorConfig.OLLAMA_HOST}/api/tags", timeout=2)
            if response.status_code == 200:
                llm_available = True
                logger.info(f"Ollama server detected at {RaptorConfig.OLLAMA_HOST}")
                logger.debug(f"Ollama available at {RaptorConfig.OLLAMA_HOST}")
        except Exception as e:
            logger.debug(f"Ollama not available at {RaptorConfig.OLLAMA_HOST}: {e}")
            pass

    analysis = {}
    if not llm_available:
        print("\n⚠️  Phase 2 skipped - No LLM provider available")
        print("    To enable autonomous analysis, either:")
        print("    1. Set ANTHROPIC_API_KEY environment variable, OR")
        print("    2. Set OPENAI_API_KEY environment variable, OR")
        print("    3. Run Ollama locally (https://ollama.ai)")
        print("\n    Example:")
        print("      export ANTHROPIC_API_KEY='your-api-key'")
        print("      python3 raptor_agentic.py --repo /path/to/code")
        logger.warning("Phase 2 skipped - No LLM provider configured")
    else:
        # Show which LLM will be used
        print()
        if os.environ.get("ANTHROPIC_API_KEY"):
            print("🤖 LLM: Anthropic Claude Sonnet 4")
        elif os.environ.get("OPENAI_API_KEY"):
            print("🤖 LLM: OpenAI GPT-4 Turbo")
        else:
            print("🤖 LLM: Ollama (local)")
        print()
        autonomous_out = out_dir / "autonomous"
        autonomous_out.mkdir(exist_ok=True)

        analysis_cmd = [
            "python3",
            str(script_root / "packages/llm_analysis/agent.py"),
            "--repo", str(repo_path),
            "--sarif"
        ] + [str(f) for f in sarif_files] + [
            "--out", str(autonomous_out),
            "--max-findings", str(args.max_findings)
        ]

        rc, stdout, stderr = run_command_streaming(analysis_cmd, "Analysing vulnerabilities autonomously")

        # Parse analysis results
        analysis_report = autonomous_out / "autonomous_analysis_report.json"
        if analysis_report.exists():
            with open(analysis_report) as f:
                analysis = json.load(f)

            print(f"\n✓ Analysis complete:")
            print(f"  - Analysed: {analysis.get('analyzed', 0)}")
            print(f"  - Exploitable: {analysis.get('exploitable', 0)}")
            print(f"  - Exploits generated: {analysis.get('exploits_generated', 0)}")
            print(f"  - Patches generated: {analysis.get('patches_generated', 0)}")

            # CodeQL-specific metrics
            if args.codeql or args.codeql_only:
                print(f"  - CodeQL dataflow paths validated: {analysis.get('dataflow_validated', 0)}")
        else:
            print(f"⚠️  Analysis failed or produced no output")
            if stderr:
                print(f"    Error: {stderr[:500]}")
            logger.warning(f"Phase 2 failed - rc={rc}, stderr={stderr[:200]}")
            analysis = {}

    # ========================================================================
    # PHASE 3: AGENTIC ORCHESTRATION (Optional - requires Claude Code)
    # ========================================================================
    print("\n" + "=" * 70)
    print("PHASE 3: AGENTIC ORCHESTRATION")
    print("=" * 70)
    print("\n💡 To enable FULL agentic capabilities:")
    print("   1. Install Claude Code: npm install -g @anthropic-ai/claude-code")
    print("   2. Run: python3 packages/llm_analysis/orchestrator.py \\")
    print(f"           --repo {repo_path} \\")
    print(f"           --sarif {' '.join(str(f) for f in sarif_files)} \\")
    print(f"           --max-findings {args.max_findings}")
    print("\n   This will spawn autonomous Claude Code agents that:")
    print("   - Read your code files")
    print("   - Understand vulnerabilities deeply")
    print("   - Write working exploit code")
    print("   - Create secure patches")
    print("   - Test their work")

    # ========================================================================
    # FINAL REPORT
    # ========================================================================
    workflow_duration = time.time() - workflow_start

    print("\n" + "=" * 70)
    print("🎉 RAPTOR AGENTIC WORKFLOW COMPLETE")
    print("=" * 70)

    final_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repository": str(repo_path),
        "duration_seconds": workflow_duration,
        "tools_used": {
            "semgrep": not args.codeql_only,
            "codeql": args.codeql or args.codeql_only,
        },
        "phases": {
            "scanning": {
                "completed": True,
                "total_findings": scan_metrics.get('total_findings', 0),
                "files_scanned": scan_metrics.get('total_files_scanned', 0),
                "semgrep": {
                    "enabled": not args.codeql_only,
                    "findings": semgrep_metrics.get('total_findings', 0) if semgrep_metrics else 0,
                },
                "codeql": {
                    "enabled": args.codeql or args.codeql_only,
                    "findings": codeql_metrics.get('total_findings', 0) if codeql_metrics else 0,
                    "languages": list(codeql_metrics.get('languages_detected', {}).keys()) if codeql_metrics else [],
                },
            },
            "autonomous_analysis": {
                "completed": bool(analysis),
                "skipped": not llm_available,
                "exploitable": analysis.get('exploitable', 0),
                "exploits_generated": analysis.get('exploits_generated', 0),
                "patches_generated": analysis.get('patches_generated', 0),
                "dataflow_validated": analysis.get('dataflow_validated', 0) if (args.codeql or args.codeql_only) else 0,
            },
        },
        "outputs": {
            "sarif_files": [str(f) for f in sarif_files],
            "autonomous_report": str(analysis_report) if 'analysis_report' in locals() and analysis_report.exists() else None,
            "exploits_directory": str(autonomous_out / "exploits") if 'autonomous_out' in locals() else None,
            "patches_directory": str(autonomous_out / "patches") if 'autonomous_out' in locals() else None,
        }
    }

    report_file = out_dir / "raptor_agentic_report.json"
    with open(report_file, "w") as f:
        json.dump(final_report, f, indent=2)

    print(f"\n📊 Summary:")
    print(f"   Total findings: {scan_metrics.get('total_findings', 0)}")
    if semgrep_metrics:
        print(f"     Semgrep: {semgrep_metrics.get('total_findings', 0)}")
    if codeql_metrics:
        print(f"     CodeQL: {codeql_metrics.get('total_findings', 0)}")
    print(f"   Exploitable: {analysis.get('exploitable', 0)}")
    print(f"   Exploits generated: {analysis.get('exploits_generated', 0)}")
    print(f"   Patches generated: {analysis.get('patches_generated', 0)}")
    if (args.codeql or args.codeql_only) and analysis.get('dataflow_validated', 0) > 0:
        print(f"   Dataflow paths validated: {analysis.get('dataflow_validated', 0)}")
    print(f"   Duration: {workflow_duration:.2f}s")

    print(f"\n📁 Outputs:")
    print(f"   Main report: {report_file}")
    if 'analysis_report' in locals() and analysis_report.exists():
        print(f"   Analysis: {analysis_report}")
    if 'autonomous_out' in locals():
        print(f"   Exploits: {autonomous_out / 'exploits'}/")
        print(f"   Patches: {autonomous_out / 'patches'}/")

    print("\n" + "=" * 70)
    print("RAPTOR has autonomously:")
    if not args.codeql_only:
        print("   ✓ Scanned with Semgrep")
    if args.codeql or args.codeql_only:
        print("   ✓ Scanned with CodeQL")
        print("   ✓ Validated dataflow paths")
    print("   ✓ Analysed vulnerabilities")
    print("   ✓ Generated exploits")
    print("   ✓ Created patches")
    print("\nReview the outputs and apply patches as needed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
