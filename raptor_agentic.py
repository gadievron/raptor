#!/usr/bin/env python3
"""
RAPTOR Truly Agentic Workflow

Complete end-to-end autonomous security testing:
0. Pre-exploit mitigation analysis (optional)
1. Scan code with Semgrep and CodeQL (parallel)
2. Validate exploitability (filter false positives and unreachable code)
3. Analyse each finding (read code, understand context, assess impact)
4. Generate exploit PoCs for confirmed vulnerabilities
5. Create secure patches
6. Cross-finding analysis (structural grouping, shared root causes)
7. Multi-model consensus (when configured)
8. Report everything
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
                    # Strip [INFO] prefix for cleaner output.
                    # Keep [WARNING], [ERROR], [DEBUG] visible.
                    display = line.rstrip()
                    if display.startswith("[INFO] "):
                        display = display[7:]
                    print(f"{prefix}{display}", flush=True)
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


def _check_repo_claude_settings(repo_path: str) -> bool:
    """Check target repo for malicious .claude/settings.json.

    Claude Code's credential helpers execute shell commands from settings.
    A malicious repo could contain .claude/settings.json with injected
    helper values that exfiltrate credentials when Claude Code processes
    the workspace.
    Ref: CVE-2026-21852, Phoenix Security CWE-78 disclosure (2026-03-31).

    Returns True if dangerous helpers found (CC dispatch should be blocked).
    """
    # Don't flag RAPTOR's own settings when scanning ourselves
    raptor_dir = Path(__file__).resolve().parent
    target = Path(repo_path).resolve()
    if target == raptor_dir:
        return False

    claude_dir = target / ".claude"
    settings_files = [claude_dir / name for name in ("settings.json", "settings.local.json")
                      if (claude_dir / name).exists()]
    if not settings_files:
        return False

    try:
        import json

        print(f"\n{'=' * 70}")
        print("⚠️  TARGET REPO CONTAINS CLAUDE CODE SETTINGS")
        print(f"{'=' * 70}")

        # Check for known credential helper keys (shell-executed by Claude Code).
        # List based on Claude Code source (2026-03-31). May need updating.
        dangerous_keys = [
            "apiKeyHelper", "awsAuthHelper", "awsAuthRefresh", "gcpAuthRefresh",
        ]

        for settings_path in settings_files:
            print(f"   File: {settings_path}")
            if settings_path.stat().st_size > 1_000_000:
                print("   (skipped — file too large)")
                continue
            try:
                data = json.loads(settings_path.read_text())
            except (json.JSONDecodeError, UnicodeDecodeError):
                print("   (malformed — could not parse)")
                continue
            if isinstance(data, dict):
                for key in dangerous_keys:
                    val = data.get(key)
                    if val and isinstance(val, str):
                        display = val[:60] + "..." if len(val) > 60 else val
                        print(f"   ⚠️  {key}: {display}  (executed as shell command)")

        print()
        print("   A .claude/ directory in a third-party repo can configure Claude")
        print("   Code's behaviour in ways that may not be safe.")
        print()
        print("   RAPTOR's sub-agents use --add-dir (file access only, no settings")
        print("   loading), so RAPTOR's own dispatch is not directly vulnerable.")
        print("   If you used `bin/raptor` to launch, you are safe — it sets the")
        print("   working directory to the RAPTOR repo, not the target.")
        print("   If you ran `claude` directly from inside this repo, Claude Code")
        print("   may have already loaded these settings.")
        print()
        print("   RAPTOR will not dispatch Claude Code sub-agents for this repo")
        print("   as a precaution. Scanning and external LLM analysis proceed normally.")
        print("   Review and remove the files to enable CC dispatch.")
        print(f"{'=' * 70}\n")
        return True
    except Exception:
        pass
    return False


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

  # Skip exploitability validation (faster, but may include false positives)
  python3 raptor.py agentic --repo /path/to/code --skip-dedup

  # Focus validation on specific vulnerability type
  python3 raptor.py agentic --repo /path/to/code --vuln-type sql_injection
        """
    )

    parser.add_argument("--repo", default=os.environ.get("RAPTOR_CALLER_DIR"),
                        help="Path to repository to analyse (default: directory raptor was launched from)")
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

    # Mitigation analysis options (NEW)
    parser.add_argument("--binary", help="Target binary for mitigation analysis (enables pre-exploit checks)")
    parser.add_argument("--check-mitigations", action="store_true",
                       help="Run mitigation analysis before scanning (for binary exploit targets)")
    parser.add_argument("--skip-mitigation-checks", action="store_true",
                       help="Skip per-vulnerability mitigation checks during exploit generation")

    # Exploitability validation options
    parser.add_argument("--skip-dedup", action="store_true",
                       help="Skip deduplication (pass all scanner findings directly to analysis)")
    parser.add_argument("--vuln-type", help="Vulnerability type to focus on (e.g., command_injection, sql_injection)")

    # Orchestration options
    parser.add_argument("--max-parallel", type=int, default=3,
                       help="Maximum parallel Claude Code agents for Phase 4 orchestration (default: 3)")
    parser.add_argument("--sequential", action="store_true",
                       help="Sequential analysis in Phase 3 instead of parallel Phase 4 orchestration")

    args = parser.parse_args()

    if not args.repo:
        parser.error("--repo is required (or launch via `raptor` from the target directory)")
    if not Path(args.repo).exists():
        parser.error(f"--repo path does not exist: {args.repo}")

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
    if args.binary:
        logger.info(f"Target binary: {args.binary}")

    workflow_start = time.time()

    # Detect LLM availability once — single source of truth for all phases
    from packages.llm_analysis.llm.config import detect_llm_availability
    llm_env = detect_llm_availability()

    # ========================================================================
    # PHASE 0: PRE-EXPLOIT MITIGATION ANALYSIS (Optional but recommended)
    # ========================================================================
    mitigation_result = None
    if args.check_mitigations or args.binary:
        print("\n" + "=" * 70)
        print("MITIGATION ANALYSIS")
        print("=" * 70)
        print("\nChecking system and binary mitigations BEFORE scanning...")
        print("This prevents wasted effort on impossible exploits.\n")

        try:
            from packages.exploit_feasibility import analyze_binary, format_analysis_summary

            binary_path = str(Path(args.binary)) if args.binary else None
            mitigation_result = analyze_binary(binary_path, output_dir=str(out_dir))

            # Display formatted summary
            print(format_analysis_summary(mitigation_result, verbose=True))

            verdict = mitigation_result.get('verdict', 'unknown')
            if verdict == 'unlikely':
                print("\n" + "=" * 70)
                print("NOTE: EXPLOITATION UNLIKELY WITH CURRENT MITIGATIONS")
                print("=" * 70)
                print("\nContinuing scan anyway (for vulnerability discovery)...")

            elif verdict == 'difficult':
                print("\n" + "=" * 70)
                print("NOTE: EXPLOITATION DIFFICULT - REVIEW CONSTRAINTS ABOVE")
                print("=" * 70)

            else:
                print("\nMitigation check passed - exploitation may be feasible")

            logger.info(f"Mitigation analysis complete: {verdict}")

        except ImportError:
            print("Mitigation analysis module not available")
        except Exception as e:
            print(f"Mitigation check failed: {e}")
            logger.error(f"Mitigation check error: {e}")

    # ========================================================================
    # PRE-SCAN: Check target repo for malicious Claude Code settings
    # ========================================================================
    block_cc_dispatch = _check_repo_claude_settings(repo_path)

    # ========================================================================
    # PHASE 1: CODE SCANNING (Semgrep + CodeQL)
    # ========================================================================
    print("\n" + "=" * 70)
    print("SCANNING")
    print("=" * 70)

    # Build inventory checklist (independent of scanning, available to all phases)
    try:
        from core.inventory import build_inventory
        if not (out_dir / "checklist.json").exists():
            build_inventory(str(repo_path), str(out_dir))
            logger.info(f"Inventory checklist built: {out_dir / 'checklist.json'}")
    except Exception as e:
        logger.warning(f"Inventory build failed (continuing without metadata): {e}")

    all_sarif_files = []
    semgrep_metrics = {}
    codeql_metrics = {}

    # Launch scanners in parallel when both are enabled
    run_semgrep = not args.codeql_only
    run_codeql = (args.codeql or args.codeql_only) and not args.no_codeql

    semgrep_cmd = None
    codeql_cmd = None
    semgrep_proc = None
    codeql_proc = None

    if run_semgrep:
        print("\n[*] Running Semgrep analysis...")
        semgrep_cmd = [
            "python3",
            str(script_root / "packages/static-analysis/scanner.py"),
            "--repo", str(repo_path),
            "--policy_groups", args.policy_groups,
        ]
        logger.info(f"Running: Scanning code with Semgrep")
        semgrep_proc = subprocess.Popen(
            semgrep_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    if run_codeql:
        print("\n[*] Running CodeQL analysis...")
        codeql_cmd = [
            "python3",
            str(script_root / "packages/codeql/agent.py"),
            "--repo", str(repo_path),
            "--out", str(out_dir / "codeql"),
        ]
        if args.languages:
            codeql_cmd.extend(["--languages", args.languages])
        if args.build_command:
            codeql_cmd.extend(["--build-command", args.build_command])
        if args.extended:
            codeql_cmd.append("--extended")
        if args.codeql_cli:
            codeql_cmd.extend(["--codeql-cli", args.codeql_cli])
        logger.info(f"Running: Scanning code with CodeQL")
        codeql_proc = subprocess.Popen(
            codeql_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    # ---- Collect Semgrep results ----
    if semgrep_proc:
        try:
            semgrep_stdout, semgrep_stderr = semgrep_proc.communicate(timeout=1800)
            rc = semgrep_proc.returncode
        except subprocess.TimeoutExpired:
            semgrep_proc.kill()
            semgrep_proc.communicate()
            rc = -1
            print(f"❌ Semgrep scan timed out (30m)")
            logger.error("Semgrep scan timed out")
            if not run_codeql:
                sys.exit(1)

        if rc in (0, 1):
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

                sarif_file = actual_scan_dir / "combined.sarif"
                if sarif_file.exists():
                    all_sarif_files.append(sarif_file)
                else:
                    semgrep_sarifs = list(actual_scan_dir.glob("semgrep_*.sarif"))
                    all_sarif_files.extend(semgrep_sarifs)
        elif rc != -1:  # -1 is timeout, already reported
            print(f"❌ Semgrep scan failed (exit code {rc})")
            if not run_codeql:
                sys.exit(1)

    # ---- Collect CodeQL results ----
    if codeql_proc:
        try:
            codeql_stdout, codeql_stderr = codeql_proc.communicate(timeout=1800)
            rc = codeql_proc.returncode
        except subprocess.TimeoutExpired:
            codeql_proc.kill()
            codeql_proc.communicate()
            rc = -1
            print(f"❌ CodeQL scan timed out (30m)")
            logger.error("CodeQL scan timed out")

        if rc != 0:
            if all_sarif_files:
                print(f"⚠️  CodeQL scan failed — continuing with existing findings")
            else:
                print(f"⚠️  CodeQL scan failed — no findings from any scanner")
            logger.warning(f"CodeQL scan failed - rc={rc}")
            if args.codeql_only:
                print("❌ CodeQL-only mode failed")
                sys.exit(1)
        else:
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
        'codeql': codeql_metrics,
    }

    sarif_files = all_sarif_files

    print(f"\nTotal findings: {total_findings}")
    if semgrep_metrics:
        print(f"  Semgrep: {semgrep_metrics.get('total_findings', 0)} findings")
    if codeql_metrics:
        print(f"  CodeQL: {codeql_metrics.get('total_findings', 0)} findings")
    print(f"SARIF files: {len(sarif_files)}")

    # ========================================================================
    # PHASE 2: EXPLOITABILITY VALIDATION
    # ========================================================================
    # Run validation phase (handles all modes: skip, dedup-only, full validation)
    from packages.exploitability_validation import run_validation_phase

    validation_result, validated_findings = run_validation_phase(
        repo_path=str(repo_path),
        out_dir=out_dir,
        sarif_files=sarif_files,
        total_findings=total_findings,
        vuln_type=args.vuln_type,
        binary_path=args.binary,
        skip_dedup=args.skip_dedup,
        skip_feasibility=not (args.binary or args.check_mitigations),
        external_llm=llm_env.external_llm,
    )

    # ========================================================================
    # PHASE 3: AUTONOMOUS ANALYSIS
    # ========================================================================
    print("\n" + "=" * 70)
    print("PREPARING FINDINGS")
    print("=" * 70)

    analysis = {}
    autonomous_out = None
    analysis_report = None
    if not llm_env.llm_available:
        print("\n⚠️  Phase 3 skipped - No LLM provider available")
        print("    To enable autonomous analysis, either:")
        print("    1. Set ANTHROPIC_API_KEY environment variable, OR")
        print("    2. Set OPENAI_API_KEY / GEMINI_API_KEY / MISTRAL_API_KEY, OR")
        print("    3. Run Ollama locally (https://ollama.ai), OR")
        print("    4. Run inside Claude Code (claude)")
        logger.warning("Phase 3 skipped - No LLM provider configured")
    else:
        autonomous_out = out_dir / "autonomous"
        autonomous_out.mkdir(exist_ok=True)

        # Check if validation produced enriched findings
        validated_findings_path = out_dir / "validation" / "findings.json"
        if validated_findings_path.exists():
            logger.info("Using findings from Phase 2 for analysis")
            analysis_cmd = [
                "python3",
                str(script_root / "packages/llm_analysis/agent.py"),
                "--repo", str(repo_path),
                "--findings", str(validated_findings_path),
                "--out", str(autonomous_out),
                "--max-findings", str(args.max_findings)
            ]
        else:
            analysis_cmd = [
                "python3",
                str(script_root / "packages/llm_analysis/agent.py"),
                "--repo", str(repo_path),
                "--sarif"
            ] + [str(f) for f in sarif_files] + [
                "--out", str(autonomous_out),
                "--max-findings", str(args.max_findings)
            ]

        # Attach checklist for metadata lookup
        if (out_dir / "checklist.json").exists():
            analysis_cmd.extend(["--checklist", str(out_dir / "checklist.json")])

        # Phase 3 preps data; Phase 4 handles LLM work (unless --sequential)
        if (llm_env.claude_code or llm_env.external_llm) and not args.sequential:
            analysis_cmd.append("--prep-only")

        rc, stdout, stderr = run_command_streaming(analysis_cmd, "Preparing findings for analysis")

        # Parse analysis results
        analysis_report = autonomous_out / "autonomous_analysis_report.json"
        if analysis_report.exists():
            with open(analysis_report) as f:
                analysis = json.load(f)

            if analysis.get('mode') == 'prep_only':
                print(f"\n✓ {analysis.get('processed', 0)} findings prepared for analysis")
            else:
                print(f"\n✓ Analysis complete:")
                print(f"  - Analysed: {analysis.get('analyzed', 0)}")
                print(f"  - Exploitable: {analysis.get('exploitable', 0)}")
                print(f"  - Exploits generated: {analysis.get('exploits_generated', 0)}")
                print(f"  - Patches generated: {analysis.get('patches_generated', 0)}")

                if args.codeql or args.codeql_only:
                    print(f"  - CodeQL dataflow paths validated: {analysis.get('dataflow_validated', 0)}")
        else:
            print(f"⚠️  Analysis failed or produced no output")
            if stderr:
                print(f"    Error: {stderr[:500]}")
            logger.warning(f"Phase 3 failed - rc={rc}, stderr={stderr[:200]}")
            analysis = {}

    # ========================================================================
    # PHASE 4: AGENTIC ORCHESTRATION
    # ========================================================================
    orchestration_result = None
    if (llm_env.claude_code or llm_env.external_llm) and not args.sequential:
        print("\n" + "=" * 70)
        print("ANALYSING", flush=True)
        print("=" * 70)

        if analysis_report and analysis_report.exists():
            # Build LLMConfig if external LLM is available
            llm_config = None
            if llm_env.external_llm:
                from packages.llm_analysis.llm.config import LLMConfig
                llm_config = LLMConfig()

            from packages.llm_analysis.orchestrator import orchestrate
            orchestration_result = orchestrate(
                prep_report_path=analysis_report,
                repo_path=repo_path,
                out_dir=out_dir,
                max_parallel=args.max_parallel,
                max_findings=args.max_findings,
                no_exploits=args.no_exploits,
                no_patches=args.no_patches,
                llm_config=llm_config,
                block_cc_dispatch=block_cc_dispatch,
            )
        else:
            print("\n  No analysis report from Phase 3 — skipping orchestration")
    elif not llm_env.llm_available:
        print("\n  No LLM available. Findings prepared for manual review.")
        print("  For automated analysis, set an API key or install Claude Code.")

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
            "exploitability_validation": {
                "completed": bool(validation_result),
                "skipped": args.skip_dedup,
                "original_findings": total_findings,
                "validated_findings": validated_findings,
                "noise_reduction_percent": ((total_findings - validated_findings) / total_findings * 100) if total_findings > 0 else 0,
            },
            "autonomous_analysis": {
                "completed": bool(analysis),
                "skipped": not llm_env.llm_available,
                "exploitable": analysis.get('exploitable', 0),
                "exploits_generated": analysis.get('exploits_generated', 0),
                "patches_generated": analysis.get('patches_generated', 0),
                "dataflow_validated": analysis.get('dataflow_validated', 0) if (args.codeql or args.codeql_only) else 0,
            },
            "orchestration": orchestration_result.get("orchestration", {}) if orchestration_result else {
                "completed": False,
                "mode": "none",
            },
        },
        "outputs": {
            "sarif_files": [str(f) for f in sarif_files],
            "validation_report": str(out_dir / "validation" / "findings.json") if validation_result else None,
            "autonomous_report": str(analysis_report) if analysis_report and analysis_report.exists() else None,
            "orchestrated_report": str(out_dir / "orchestrated_report.json") if orchestration_result else None,
            "exploits_directory": str(autonomous_out / "exploits") if autonomous_out else None,
            "patches_directory": str(autonomous_out / "patches") if autonomous_out else None,
            "exploit_feasibility": str(out_dir / "exploit_feasibility.txt") if mitigation_result else None,
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
    # Build findings funnel from orchestration results
    analysed_count = 0
    true_positives = 0
    false_positives = 0
    exploitable_count = 0
    failed_count = 0
    blocked_count = 0
    severity_mismatches = []
    exploits_count = analysis.get('exploits_generated', 0)
    patches_count = analysis.get('patches_generated', 0)

    if orchestration_result:
        orch = orchestration_result.get("orchestration", {})
        analysed_count = orch.get("findings_analysed", 0)
        exploits_count = max(exploits_count, orchestration_result.get('exploits_generated', 0))
        patches_count = max(patches_count, orchestration_result.get('patches_generated', 0))
        for r in orchestration_result.get("results", []):
            if "error" in r:
                if r.get("error_type") == "blocked":
                    blocked_count += 1
                else:
                    failed_count += 1
                continue
            # Only count findings that were actually analysed (have explicit verdict)
            if "is_true_positive" not in r:
                continue
            if r.get("is_true_positive") is False:
                false_positives += 1
                # Flag severity mismatches: scanner says error/critical but LLM says false positive
                scanner_level = r.get("level", "")
                if scanner_level == "error":
                    severity_mismatches.append(r)
            else:
                true_positives += 1
            if r.get("is_exploitable"):
                exploitable_count += 1
    else:
        analysed_count = analysis.get('analyzed', 0)
        exploitable_count = analysis.get('exploitable', 0)

    # Post-process orchestration results: compute CVSS, infer CWE, fix severity
    if orchestration_result:
        _postprocess_findings(orchestration_result.get("results", []))
        # Write corrected results back to disk
        orch_report_path = out_dir / "orchestrated_report.json"
        if orch_report_path.exists():
            with open(orch_report_path, "w") as f:
                json.dump(orchestration_result, f, indent=2)

    # Findings funnel
    if validation_result:
        print(f"   After dedup: {validated_findings}")
        if total_findings > validated_findings:
            reduction = ((total_findings - validated_findings) / total_findings) * 100
            print(f"   Duplicates removed: {reduction:.0f}%")
    if analysed_count > 0 and analysed_count < validated_findings:
        skipped = validated_findings - analysed_count
        print(f"   Analysed: {analysed_count} of {validated_findings}")
        print(f"   ⚠️  {skipped} finding{'s' if skipped != 1 else ''} skipped (--max-findings {args.max_findings})")
    elif analysed_count > 0:
        print(f"   Analysed: {analysed_count}")
    if failed_count > 0 or blocked_count > 0:
        parts = []
        if blocked_count > 0:
            parts.append(f"{blocked_count} blocked by content filter")
        if failed_count > 0:
            parts.append(f"{failed_count} failed")
        print(f"   ⚠️  {', '.join(parts)}")
    if true_positives > 0 or false_positives > 0:
        print(f"   True positives: {true_positives}")
        if false_positives > 0:
            print(f"   False positives: {false_positives}")
    contradictions = sum(1 for r in orchestration_result.get("results", [])
                         if r.get("self_contradictory")) if orchestration_result else 0
    if contradictions > 0:
        print(f"   ⚠️  Self-contradictory: {contradictions} (review recommended)")
    if severity_mismatches:
        print(f"   ⚠️  {len(severity_mismatches)} high-severity finding{'s' if len(severity_mismatches) != 1 else ''} "
              f"ruled as false positive (review recommended)")
    print(f"   Exploitable: {exploitable_count}")
    if exploits_count > 0:
        print(f"   Exploits generated: {exploits_count}")
    if patches_count > 0:
        print(f"   Patches generated: {patches_count}")
    if (args.codeql or args.codeql_only) and analysis.get('dataflow_validated', 0) > 0:
        print(f"   Dataflow paths validated: {analysis.get('dataflow_validated', 0)}")
    from core.reporting import (
        FINDINGS_COLUMNS, render_console_table, render_report, build_findings_spec,
        build_findings_rows, build_findings_summary, findings_summary_line,
    )
    from core.reporting.formatting import format_elapsed
    print(f"   Duration: {format_elapsed(workflow_duration)}")
    if orchestration_result:
        cost_summary = orchestration_result.get("orchestration", {}).get("cost", {})
        cost = cost_summary.get("total_cost", 0)
        if cost > 0:
            thinking = cost_summary.get("thinking_tokens", 0)
            cost_str = f"   Cost: ${cost:.2f}"
            if thinking > 0:
                cost_str += f" ({thinking:,} thinking tokens)"
            print(cost_str)
            # Per-model breakdown if multiple models used
            by_model = cost_summary.get("cost_by_model", {})
            if len(by_model) > 1:
                for model, mcost in by_model.items():
                    print(f"     {model}: ${mcost:.2f}")

    print(f"\n📁 Outputs:")
    print(f"   Main report: {report_file}")
    if mitigation_result:
        print(f"   Exploit feasibility: {out_dir / 'exploit_feasibility.txt'}")
    # Dedup results are intermediate — don't list in user-facing outputs
    if analysis_report and analysis_report.exists():
        print(f"   Analysis: {analysis_report}")
    if exploits_count > 0 and autonomous_out:
        print(f"   Exploits: {autonomous_out / 'exploits'}/")
    if patches_count > 0 and autonomous_out:
        print(f"   Patches: {autonomous_out / 'patches'}/")

    # Filter to analysed results (used by both console table and report)
    results = orchestration_result.get("results", []) if orchestration_result else []
    analysed_results = [r for r in results if "is_true_positive" in r or "error" in r]

    # Results at a Glance table (matches /validate console output)
    if orchestration_result:
        if analysed_results:
            rows = build_findings_rows(analysed_results, filename_only=True)
            columns = FINDINGS_COLUMNS
            counts = build_findings_summary(analysed_results)
            footer = findings_summary_line(counts) + "\n\n  CVSS scores reflect inherent vulnerability impact — not binary mitigations."
            print(render_console_table(columns, rows, max_widths={3: 28, 4: 25}, footer=footer))

    print("\n" + "=" * 70)
    print("RAPTOR has autonomously:")
    if not args.codeql_only:
        print("   ✓ Scanned with Semgrep")
    if codeql_metrics:
        print("   ✓ Scanned with CodeQL")
        if codeql_metrics.get('total_findings', 0) > 0:
            print("   ✓ Validated dataflow paths")
    if validation_result:
        print("   ✓ Deduplicated findings")
    print("   ✓ Analysed vulnerabilities")
    if exploits_count > 0:
        print(f"   ✓ Generated {exploits_count} exploit{'s' if exploits_count != 1 else ''}")
    if patches_count > 0:
        print(f"   ✓ Created {patches_count} patch{'es' if patches_count != 1 else ''}")
    if orchestration_result:
        orch = orchestration_result.get("orchestration", {})
        mode = orch.get("mode", "unknown")
        if mode == "cc_dispatch":
            via = "Claude Code"
        elif mode == "external_llm":
            via = orch.get("analysis_model") or "external LLM"
        elif mode == "cc_fallback":
            via = "Claude Code (fallback)"
        else:
            via = mode
        n = orch.get('findings_analysed', 0)
        print(f"   ✓ Analysed {n} finding{'s' if n != 1 else ''} via {via}")
    print("\nReview the outputs and apply patches as needed.")

    # Generate markdown report

    phases = final_report.get("phases", {})
    scanning = phases.get("scanning", {})
    validation = phases.get("exploitability_validation", {})
    orch_phase = phases.get("orchestration", {})
    duration = final_report.get("duration_seconds", 0)

    # Determine model
    mode = orch_phase.get("mode", "none")
    if mode == "cc_dispatch":
        via = "Claude Code"
    elif mode == "external_llm":
        via = orch_phase.get("analysis_model") or "external LLM"
    elif mode == "cc_fallback":
        via = "Claude Code (fallback)"
    else:
        via = None

    pipeline_parts = ["Scan"]
    if validation.get("completed"):
        pipeline_parts.append("Dedup")
    if analysed_count > 0:
        pipeline_parts.append("Analyse")
    if exploits_count > 0:
        pipeline_parts.append("Exploit")
    if patches_count > 0:
        pipeline_parts.append("Patch")

    metadata = {
        "Target": f"`{final_report.get('repository', 'unknown')}`",
        "Date": final_report.get("timestamp", "unknown")[:10],
        "Pipeline": f"{' → '.join(pipeline_parts)} ({format_elapsed(duration)})",
    }
    if via:
        metadata["Model"] = via

    # Build extra summary (scanning/dedup metrics go before findings counts)
    extra_summary = {}
    extra_summary["Total findings"] = scanning.get("total_findings", 0)
    semgrep = scanning.get("semgrep", {})
    if semgrep.get("enabled"):
        extra_summary["Semgrep"] = semgrep.get("findings", 0)
    codeql = scanning.get("codeql", {})
    if codeql.get("enabled"):
        extra_summary["CodeQL"] = codeql.get("findings", 0)
    if validation.get("completed"):
        extra_summary["After deduplication"] = validation.get("validated_findings", 0)
    if analysed_count > 0:
        extra_summary["Analysed"] = analysed_count
    if failed_count > 0:
        extra_summary["Failed"] = failed_count
    if blocked_count > 0:
        extra_summary["Blocked (content filter)"] = blocked_count
    if exploits_count > 0:
        extra_summary["Exploits generated"] = exploits_count
    if patches_count > 0:
        extra_summary["Patches generated"] = patches_count
    cost_summary = orch_phase.get("cost", {})
    cost = cost_summary.get("total_cost", 0)
    if cost > 0:
        extra_summary["Cost"] = f"${cost:.2f}"

    # Warnings
    warnings = []
    if severity_mismatches:
        warnings.append(f"{len(severity_mismatches)} high-severity finding(s) ruled as false positive — review recommended")
    if contradictions > 0:
        warnings.append(f"{contradictions} self-contradictory verdict(s) — reasoning conflicts with conclusion")

    # Output files — significant outputs only, not per-category SARIF
    outputs = final_report.get("outputs", {})
    output_files = []
    if outputs.get("orchestrated_report"):
        output_files.append(outputs["orchestrated_report"])
    if outputs.get("autonomous_report"):
        output_files.append(outputs["autonomous_report"])
    sarif_files = outputs.get("sarif_files", [])
    combined = [sf for sf in sarif_files if "combined" in sf]
    if combined:
        output_files.append(combined[0])
    elif len(sarif_files) == 1:
        output_files.append(sarif_files[0])
    output_files.append("agentic-report.md")

    spec = build_findings_spec(
        analysed_results,
        title="RAPTOR Agentic Security Report",
        metadata=metadata,
        extra_summary=extra_summary,
        warnings=warnings,
        output_files=output_files,
        include_details=False,
    )

    md_report = render_report(spec)
    md_path = out_dir / "agentic-report.md"
    with open(md_path, "w") as f:
        f.write(md_report)
    print(f"   Report: {md_path}")


# Fallback CWE mapping for when LLM returns null
_CWE_FROM_VULN_TYPE = {
    "buffer_overflow": "CWE-120",
    "format_string": "CWE-134",
    "command_injection": "CWE-78",
    "xss": "CWE-79",
    "sql_injection": "CWE-89",
    "use_after_free": "CWE-416",
    "double_free": "CWE-415",
    "integer_overflow": "CWE-190",
    "null_dereference": "CWE-476",
    "path_traversal": "CWE-22",
    "ssrf": "CWE-918",
    "deserialization": "CWE-502",
    "race_condition": "CWE-367",
    "buffer_overread": "CWE-125",
    "heap_overflow": "CWE-122",
    "stack_overflow": "CWE-121",
    "type_confusion": "CWE-843",
}


def _postprocess_findings(results):
    """Post-process LLM results: compute CVSS scores, infer CWE."""
    from packages.cvss import score_finding

    for r in results:
        if "error" in r:
            continue

        score_finding(r)

        # Infer CWE from vuln_type if LLM didn't provide one
        if not r.get("cwe_id"):
            vuln_type = r.get("vuln_type", "")
            cwe = _CWE_FROM_VULN_TYPE.get(vuln_type)
            if cwe:
                r["cwe_id"] = cwe


if __name__ == "__main__":
    main()
