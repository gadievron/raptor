#!/usr/bin/env python3
"""
RAPTOR CodeQL - Complete Autonomous Workflow

Combines Phase 1 (scanning) and Phase 2 (autonomous analysis) into a
single fully autonomous security testing workflow.

Workflow:
1. Language detection
2. Build system detection
3. CodeQL database creation
4. Security suite execution → SARIF
5. LLM-powered autonomous analysis
6. Dataflow validation
7. PoC exploit generation
8. Exploit validation & refinement
"""

import argparse
import json
import sys
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import RaptorConfig
from core.logging import get_logger
from packages.codeql.agent import CodeQLAgent
from packages.codeql.autonomous_analyzer import AutonomousCodeQLAnalyzer

logger = get_logger()


def get_llm_client():
    """Initialize LLM client from existing RAPTOR system."""
    try:
        from core.llm.client import LLMClient
        return LLMClient()
    except Exception as e:
        logger.warning(f"LLM client not available: {e}")
        return None


def get_exploit_validator(work_dir: Path):
    """Initialize exploit validator from existing RAPTOR system."""
    try:
        from packages.autonomous.exploit_validator import ExploitValidator
        return ExploitValidator(work_dir)
    except Exception as e:
        logger.warning(f"Exploit validator not available: {e}")
        return None


def get_multi_turn_analyzer(llm_client):
    """Initialize multi-turn analyzer from existing RAPTOR system."""
    try:
        from packages.autonomous.dialogue import MultiTurnAnalyser
        return MultiTurnAnalyser(llm_client)
    except Exception as e:
        logger.warning(f"Multi-turn analyzer not available: {e}")
        return None


def run_autonomous_workflow(args):
    """
    Run complete autonomous CodeQL workflow.

    Args:
        args: Parsed command-line arguments
    """
    logger.info(f"{'=' * 70}")
    logger.info("RAPTOR CODEQL - AUTONOMOUS SECURITY ANALYSIS")
    logger.info(f"{'=' * 70}")

    # Parse languages
    languages = None
    if args.languages:
        languages = [lang.strip() for lang in args.languages.split(",")]

    # Parse build commands
    build_commands = None
    if args.build_command:
        if not languages or len(languages) != 1:
            logger.error("--build-command requires exactly one language")
            sys.exit(1)
        build_commands = {languages[0]: args.build_command}

    # PHASE 1: CodeQL Scanning
    logger.info("\n" + "=" * 70)
    logger.info("PHASE 1: CODEQL SCANNING")
    logger.info("=" * 70)

    agent = CodeQLAgent(
        repo_path=Path(args.repo),
        out_dir=Path(args.out) if args.out else None,
        codeql_cli=args.codeql_cli
    )

    scan_result = agent.run_autonomous_analysis(
        languages=languages,
        build_commands=build_commands,
        force_db_creation=args.force,
        use_extended=args.extended,
        min_files=args.min_files
    )

    if not scan_result.success:
        logger.error("Scanning failed - cannot proceed to autonomous analysis")
        agent.print_summary(scan_result)
        sys.exit(1)

    logger.info(f"\n✓ Phase 1 complete: {scan_result.total_findings} findings")

    # Check if we should do autonomous analysis
    if args.scan_only:
        logger.info("Scan-only mode - skipping autonomous analysis")
        agent.print_summary(scan_result)
        return

    if scan_result.total_findings == 0:
        logger.info("No findings - skipping autonomous analysis")
        agent.print_summary(scan_result)
        return

    # PHASE 2: Autonomous Analysis
    logger.info("\n" + "=" * 70)
    logger.info("PHASE 2: AUTONOMOUS VULNERABILITY ANALYSIS")
    logger.info("=" * 70)

    # Initialize autonomous components
    llm_client = get_llm_client()
    if not llm_client:
        logger.error("LLM client not available - cannot perform autonomous analysis")
        logger.info("Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable")
        agent.print_summary(scan_result)
        sys.exit(1)

    exploit_validator = get_exploit_validator(agent.out_dir / "exploits")
    multi_turn = get_multi_turn_analyzer(llm_client)

    # Initialize autonomous analyzer
    autonomous_analyzer = AutonomousCodeQLAnalyzer(
        llm_client=llm_client,
        exploit_validator=exploit_validator,
        multi_turn_analyzer=multi_turn,
        enable_visualization=not args.no_visualizations
    )

    # Analyze each SARIF file
    autonomous_results = []
    total_analyzed = 0
    total_exploitable = 0
    total_exploits_generated = 0
    total_exploits_compiled = 0

    for sarif_file in scan_result.sarif_files:
        logger.info(f"\nAnalyzing SARIF: {sarif_file}")

        with open(sarif_file) as f:
            sarif = json.load(f)

        run = sarif["runs"][0]
        results = run["results"]

        # Analyze findings (up to max_findings)
        findings_to_analyze = results[:args.max_findings]
        logger.info(f"Analyzing {len(findings_to_analyze)} findings...")

        for i, result in enumerate(findings_to_analyze, 1):
            rule_id = result.get("ruleId", "unknown")
            logger.info(f"\n[{i}/{len(findings_to_analyze)}] {rule_id}")

            try:
                analysis = autonomous_analyzer.analyze_finding_autonomous(
                    sarif_result=result,
                    sarif_run=run,
                    repo_path=Path(args.repo),
                    out_dir=agent.out_dir / "autonomous"
                )

                autonomous_results.append(analysis)
                total_analyzed += 1

                if analysis.exploitable:
                    total_exploitable += 1

                if analysis.exploit_code:
                    total_exploits_generated += 1

                if analysis.exploit_compiled:
                    total_exploits_compiled += 1

                # Log results
                if analysis.exploitable:
                    logger.info(f"✓ Exploitable (score: {analysis.analysis.exploitability_score:.2f})")
                    if analysis.exploit_code:
                        logger.info(f"  Exploit generated: {len(analysis.exploit_code)} bytes")
                        if analysis.exploit_compiled:
                            logger.info(f"  ✓ Exploit compiled successfully")
                        else:
                            logger.info(f"  ⚠ Exploit failed to compile")
                else:
                    logger.info(f"❌ Not exploitable")

            except Exception as e:
                logger.error(f"Analysis failed: {e}", exc_info=True)

    # Save autonomous analysis summary
    summary = {
        "total_findings": scan_result.total_findings,
        "analyzed": total_analyzed,
        "exploitable": total_exploitable,
        "exploits_generated": total_exploits_generated,
        "exploits_compiled": total_exploits_compiled,
        "scan_result": scan_result.to_dict(),
    }

    summary_file = agent.out_dir / "autonomous_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)

    logger.info(f"\n✓ Autonomous analysis summary saved: {summary_file}")

    # Print final summary
    print(f"\n{'=' * 70}")
    print("AUTONOMOUS ANALYSIS SUMMARY")
    print(f"{'=' * 70}")
    print(f"Total findings: {scan_result.total_findings}")
    print(f"Analyzed: {total_analyzed}")
    print(f"Exploitable: {total_exploitable}")
    print(f"Exploits generated: {total_exploits_generated}")
    print(f"Exploits compiled: {total_exploits_compiled}")
    print(f"\nOutput: {agent.out_dir}")
    print(f"  Scan results: {len(scan_result.sarif_files)} SARIF files")
    print(f"  Autonomous analysis: autonomous/")
    print(f"  Exploits: exploits/")
    if not args.no_visualizations:
        print(f"  Visualizations: autonomous/visualizations/")
    print(f"{'=' * 70}\n")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="RAPTOR CodeQL - Fully Autonomous Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fully autonomous (auto-detect + analyze + exploit)
  python3 raptor_codeql.py --repo /path/to/code

  # Scan only (no autonomous analysis)
  python3 raptor_codeql.py --repo /path/to/code --scan-only

  # With custom build command
  python3 raptor_codeql.py --repo /path/to/code --languages java \\
    --build-command "mvn clean compile -DskipTests"

  # Analyze up to 20 findings
  python3 raptor_codeql.py --repo /path/to/code --max-findings 20
        """
    )

    parser.add_argument("--repo", required=True, help="Repository path")
    parser.add_argument("--languages", help="Comma-separated languages")
    parser.add_argument("--build-command", help="Custom build command")
    parser.add_argument("--out", help="Output directory")
    parser.add_argument("--force", action="store_true", help="Force database recreation")
    parser.add_argument("--extended", action="store_true", help="Use extended security suites")
    parser.add_argument("--min-files", type=int, default=3, help="Min files to detect language")
    parser.add_argument("--codeql-cli", help="Path to CodeQL CLI")
    parser.add_argument("--scan-only", action="store_true", help="Scan only (skip autonomous analysis)")
    parser.add_argument("--max-findings", type=int, default=20, help="Max findings to analyze")
    parser.add_argument("--no-visualizations", action="store_true", help="Disable dataflow visualizations")

    args = parser.parse_args()

    try:
        run_autonomous_workflow(args)
    except KeyboardInterrupt:
        print("\n\nWorkflow interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n✗ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
