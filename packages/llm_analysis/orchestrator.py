#!/usr/bin/env python3
"""
RAPTOR Truly Agentic Orchestrator

This orchestrator autonomously:
1. analyses vulnerabilities with deep code understanding
2. Generates working proof of concept exploits to help with detection engineering efforts and patching capabilities
3. Creates secure patches with context awareness
4. Coordinates multi step workflows

This makes RAPTOR truly agentic, not just a wrapper.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "static-analysis"))
from core.config import RaptorConfig
from core.logging import get_logger
from core.sarif.parser import parse_sarif_findings, deduplicate_findings
from codeql.env import detect_codeql, CodeQLEnv


logger = get_logger()

# Import the autonomous security agent to do the actual work
try:
    from agent import AutonomousSecurityAgentV2
    AUTONOMOUS_AGENT_AVAILABLE = True
except ImportError:
    logger.error("Cannot import AutonomousSecurityAgentV2")
    AUTONOMOUS_AGENT_AVAILABLE = False


class AgenticOrchestrator:
    """
    Orchestrator that coordinates autonomous security analysis.

    Uses the AutonomousSecurityAgentV2 to actually perform:
    - Vulnerability analysis (LLM-powered, no heuristics)
    - Exploit generation (context-aware, no templates)
    - Patch creation (intelligent, no templates)
    """

    def __init__(self, repo_path: Path, out_dir: Path) -> None:
        self.repo_path = repo_path.resolve()
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        (self.out_dir / "analysis").mkdir(exist_ok=True)
        (self.out_dir / "exploits").mkdir(exist_ok=True)
        (self.out_dir / "patches").mkdir(exist_ok=True)

        logger.info("=" * 60)
        logger.info("AGENTIC ORCHESTRATOR INITIALISED")
        logger.info("=" * 60)
        logger.info(f"Repository: {self.repo_path}")
        logger.info(f"Output: {self.out_dir}")

    def orchestrate_autonomous_workflow(
        self,
        sarif_paths: List[str],
        max_findings: int = 5,
        codeql_env: Optional[CodeQLEnv] = None,
    ) -> Dict[str, Any]:
        """
        Main autonomous orchestration:
        1. Load findings
        2. Autonomously analyse each vulnerability
        3. For exploitable findings, generate exploits
        4. Generate patches for all findings
        5. Coordinate and report

        Args:
            sarif_paths: List of SARIF files
            max_findings: Maximum findings to process (to avoid overwhelming)
            codeql_env: Optional CodeQL environment snapshot for provenance
        """
        logger.info("=" * 60)
        logger.info("STARTING AUTONOMOUS WORKFLOW ORCHESTRATION")
        logger.info("=" * 60)

        # Debug: Show SARIF files being processed
        print(f"\n[DEBUG] Processing SARIF files:")
        for i, sarif_path in enumerate(sarif_paths, 1):
            sarif_file = Path(sarif_path)
            exists = "✓" if sarif_file.exists() else "✗"
            size = sarif_file.stat().st_size if sarif_file.exists() else 0
            print(f"  {i}. {exists} {sarif_path} ({size:,} bytes)")

        if not AUTONOMOUS_AGENT_AVAILABLE:
            logger.error("AutonomousSecurityAgentV2 not available, cannot proceed")
            print("❌ Error: Autonomous agent not available")
            print("   Make sure autonomous_security_agent.py is in the same directory")
            sys.exit(1)

        # Quick check: Load findings to get counts
        all_findings = []
        for sarif_path in sarif_paths:
            print(f"\n[DEBUG] Parsing SARIF: {sarif_path}")
            findings = parse_sarif_findings(Path(sarif_path))
            print(f"[DEBUG] Found {len(findings)} findings in this file")
            all_findings.extend(findings)

        print(f"\n[DEBUG] Total findings from all files: {len(all_findings)}")
        unique_findings = deduplicate_findings(all_findings)
        print(f"[DEBUG] Unique findings after deduplication: {len(unique_findings)}")
        logger.info(
            f"Found {len(unique_findings)} unique findings from {len(sarif_paths)} SARIF files"
        )

        if len(unique_findings) == 0:
            print("⚠️  No findings to process.")
            print(f"   Checked SARIF files: {sarif_paths}")
            print("   Make sure the SARIF files contain vulnerability findings")
            return {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "repository": str(self.repo_path),
                "total_findings": 0,
                "unique_findings": 0,
                "processed_findings": 0,
                "analysed": 0,
                "exploitable": 0,
                "exploits_generated": 0,
                "patches_generated": 0,
                "execution_time_seconds": 0,
                "detailed_results": [],
                "codeql": codeql_env.to_dict() if codeql_env is not None else None,
            }

        # Initialise the autonomous agent
        agent = AutonomousSecurityAgentV2(self.repo_path, self.out_dir)

        # Set max findings limit on the agent
        if max_findings < len(unique_findings):
            logger.warning(
                f"Limiting to {max_findings} findings (found {len(unique_findings)})"
            )
            # Note: the agent processes all findings; limiting behaviour is enforced
            # in the agent implementation.

        # Process findings autonomously, passing SARIF paths and max_findings
        results = agent.process_findings(sarif_paths, max_findings=max_findings)

        # Generate orchestration report from agent results
        report: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "repository": str(self.repo_path),
            "total_findings": len(all_findings),
            "unique_findings": len(unique_findings),
            "processed_findings": results.get("processed", 0),
            "analysed": results.get("analysed", 0),
            "exploitable": results.get("exploitable", 0),
            "exploits_generated": results.get("exploits_generated", 0),
            "patches_generated": results.get("patches_generated", 0),
            "execution_time_seconds": results.get("execution_time", 0),
            "detailed_results": results.get("results", []),
        }

        # Attach CodeQL provenance if available
        if codeql_env is not None:
            report["codeql"] = codeql_env.to_dict()

        # Save report
        report_file = self.out_dir / "orchestration_report.json"
        report_file.write_text(json.dumps(report, indent=2))

        logger.info("\n" + "=" * 60)
        logger.info("ORCHESTRATION COMPLETE")
        logger.info("=" * 60)
        logger.info(f"analysed: {report['analysed']}")
        logger.info(f"Exploitable: {report['exploitable']}")
        logger.info(f"Exploits generated: {report['exploits_generated']}")
        logger.info(f"Patches generated: {report['patches_generated']}")
        logger.info(f"Report saved: {report_file}")

        return report


def main() -> None:
    ap = argparse.ArgumentParser(
        description="RAPTOR Agentic Orchestrator - Fully Autonomous Security Testing",
        epilog="""
Examples:
  # Fully autonomous, scans and analyses automatically
  python3 agentic_orchestrator.py --repo /path/to/code

  # Use existing SARIF files
  python3 agentic_orchestrator.py --repo /path/to/code --sarif results.sarif

  # Specify policy groups for scanning
  python3 agentic_orchestrator.py --repo /path/to/code --policy-groups crypto,secrets
        """,
    )
    ap.add_argument("--repo", required=True, help="Repository path")
    ap.add_argument(
        "--sarif",
        nargs="+",
        help="SARIF files (optional, will scan if not provided)",
    )
    ap.add_argument(
        "--policy-groups",
        default="all",
        help="Policy groups to scan (default: all)",
    )
    ap.add_argument("--out", help="Output directory")
    ap.add_argument(
        "--max-findings",
        type=int,
        default=10,
        help="Maximum findings to process",
    )
    ap.add_argument(
        "--codeql-mode",
        choices=["disabled", "detect", "require"],
        default="disabled",
        help=(
            "Enable optional CodeQL integration. "
            "'disabled' ignores CodeQL, "
            "'detect' uses CodeQL if available, "
            "'require' fails if CodeQL is missing."
        ),
    )

    args = ap.parse_args()

    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"❌ Error: Repository not found: {repo_path}")
        sys.exit(1)

    # Check for .git directory (used for Semgrep context)
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        print(f"\n⚠️  No .git directory found in {repo_path}")
        print("    Initialising git repository for better context...")
        try:
            subprocess.run(
                ["git", "init"],
                cwd=repo_path,
                capture_output=True,
                timeout=30,
                check=False,
            )
            subprocess.run(
                ["git", "add", "."],
                cwd=repo_path,
                capture_output=True,
                timeout=60,
                check=False,
            )
            subprocess.run(
                ["git", "commit", "-m", "Initial commit for RAPTOR scan"],
                cwd=repo_path,
                capture_output=True,
                timeout=60,
                check=False,
            )
            print("✓ Git repository initialised")
        except Exception as e:
            logger.warning(f"Could not initialise git: {e}")

    # Generate output directory with repository name and timestamp
    if args.out:
        out_dir = Path(args.out).resolve()
        repo_name = repo_path.name
    else:
        repo_name = repo_path.name
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_dir = RaptorConfig.get_out_dir() / f"agentic_{repo_name}_{timestamp}"

    print("\n" + "=" * 70)
    print(f"Repository: {repo_name}")
    print(f"Full path: {repo_path}")
    print(f"Output: {out_dir}")
    print(f"Max findings: {args.max_findings}")
    print("=" * 70 + "\n")

    # CodeQL environment detection
    codeql_env: CodeQLEnv = detect_codeql(mode=args.codeql_mode)
    if args.codeql_mode == "require" and not codeql_env.available:
        print("[RAPTOR] Error: CodeQL is required but not available.")
        print(f"Reason: {codeql_env.reason}")
        raise SystemExit(1)

    print(f"[RAPTOR] CodeQL mode: {args.codeql_mode}")
    if codeql_env.available:
        print(f"[RAPTOR] CodeQL version: {codeql_env.version}")
        print(f"[RAPTOR] CodeQL path: {codeql_env.cli_path}")
    else:
        print(f"[RAPTOR] CodeQL unavailable ({codeql_env.reason})")

    # Autonomous behaviour: if no SARIF provided, run auto_codesec to create SARIF
    if not args.sarif:
        print("\n🔍 No SARIF files provided, running autonomous scan...")
        print(f"Policy groups: {args.policy_groups}")
        print("=" * 70)

        scan_cmd = [
            "python3",
            str(Path(__file__).parent / "auto_codesec.py"),
            "--repo",
            str(repo_path),
            "--policy_groups",
            args.policy_groups,
        ]

        print(f"\n[*] Running: {' '.join(scan_cmd)}")
        try:
            result = subprocess.run(
                scan_cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minutes
                check=False,
            )
            if result.returncode != 0:
                print("\n❌ Scan failed.")
                print(f"Error: {result.stderr}")
                sys.exit(1)

            print("✓ Scan completed successfully")

            # auto_codesec creates: out/scan_<repo>_<timestamp>/combined.sarif
            scan_dirs = sorted(RaptorConfig.get_out_dir().glob(f"scan_{repo_name}_*"))
            if not scan_dirs:
                print("❌ Could not find scan output directory")
                sys.exit(1)

            latest_scan_dir = scan_dirs[-1]
            combined_sarif = latest_scan_dir / "combined.sarif"

            if not combined_sarif.exists():
                print(f"❌ SARIF file not found: {combined_sarif}")
                sys.exit(1)

            sarif_paths = [str(combined_sarif)]
            print(f"✓ Using SARIF: {combined_sarif}")

        except subprocess.TimeoutExpired:
            print("❌ Scan timed out after 30 minutes")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Scan error: {e}")
            sys.exit(1)
    else:
        sarif_paths = args.sarif
        print(f"\n📋 Using provided SARIF files: {len(sarif_paths)} file(s)")

    orchestrator = AgenticOrchestrator(repo_path, out_dir)
    report = orchestrator.orchestrate_autonomous_workflow(
        sarif_paths,
        args.max_findings,
        codeql_env=codeql_env,
    )

    print("\n" + "=" * 70)
    print("✅ AUTONOMOUS ORCHESTRATION COMPLETE")
    print("=" * 70)
    print(f"Total findings: {report['total_findings']}")
    print(f"Processed: {report['processed_findings']}")
    print(f"analysed: {report['analysed']}")
    print(f"Exploitable: {report['exploitable']}")
    print("\nAutonomous Actions:")
    print(f"  ✓ Exploits generated: {report['exploits_generated']}")
    print(f"  ✓ Patches generated: {report['patches_generated']}")
    print(f"\nExecution time: {report['execution_time_seconds']:.2f}s")
    print(f"\nResults saved to: {out_dir}")
    print(f"  - Analysis: {out_dir / 'analysis'}")
    print(f"  - Exploits: {out_dir / 'exploits'}")
    print(f"  - Patches: {out_dir / 'patches'}")
    print(f"  - Report: {out_dir / 'orchestration_report.json'}")
    print("=" * 70)


if __name__ == "__main__":
    main()
