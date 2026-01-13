#!/usr/bin/env python3
"""
CodeQL Agent - Main Entry Point

Autonomous CodeQL security analysis workflow orchestrator.
Combines language detection, database creation, and query execution
into a seamless automated pipeline.
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.config import RaptorConfig
from core.logging import get_logger
from packages.codeql.language_detector import LanguageDetector, LanguageInfo
from packages.codeql.build_detector import BuildDetector, BuildSystem
from packages.codeql.database_manager import DatabaseManager, DatabaseResult
from packages.codeql.query_runner import QueryRunner, QueryResult

logger = get_logger()


@dataclass
class CodeQLWorkflowResult:
    """Complete workflow result."""
    success: bool
    repo_path: str
    timestamp: str
    duration_seconds: float
    languages_detected: Dict[str, LanguageInfo]
    databases_created: Dict[str, DatabaseResult]
    analyses_completed: Dict[str, QueryResult]
    total_findings: int
    sarif_files: List[str]
    errors: List[str]

    def to_dict(self):
        """
        Convert to dictionary for JSON serialization.

        Important: When adding new fields with non-serializable types (Path, datetime, etc.),
        you MUST add manual conversion here. Otherwise JSON serialization will fail.
        """
        data = asdict(self)

        # Convert LanguageInfo objects (existing - unchanged)
        data['languages_detected'] = {
            lang: {
                'confidence': info.confidence,
                'file_count': info.file_count,
                'extensions': list(info.extensions_found),
                'build_files': info.build_files_found,
            }
            for lang, info in self.languages_detected.items()
        }

        # Convert DatabaseResult objects (database_path: Path → str)
        data['databases_created'] = {
            lang: {
                'success': result.success,
                'language': result.language,
                'database_path': str(result.database_path) if result.database_path else None,
                'metadata': result.metadata.to_dict() if result.metadata else None,
                'errors': result.errors,
                'duration_seconds': result.duration_seconds,
                'cached': result.cached,
            }
            for lang, result in self.databases_created.items()
        }

        # Convert QueryResult objects (database_path and sarif_path: Path → str)
        data['analyses_completed'] = {
            lang: {
                'success': result.success,
                'language': result.language,
                'database_path': str(result.database_path),
                'sarif_path': str(result.sarif_path) if result.sarif_path else None,
                'findings_count': result.findings_count,
                'duration_seconds': result.duration_seconds,
                'errors': result.errors,
                'suite_name': result.suite_name,
                'queries_executed': result.queries_executed,
            }
            for lang, result in self.analyses_completed.items()
        }

        # CRITICAL: Convert sarif_files (type annotation says List[str], but agent.py:485 creates List[Path])
        data['sarif_files'] = [str(p) if isinstance(p, Path) else p for p in self.sarif_files]

        return data


class CodeQLAgent:
    """
    Main CodeQL agent orchestrator.

    Autonomous workflow:
    1. Detect languages in repository
    2. Detect build systems for each language
    3. Create CodeQL databases (with caching)
    4. Execute security analysis suites
    5. Generate SARIF output
    6. Create comprehensive report
    """

    def __init__(
        self,
        repo_path: Path,
        out_dir: Optional[Path] = None,
        codeql_cli: Optional[str] = None
    ):
        """
        Initialize CodeQL agent.

        Args:
            repo_path: Path to repository to analyze
            out_dir: Output directory (auto-generated if None)
            codeql_cli: Path to CodeQL CLI (auto-detected if None)
        """
        self.repo_path = Path(repo_path).resolve()
        self.start_time = time.time()

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        # Generate output directory
        if out_dir:
            self.out_dir = Path(out_dir)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            repo_name = self.repo_path.name
            self.out_dir = RaptorConfig.BASE_OUT_DIR / f"codeql_{repo_name}_{timestamp}"

        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.language_detector = LanguageDetector(self.repo_path)
        self.build_detector = BuildDetector(self.repo_path)
        self.database_manager = DatabaseManager(codeql_cli=codeql_cli)
        self.query_runner = QueryRunner(codeql_cli=codeql_cli)

        logger.info(f"{'=' * 70}")
        logger.info("RAPTOR CODEQL AGENT")
        logger.info(f"{'=' * 70}")
        logger.info(f"Repository: {self.repo_path}")
        logger.info(f"Output: {self.out_dir}")

    def run_autonomous_analysis(
        self,
        languages: Optional[List[str]] = None,
        build_commands: Optional[Dict[str, str]] = None,
        force_db_creation: bool = False,
        use_extended: bool = False,
        min_files: int = 3
    ) -> CodeQLWorkflowResult:
        """
        Run complete autonomous CodeQL analysis workflow.

        Args:
            languages: Languages to analyze (auto-detected if None)
            build_commands: Custom build commands per language
            force_db_creation: Force database recreation
            use_extended: Use extended security suites
            min_files: Minimum files to consider a language present

        Returns:
            CodeQLWorkflowResult with complete analysis results
        """
        errors = []

        try:
            # PHASE 1: Language Detection
            logger.info(f"\n{'=' * 70}")
            logger.info("PHASE 1: LANGUAGE DETECTION")
            logger.info(f"{'=' * 70}")

            if languages:
                logger.info(f"Using specified languages: {', '.join(languages)}")
                detected = {}
                for lang in languages:
                    # Create minimal LanguageInfo for specified languages
                    detected[lang] = LanguageInfo(
                        language=lang,
                        confidence=1.0,
                        file_count=0,
                        extensions_found=set(),
                        build_files_found=[],
                        indicators_found=[],
                    )
            else:
                logger.info("Auto-detecting languages...")
                detected = self.language_detector.detect_languages(min_files=min_files)
                detected = self.language_detector.filter_codeql_supported(detected)

            if not detected:
                error = "No CodeQL-supported languages detected"
                logger.error(error)
                return CodeQLWorkflowResult(
                    success=False,
                    repo_path=str(self.repo_path),
                    timestamp=datetime.now().isoformat(),
                    duration_seconds=time.time() - self.start_time,
                    languages_detected={},
                    databases_created={},
                    analyses_completed={},
                    total_findings=0,
                    sarif_files=[],
                    errors=[error],
                )

            logger.info(f"\n✓ Detected {len(detected)} language(s):")
            for lang, info in detected.items():
                logger.info(f"  - {lang}: {info.file_count} files (confidence: {info.confidence:.2f})")

            # PHASE 2: Build System Detection
            logger.info(f"\n{'=' * 70}")
            logger.info("PHASE 2: BUILD SYSTEM DETECTION")
            logger.info(f"{'=' * 70}")

            language_build_map = {}
            for lang in detected.keys():
                if build_commands and lang in build_commands:
                    # Use custom build command
                    logger.info(f"{lang}: Using custom build command")
                    language_build_map[lang] = BuildSystem(
                        type="custom",
                        command=build_commands[lang],
                        working_dir=self.repo_path,
                        env_vars={},
                        confidence=1.0,
                        detected_files=[],
                    )
                else:
                    # Auto-detect build system
                    build_system = self.build_detector.detect_build_system(lang)
                    if build_system:
                        # Validate build system
                        valid = self.build_detector.validate_build_command(build_system)
                        if not valid:
                            logger.warning(f"Build system validation failed for {lang}, using no-build mode")
                            build_system = self.build_detector.generate_no_build_config(lang)
                    else:
                        # Use no-build mode for interpreted languages
                        build_system = self.build_detector.generate_no_build_config(lang)

                    language_build_map[lang] = build_system

            # PHASE 3: Database Creation
            logger.info(f"\n{'=' * 70}")
            logger.info("PHASE 3: DATABASE CREATION")
            logger.info(f"{'=' * 70}")

            db_results = self.database_manager.create_databases_parallel(
                self.repo_path,
                language_build_map,
                force=force_db_creation
            )

            # Check for failures
            successful_dbs = {
                lang: result.database_path
                for lang, result in db_results.items()
                if result.success and result.database_path
            }

            failed_dbs = {
                lang: result
                for lang, result in db_results.items()
                if not result.success
            }

            if failed_dbs:
                logger.warning(f"\n⚠ {len(failed_dbs)} database(s) failed to create:")
                for lang, result in failed_dbs.items():
                    logger.warning(f"  - {lang}: {', '.join(result.errors[:2])}")
                    errors.extend(result.errors)

            if not successful_dbs:
                error = "No databases created successfully"
                logger.error(error)
                return CodeQLWorkflowResult(
                    success=False,
                    repo_path=str(self.repo_path),
                    timestamp=datetime.now().isoformat(),
                    duration_seconds=time.time() - self.start_time,
                    languages_detected=detected,
                    databases_created=db_results,
                    analyses_completed={},
                    total_findings=0,
                    sarif_files=[],
                    errors=[error] + errors,
                )

            logger.info(f"\n✓ Created {len(successful_dbs)} database(s):")
            for lang in successful_dbs.keys():
                cached = " (cached)" if db_results[lang].cached else ""
                logger.info(f"  - {lang}{cached}")

            # PHASE 4: Security Analysis
            logger.info(f"\n{'=' * 70}")
            logger.info("PHASE 4: SECURITY ANALYSIS")
            logger.info(f"{'=' * 70}")

            analysis_results = self.query_runner.analyze_all_databases(
                successful_dbs,
                self.out_dir,
                use_extended=use_extended
            )

            # Collect SARIF files and count findings
            sarif_files = []
            total_findings = 0

            for lang, result in analysis_results.items():
                if result.success and result.sarif_path:
                    sarif_files.append(str(result.sarif_path))
                    total_findings += result.findings_count
                    logger.info(f"  - {lang}: {result.findings_count} findings")
                else:
                    logger.error(f"  - {lang}: Analysis failed")
                    errors.extend(result.errors)

            # PHASE 5: Generate Report
            logger.info(f"\n{'=' * 70}")
            logger.info("PHASE 5: REPORT GENERATION")
            logger.info(f"{'=' * 70}")

            workflow_result = CodeQLWorkflowResult(
                success=len(sarif_files) > 0,
                repo_path=str(self.repo_path),
                timestamp=datetime.now().isoformat(),
                duration_seconds=time.time() - self.start_time,
                languages_detected=detected,
                databases_created=db_results,
                analyses_completed=analysis_results,
                total_findings=total_findings,
                sarif_files=sarif_files,
                errors=errors,
            )

            # Save report
            self._save_report(workflow_result)

            return workflow_result

        except Exception as e:
            logger.error(f"Workflow failed with exception: {e}", exc_info=True)
            return CodeQLWorkflowResult(
                success=False,
                repo_path=str(self.repo_path),
                timestamp=datetime.now().isoformat(),
                duration_seconds=time.time() - self.start_time,
                languages_detected={},
                databases_created={},
                analyses_completed={},
                total_findings=0,
                sarif_files=[],
                errors=[str(e)] + errors,
            )

    def _save_report(self, result: CodeQLWorkflowResult):
        """Save workflow report to JSON."""
        report_path = self.out_dir / "codeql_report.json"

        try:
            with open(report_path, 'w') as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            logger.info(f"✓ Report saved: {report_path}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def print_summary(self, result: CodeQLWorkflowResult):
        """Print workflow summary."""
        print(f"\n{'=' * 70}")
        print("CODEQL ANALYSIS SUMMARY")
        print(f"{'=' * 70}")
        print(f"Repository: {result.repo_path}")
        print(f"Duration: {result.duration_seconds:.1f}s")
        print(f"Status: {'✓ SUCCESS' if result.success else '✗ FAILED'}")
        print(f"\nLanguages detected: {len(result.languages_detected)}")
        print(f"Databases created: {len([r for r in result.databases_created.values() if r.success])}")
        print(f"Analyses completed: {len([r for r in result.analyses_completed.values() if r.success])}")
        print(f"\nTotal findings: {result.total_findings}")
        print(f"SARIF files: {len(result.sarif_files)}")

        # Count dataflow paths across all SARIF files
        total_dataflow_paths = 0
        total_dataflow_steps = 0
        dataflow_examples = []

        if result.sarif_files:
            for sarif_path in result.sarif_files:
                summary = self.query_runner.get_sarif_summary(Path(sarif_path))
                total_dataflow_paths += summary.get("dataflow_paths", 0)
                total_dataflow_steps += summary.get("total_dataflow_steps", 0)

                # Collect example dataflow paths for visualization
                if total_dataflow_paths > 0 and len(dataflow_examples) < 5:
                    examples = self._extract_dataflow_examples(Path(sarif_path), limit=5 - len(dataflow_examples))
                    dataflow_examples.extend(examples)

        if total_dataflow_paths > 0:
            print(f"\nDataflow Analysis:")
            print(f"  Findings with dataflow paths: {total_dataflow_paths}")
            avg_steps = total_dataflow_steps / total_dataflow_paths if total_dataflow_paths > 0 else 0
            print(f"  Average path length: {avg_steps:.1f} steps")

            # Show example dataflow paths in table format
            if dataflow_examples:
                self._print_dataflow_table(dataflow_examples)

        if result.sarif_files:
            print("\nSARIF outputs:")
            for sarif in result.sarif_files:
                print(f"  - {sarif}")

        if result.errors:
            print(f"\nErrors encountered: {len(result.errors)}")
            for error in result.errors[:5]:  # Show first 5 errors
                print(f"  - {error[:100]}")

        print(f"\nOutput directory: {self.out_dir}")
        print(f"{'=' * 70}\n")

    def _extract_dataflow_examples(self, sarif_path: Path, limit: int = 5) -> list:
        """Extract example dataflow paths from SARIF for visualization."""
        examples = []
        try:
            with open(sarif_path) as f:
                sarif_data = json.load(f)

            for run in sarif_data.get("runs", []):
                for result in run.get("results", []):
                    if len(examples) >= limit:
                        break

                    code_flows = result.get("codeFlows", [])
                    if not code_flows:
                        continue

                    # Extract path information
                    rule_id = result.get("ruleId", "unknown")
                    message = result.get("message", {}).get("text", "")

                    # Get the dataflow path
                    flow = code_flows[0]
                    thread_flows = flow.get("threadFlows", [])
                    if not thread_flows:
                        continue

                    locations = thread_flows[0].get("locations", [])
                    if len(locations) < 2:  # Need at least source and sink
                        continue

                    # Extract source, sink, and intermediate steps
                    source_loc = locations[0].get("location", {})
                    sink_loc = locations[-1].get("location", {})

                    source_file = source_loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    source_line = source_loc.get("physicalLocation", {}).get("region", {}).get("startLine", 0)

                    sink_file = sink_loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    sink_line = sink_loc.get("physicalLocation", {}).get("region", {}).get("startLine", 0)

                    examples.append({
                        "rule": rule_id.split("/")[-1] if "/" in rule_id else rule_id,
                        "message": message[:60] + "..." if len(message) > 60 else message,
                        "source": f"{Path(source_file).name}:{source_line}",
                        "sink": f"{Path(sink_file).name}:{sink_line}",
                        "steps": len(locations)
                    })

        except Exception as e:
            logger.debug(f"Failed to extract dataflow examples: {e}")

        return examples

    def _print_dataflow_table(self, dataflow_examples: list):
        """Print dataflow paths in a formatted table."""
        try:
            from tabulate import tabulate

            print(f"\n  Example Dataflow Paths:")

            table_data = []
            for example in dataflow_examples:
                table_data.append([
                    example["rule"],
                    example["source"],
                    "→" * (example["steps"] - 1),
                    example["sink"],
                    example["steps"]
                ])

            headers = ["Rule", "Source", "Flow", "Sink", "Steps"]
            table = tabulate(table_data, headers=headers, tablefmt="simple", maxcolwidths=[20, 25, 10, 25, 5])

            # Indent the table
            for line in table.split('\n'):
                print(f"  {line}")

        except ImportError:
            # Fallback to simple formatting if tabulate not available
            print(f"\n  Example Dataflow Paths:")
            for i, example in enumerate(dataflow_examples, 1):
                print(f"    {i}. {example['rule']}: {example['source']} → {example['sink']} ({example['steps']} steps)")
        except Exception as e:
            logger.debug(f"Failed to print dataflow table: {e}")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="RAPTOR CodeQL Agent - Autonomous CodeQL Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fully autonomous (auto-detect everything)
  python3 packages/codeql/agent.py --repo /path/to/code

  # Specify languages
  python3 packages/codeql/agent.py --repo /path/to/code --languages java,python

  # With custom build command
  python3 packages/codeql/agent.py --repo /path/to/code --language java \\
    --build-command "mvn clean compile -DskipTests"

  # Use extended security suite
  python3 packages/codeql/agent.py --repo /path/to/code --extended

  # Force database recreation
  python3 packages/codeql/agent.py --repo /path/to/code --force
        """
    )

    parser.add_argument("--repo", required=True, help="Repository path to analyze")
    parser.add_argument("--languages", help="Comma-separated languages (auto-detected if not specified)")
    parser.add_argument("--build-command", help="Custom build command")
    parser.add_argument("--force", action="store_true", help="Force database recreation (ignore cache)")
    parser.add_argument("--extended", action="store_true", help="Use extended security suites")
    parser.add_argument("--out", help="Output directory (auto-generated if not specified)")
    parser.add_argument("--min-files", type=int, default=3, help="Minimum files to detect language")
    parser.add_argument("--codeql-cli", help="Path to CodeQL CLI (auto-detected if not specified)")

    args = parser.parse_args()

    # Parse languages
    languages = None
    if args.languages:
        languages = [lang.strip() for lang in args.languages.split(",")]

    # Parse build commands
    build_commands = None
    if args.build_command:
        if not languages or len(languages) != 1:
            print("Error: --build-command requires exactly one language specified with --languages")
            sys.exit(1)
        build_commands = {languages[0]: args.build_command}

    try:
        # Initialize agent
        agent = CodeQLAgent(
            repo_path=Path(args.repo),
            out_dir=Path(args.out) if args.out else None,
            codeql_cli=args.codeql_cli
        )

        # Run analysis
        result = agent.run_autonomous_analysis(
            languages=languages,
            build_commands=build_commands,
            force_db_creation=args.force,
            use_extended=args.extended,
            min_files=args.min_files
        )

        # Print summary
        agent.print_summary(result)

        # Exit with appropriate code
        sys.exit(0 if result.success else 1)

    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n✗ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
