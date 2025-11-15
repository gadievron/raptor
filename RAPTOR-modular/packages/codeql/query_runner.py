#!/usr/bin/env python3
"""
CodeQL Query Runner

Executes CodeQL queries and suites against databases,
producing SARIF output for vulnerability analysis.
"""

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()


@dataclass
class QueryResult:
    """Result of query execution."""
    success: bool
    language: str
    database_path: Path
    sarif_path: Optional[Path]
    findings_count: int
    duration_seconds: float
    errors: List[str]
    suite_name: str
    queries_executed: int = 0


class QueryRunner:
    """
    Execute CodeQL queries and suites against databases.

    Supports:
    - Official CodeQL security suites
    - Custom query packs
    - Parallel execution for multiple databases
    - SARIF output generation
    """

    # Official CodeQL security suites (from GitHub)
    SECURITY_SUITES = {
        "java": "codeql/java-queries:codeql-suites/java-security-and-quality.qls",
        "python": "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
        "typescript": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
        "go": "codeql/go-queries:codeql-suites/go-security-and-quality.qls",
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls",
        "csharp": "codeql/csharp-queries:codeql-suites/csharp-security-and-quality.qls",
        "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-and-quality.qls",
        "swift": "codeql/swift-queries:codeql-suites/swift-security-and-quality.qls",
        "kotlin": "codeql/java-queries:codeql-suites/java-security-and-quality.qls",  # Kotlin uses Java queries
    }

    # Alternative: security-extended suites (more comprehensive)
    SECURITY_EXTENDED_SUITES = {
        "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
        "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        "typescript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        "go": "codeql/go-queries:codeql-suites/go-security-extended.qls",
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        "csharp": "codeql/csharp-queries:codeql-suites/csharp-security-extended.qls",
        "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
    }

    def __init__(self, codeql_cli: Optional[str] = None):
        """
        Initialize query runner.

        Args:
            codeql_cli: Path to CodeQL CLI (auto-detected if None)
        """
        import shutil
        self.codeql_cli = codeql_cli or shutil.which("codeql")
        if not self.codeql_cli:
            raise RuntimeError("CodeQL CLI not found")

        logger.info(f"Query runner initialized with CodeQL: {self.codeql_cli}")

    def run_suite(
        self,
        database_path: Path,
        language: str,
        out_dir: Path,
        suite: Optional[str] = None,
        use_extended: bool = False
    ) -> QueryResult:
        """
        Execute CodeQL suite against database.

        Args:
            database_path: Path to CodeQL database
            language: Programming language
            out_dir: Output directory for SARIF
            suite: Custom suite identifier (uses default if None)
            use_extended: Use security-extended suite instead of standard

        Returns:
            QueryResult with execution status
        """
        start_time = time.time()
        errors = []

        logger.info(f"{'=' * 70}")
        logger.info(f"Running CodeQL analysis for {language}")
        logger.info(f"{'=' * 70}")

        # Determine suite to use
        if suite:
            suite_name = suite
            logger.info(f"Using custom suite: {suite}")
        else:
            # Use standard or extended suite
            suites = self.SECURITY_EXTENDED_SUITES if use_extended else self.SECURITY_SUITES
            suite_name = suites.get(language)

            if not suite_name:
                error = f"No default suite for language: {language}"
                logger.error(error)
                return QueryResult(
                    success=False,
                    language=language,
                    database_path=database_path,
                    sarif_path=None,
                    findings_count=0,
                    duration_seconds=time.time() - start_time,
                    errors=[error],
                    suite_name="unknown",
                )

            suite_type = "security-extended" if use_extended else "security-and-quality"
            logger.info(f"Using {suite_type} suite: {suite_name}")

        # Prepare output path
        out_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = out_dir / f"codeql_{language}.sarif"

        # If CODEQL_QUERIES is set, try to resolve the absolute path to avoid ambiguity
        import os
        codeql_queries = os.environ.get("CODEQL_QUERIES")
        actual_suite_path = suite_name

        if codeql_queries and Path(codeql_queries).exists():
            # Try to resolve the suite to an absolute path to avoid pack conflicts
            # Convert pack reference like "codeql/java-queries:codeql-suites/java-security-and-quality.qls"
            # to absolute path like "/path/to/codeql-queries/java/ql/src/codeql-suites/java-security-and-quality.qls"
            if ":" in suite_name:
                pack_name, suite_path = suite_name.split(":", 1)
                # Map pack names to directories
                lang_map = {
                    "codeql/java-queries": "java",
                    "codeql/python-queries": "python",
                    "codeql/javascript-queries": "javascript",
                    "codeql/cpp-queries": "cpp",
                    "codeql/csharp-queries": "csharp",
                    "codeql/go-queries": "go",
                    "codeql/ruby-queries": "ruby",
                    "codeql/swift-queries": "swift",
                }

                lang_dir = lang_map.get(pack_name)
                if lang_dir:
                    # Try to find the suite file
                    potential_path = Path(codeql_queries) / lang_dir / "ql" / "src" / suite_path
                    if potential_path.exists():
                        actual_suite_path = str(potential_path)
                        logger.info(f"Resolved suite to absolute path: {actual_suite_path}")
                    else:
                        logger.warning(f"Could not find suite at {potential_path}, using pack reference")

        # Build command
        cmd = [
            self.codeql_cli,
            "database",
            "analyze",
            str(database_path),
            actual_suite_path,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            f"--threads={RaptorConfig.CODEQL_THREADS}",
            f"--ram={RaptorConfig.CODEQL_RAM_MB}",
            "--no-rerun",  # Don't rerun queries if results exist
        ]

        # Add search path if CODEQL_QUERIES is set (as fallback for pack references)
        if codeql_queries and Path(codeql_queries).exists() and actual_suite_path == suite_name:
            # Only add search-path if we're still using pack reference
            cmd.insert(1, f"--search-path={codeql_queries}")
            logger.info(f"Using CODEQL_QUERIES search path: {codeql_queries}")

        logger.info(f"Executing: {' '.join(cmd)}")
        logger.info(f"Timeout: {RaptorConfig.CODEQL_ANALYZE_TIMEOUT}s")

        # Execute analysis
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=RaptorConfig.CODEQL_ANALYZE_TIMEOUT,
            )

            success = result.returncode == 0

            if not success:
                errors.append(f"Analysis failed with exit code {result.returncode}")
                if result.stderr:
                    errors.append(result.stderr[:1000])
                logger.error(f"✗ Analysis failed for {language}")
                logger.error(result.stderr[:500])

                return QueryResult(
                    success=False,
                    language=language,
                    database_path=database_path,
                    sarif_path=None,
                    findings_count=0,
                    duration_seconds=time.time() - start_time,
                    errors=errors,
                    suite_name=suite_name,
                )

            # Parse SARIF to count findings
            findings_count = 0
            queries_executed = 0

            if sarif_path.exists():
                try:
                    with open(sarif_path) as f:
                        sarif_data = json.load(f)

                    # Count findings
                    for run in sarif_data.get("runs", []):
                        results = run.get("results", [])
                        findings_count += len(results)

                        # Count queries executed
                        tool = run.get("tool", {})
                        driver = tool.get("driver", {})
                        rules = driver.get("rules", [])
                        queries_executed += len(rules)

                except Exception as e:
                    logger.warning(f"Failed to parse SARIF: {e}")

            logger.info(f"✓ Analysis completed for {language}")
            logger.info(f"  Findings: {findings_count}")
            logger.info(f"  Queries executed: {queries_executed}")
            logger.info(f"  Duration: {time.time() - start_time:.1f}s")
            logger.info(f"  SARIF: {sarif_path}")

            return QueryResult(
                success=True,
                language=language,
                database_path=database_path,
                sarif_path=sarif_path,
                findings_count=findings_count,
                duration_seconds=time.time() - start_time,
                errors=[],
                suite_name=suite_name,
                queries_executed=queries_executed,
            )

        except subprocess.TimeoutExpired:
            error = f"Analysis timed out after {RaptorConfig.CODEQL_ANALYZE_TIMEOUT}s"
            errors.append(error)
            logger.error(f"✗ {error}")

            return QueryResult(
                success=False,
                language=language,
                database_path=database_path,
                sarif_path=None,
                findings_count=0,
                duration_seconds=time.time() - start_time,
                errors=errors,
                suite_name=suite_name,
            )

        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            errors.append(error)
            logger.error(f"✗ Analysis failed with exception: {e}")

            return QueryResult(
                success=False,
                language=language,
                database_path=database_path,
                sarif_path=None,
                findings_count=0,
                duration_seconds=time.time() - start_time,
                errors=errors,
                suite_name=suite_name,
            )

    def run_custom_queries(
        self,
        database_path: Path,
        query_path: Path,
        out_dir: Path,
        language: str
    ) -> QueryResult:
        """
        Run custom query pack against database.

        Args:
            database_path: Path to CodeQL database
            query_path: Path to query pack or directory
            out_dir: Output directory
            language: Programming language

        Returns:
            QueryResult
        """
        start_time = time.time()

        logger.info(f"Running custom queries from: {query_path}")

        out_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = out_dir / f"codeql_{language}_custom.sarif"

        cmd = [
            self.codeql_cli,
            "database",
            "analyze",
            str(database_path),
            str(query_path),
            "--format=sarif-latest",
            f"--output={sarif_path}",
            f"--threads={RaptorConfig.CODEQL_THREADS}",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=RaptorConfig.CODEQL_ANALYZE_TIMEOUT,
            )

            success = result.returncode == 0

            if success and sarif_path.exists():
                findings_count = self._count_sarif_findings(sarif_path)
                logger.info(f"✓ Custom queries completed: {findings_count} findings")

                return QueryResult(
                    success=True,
                    language=language,
                    database_path=database_path,
                    sarif_path=sarif_path,
                    findings_count=findings_count,
                    duration_seconds=time.time() - start_time,
                    errors=[],
                    suite_name="custom",
                )
            else:
                return QueryResult(
                    success=False,
                    language=language,
                    database_path=database_path,
                    sarif_path=None,
                    findings_count=0,
                    duration_seconds=time.time() - start_time,
                    errors=[result.stderr] if result.stderr else [],
                    suite_name="custom",
                )

        except Exception as e:
            logger.error(f"✗ Custom query execution failed: {e}")
            return QueryResult(
                success=False,
                language=language,
                database_path=database_path,
                sarif_path=None,
                findings_count=0,
                duration_seconds=time.time() - start_time,
                errors=[str(e)],
                suite_name="custom",
            )

    def analyze_all_databases(
        self,
        databases: Dict[str, Path],
        out_dir: Path,
        use_extended: bool = False,
        max_workers: Optional[int] = None
    ) -> Dict[str, QueryResult]:
        """
        Analyze multiple databases in parallel.

        Args:
            databases: Dict mapping language -> database path
            out_dir: Output directory
            use_extended: Use extended security suites
            max_workers: Max parallel workers

        Returns:
            Dict mapping language -> QueryResult
        """
        max_workers = max_workers or RaptorConfig.MAX_CODEQL_WORKERS
        results = {}

        logger.info(f"Analyzing {len(databases)} databases in parallel (max workers: {max_workers})")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_lang = {
                executor.submit(
                    self.run_suite,
                    db_path,
                    lang,
                    out_dir,
                    None,
                    use_extended
                ): lang
                for lang, db_path in databases.items()
            }

            # Collect results
            for future in as_completed(future_to_lang):
                lang = future_to_lang[future]
                try:
                    result = future.result()
                    results[lang] = result
                    if result.success:
                        logger.info(f"✓ {lang} analysis completed: {result.findings_count} findings")
                    else:
                        logger.error(f"✗ {lang} analysis failed")
                except Exception as e:
                    logger.error(f"✗ {lang} analysis raised exception: {e}")
                    results[lang] = QueryResult(
                        success=False,
                        language=lang,
                        database_path=databases[lang],
                        sarif_path=None,
                        findings_count=0,
                        duration_seconds=0.0,
                        errors=[str(e)],
                        suite_name="unknown",
                    )

        return results

    def _count_sarif_findings(self, sarif_path: Path) -> int:
        """Count findings in SARIF file."""
        try:
            with open(sarif_path) as f:
                sarif_data = json.load(f)

            count = 0
            for run in sarif_data.get("runs", []):
                count += len(run.get("results", []))

            return count
        except Exception as e:
            logger.debug(f"Failed to count SARIF findings: {e}")
            return 0

    def get_sarif_summary(self, sarif_path: Path) -> Dict:
        """
        Extract summary information from SARIF file.

        Returns:
            Dict with summary statistics
        """
        try:
            with open(sarif_path) as f:
                sarif_data = json.load(f)

            summary = {
                "total_findings": 0,
                "by_severity": {"error": 0, "warning": 0, "note": 0},
                "by_rule": {},
                "queries_executed": 0,
                "dataflow_paths": 0,
                "total_dataflow_steps": 0,
            }

            for run in sarif_data.get("runs", []):
                # Count findings by severity
                for result in run.get("results", []):
                    summary["total_findings"] += 1

                    level = result.get("level", "warning")
                    summary["by_severity"][level] = summary["by_severity"].get(level, 0) + 1

                    # Count by rule
                    rule_id = result.get("ruleId", "unknown")
                    summary["by_rule"][rule_id] = summary["by_rule"].get(rule_id, 0) + 1

                    # Count dataflow paths
                    code_flows = result.get("codeFlows", [])
                    if code_flows:
                        summary["dataflow_paths"] += 1
                        # Count total steps in all dataflow paths for this finding
                        for flow in code_flows:
                            for thread_flow in flow.get("threadFlows", []):
                                locations = thread_flow.get("locations", [])
                                summary["total_dataflow_steps"] += len(locations)

                # Count queries
                tool = run.get("tool", {})
                driver = tool.get("driver", {})
                rules = driver.get("rules", [])
                summary["queries_executed"] += len(rules)

            return summary

        except Exception as e:
            logger.warning(f"Failed to generate SARIF summary: {e}")
            return {}


def main():
    """CLI entry point for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="CodeQL Query Runner")
    parser.add_argument("--database", required=True, help="Database path")
    parser.add_argument("--language", required=True, help="Programming language")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--extended", action="store_true", help="Use extended security suite")
    parser.add_argument("--custom-queries", help="Path to custom query pack")
    args = parser.parse_args()

    runner = QueryRunner()

    if args.custom_queries:
        result = runner.run_custom_queries(
            Path(args.database),
            Path(args.custom_queries),
            Path(args.out),
            args.language
        )
    else:
        result = runner.run_suite(
            Path(args.database),
            args.language,
            Path(args.out),
            use_extended=args.extended
        )

    if result.success:
        print(f"\n✓ Analysis completed")
        print(f"  Findings: {result.findings_count}")
        print(f"  SARIF: {result.sarif_path}")
        print(f"  Duration: {result.duration_seconds:.1f}s")
    else:
        print(f"\n✗ Analysis failed")
        for error in result.errors:
            print(f"  {error}")


if __name__ == "__main__":
    main()
