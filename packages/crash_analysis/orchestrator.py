"""
Crash Analysis Orchestrator

Main workflow engine for crash root-cause analysis.
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from .bug_fetcher import BugFetcher, BugReport, load_local_crashes
from .build_detector import BuildDetector, BuildConfig, BuildSystem, run_custom_build


@dataclass
class CrashAnalysisConfig:
    """Configuration for crash analysis."""

    # Input mode: either bug_url + git_url, or crash_dir + repo
    bug_url: Optional[str] = None
    git_url: Optional[str] = None
    crash_dir: Optional[Path] = None
    repo_path: Optional[Path] = None

    # Build options
    branch: str = "main"
    build_cmd: Optional[str] = None

    # Output
    output_dir: Optional[Path] = None

    # Analysis options
    enable_function_tracing: bool = True
    enable_coverage: bool = True
    enable_rr_recording: bool = True

    def validate(self) -> None:
        """Validate configuration."""
        if self.bug_url and self.git_url:
            # External bug mode
            pass
        elif self.crash_dir and self.repo_path:
            # Local crash mode
            if not Path(self.crash_dir).exists():
                raise ValueError(f"Crash directory does not exist: {self.crash_dir}")
            if not Path(self.repo_path).exists():
                raise ValueError(f"Repository path does not exist: {self.repo_path}")
        else:
            raise ValueError(
                "Must specify either (--bug-url + --git-url) or (--crash-dir + --repo)"
            )


@dataclass
class CrashAnalysisResult:
    """Result of crash analysis."""

    working_dir: Path
    bug_report: Optional[BugReport] = None
    crashes: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Path] = field(default_factory=list)
    confirmed_hypothesis: Optional[Path] = None
    status: str = "pending"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "working_dir": str(self.working_dir),
            "bug_report": self.bug_report.to_dict() if self.bug_report else None,
            "crashes": self.crashes,
            "hypotheses": [str(h) for h in self.hypotheses],
            "confirmed_hypothesis": str(self.confirmed_hypothesis) if self.confirmed_hypothesis else None,
            "status": self.status,
            "error": self.error,
        }


class CrashAnalysisOrchestrator:
    """
    Orchestrate the crash analysis workflow.

    Supports two modes:
    1. External bug mode: Fetch bug from URL, clone repo, analyze
    2. Local crash mode: Analyze crashes from fuzzing output
    """

    def __init__(self, config: CrashAnalysisConfig):
        """
        Initialize orchestrator.

        Args:
            config: Analysis configuration
        """
        self.config = config
        config.validate()

        # Setup output directory
        if config.output_dir:
            self.output_dir = Path(config.output_dir)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = Path("out") / f"crash-analysis-{timestamp}"

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Working directories
        self.repo_dir: Optional[Path] = None
        self.traces_dir = self.output_dir / "traces"
        self.gcov_dir = self.output_dir / "gcov"
        self.rr_dir = self.output_dir / "rr-trace"
        self.hypotheses_dir = self.output_dir / "hypotheses"

        # Results
        self.result = CrashAnalysisResult(working_dir=self.output_dir)

    def run(self) -> CrashAnalysisResult:
        """
        Run the crash analysis workflow.

        Returns:
            CrashAnalysisResult with analysis outcomes
        """
        try:
            if self.config.bug_url and self.config.git_url:
                self._run_external_bug_mode()
            else:
                self._run_local_crash_mode()

            self.result.status = "completed"

        except Exception as e:
            self.result.status = "failed"
            self.result.error = str(e)
            raise

        finally:
            # Save result summary
            self._save_result()

        return self.result

    def _run_external_bug_mode(self) -> None:
        """Run analysis for external bug report."""
        print(f"\n[*] Running crash analysis for bug: {self.config.bug_url}")
        print(f"[*] Repository: {self.config.git_url}")
        print(f"[*] Output directory: {self.output_dir}\n")

        # Step 1: Fetch bug report
        print("[Step 1/8] Fetching bug report...")
        fetcher = BugFetcher()
        self.result.bug_report = fetcher.fetch(self.config.bug_url)
        print(f"  Title: {self.result.bug_report.title}")
        print(f"  Crash signal: {self.result.bug_report.crash_signal or 'unknown'}")

        # Save bug report
        bug_report_file = self.output_dir / "bug_report.json"
        with open(bug_report_file, "w") as f:
            json.dump(self.result.bug_report.to_dict(), f, indent=2)

        # Download attachments
        if self.result.bug_report.attachments or self.result.bug_report.crasher_input_urls:
            attachments_dir = self.output_dir / "attachments"
            downloaded = fetcher.download_attachments(self.result.bug_report, attachments_dir)
            print(f"  Downloaded {len(downloaded)} attachment(s)")

        # Step 2: Clone repository
        print("\n[Step 2/8] Cloning repository...")
        self.repo_dir = self.output_dir / "repo"
        self._clone_repository()
        print(f"  Cloned to: {self.repo_dir}")

        # Step 3: Build with ASan
        print("\n[Step 3/8] Building with AddressSanitizer...")
        self._build_project()

        # Step 4: Reproduce crash
        print("\n[Step 4/8] Reproducing crash...")
        self._reproduce_crash()

        # Step 5-8: Generate traces and analysis
        self._run_analysis_steps()

    def _run_local_crash_mode(self) -> None:
        """Run analysis for local crash directory."""
        print(f"\n[*] Running crash analysis for local crashes")
        print(f"[*] Crash directory: {self.config.crash_dir}")
        print(f"[*] Repository: {self.config.repo_path}")
        print(f"[*] Output directory: {self.output_dir}\n")

        # Step 1: Load crashes
        print("[Step 1/7] Loading crashes from directory...")
        self.result.crashes = load_local_crashes(self.config.crash_dir)
        print(f"  Found {len(self.result.crashes)} crash input(s)")

        if not self.result.crashes:
            raise RuntimeError("No crash inputs found in crash directory")

        # Use existing repo
        self.repo_dir = Path(self.config.repo_path).resolve()

        # Step 2: Rebuild if needed
        print("\n[Step 2/7] Checking build with AddressSanitizer...")
        self._build_project()

        # Step 3-7: Analyze each crash
        for i, crash in enumerate(self.result.crashes):
            print(f"\n[*] Analyzing crash {i+1}/{len(self.result.crashes)}: {crash['name']}")
            crash_output_dir = self.output_dir / f"crash_{i:04d}"
            crash_output_dir.mkdir(parents=True, exist_ok=True)

            # Copy crash input
            crash_input = crash_output_dir / "input"
            shutil.copy(crash["path"], crash_input)
            crash["analysis_dir"] = str(crash_output_dir)

            # Run analysis for this crash
            self._analyze_single_crash(crash_input, crash_output_dir)

    def _clone_repository(self) -> None:
        """Clone the git repository."""
        cmd = ["git", "clone", "--depth", "1"]

        if self.config.branch:
            cmd.extend(["--branch", self.config.branch])

        cmd.extend([self.config.git_url, str(self.repo_dir)])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to clone repository: {result.stderr}")

        # Create analysis branch
        branch_name = f"crash-analysis-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=self.repo_dir,
            capture_output=True,
        )

    def _build_project(self) -> None:
        """Build the project with ASan and debug symbols."""
        if self.config.build_cmd:
            # Use custom build command
            success = run_custom_build(
                self.config.build_cmd,
                self.repo_dir,
                env_overrides={
                    "CFLAGS": "-fsanitize=address -g -O1 -fno-omit-frame-pointer",
                    "CXXFLAGS": "-fsanitize=address -g -O1 -fno-omit-frame-pointer",
                    "LDFLAGS": "-fsanitize=address",
                },
            )
            if not success:
                raise RuntimeError("Custom build command failed")
        else:
            # Auto-detect build system
            build_dir = self.output_dir / "build"
            detector = BuildDetector(self.repo_dir, build_dir)
            config = detector.create_config(
                enable_asan=True,
                enable_debug=True,
                enable_coverage=self.config.enable_coverage,
            )

            if not detector.configure_and_build(config):
                raise RuntimeError("Build failed")

    def _reproduce_crash(self) -> None:
        """Attempt to reproduce the crash from bug report."""
        bug = self.result.bug_report

        if bug.reproduction_command:
            print(f"  Reproduction command: {bug.reproduction_command}")
            # Note: Actual reproduction would need the built binary path
            # This is a placeholder - the Claude agent will handle actual reproduction
            print("  [Note: Reproduction will be handled by Claude agent]")
        else:
            print("  No reproduction command found in bug report")
            print("  [Note: Manual reproduction may be required]")

    def _run_analysis_steps(self) -> None:
        """Run the analysis steps (tracing, coverage, rr, hypothesis generation)."""
        # Create directories
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self.gcov_dir.mkdir(parents=True, exist_ok=True)
        self.rr_dir.mkdir(parents=True, exist_ok=True)
        self.hypotheses_dir.mkdir(parents=True, exist_ok=True)

        print("\n[Step 5/8] Setting up function tracing...")
        if self.config.enable_function_tracing:
            print("  Function tracing will be configured by Claude agent")

        print("\n[Step 6/8] Setting up coverage analysis...")
        if self.config.enable_coverage:
            print("  Coverage data will be collected by Claude agent")

        print("\n[Step 7/8] Setting up rr recording...")
        if self.config.enable_rr_recording:
            print("  rr recording will be created by Claude agent")

        print("\n[Step 8/8] Preparing for root-cause analysis...")
        print("  Claude crash-analyzer agent will generate hypotheses")
        print("  Claude crash-analyzer-checker agent will validate")

        # Create analysis context file for Claude agents
        self._create_analysis_context()

    def _analyze_single_crash(self, crash_input: Path, output_dir: Path) -> None:
        """Analyze a single crash input."""
        traces_dir = output_dir / "traces"
        gcov_dir = output_dir / "gcov"
        rr_dir = output_dir / "rr-trace"
        hypotheses_dir = output_dir / "hypotheses"

        for d in [traces_dir, gcov_dir, rr_dir, hypotheses_dir]:
            d.mkdir(parents=True, exist_ok=True)

        print(f"  - Crash input: {crash_input}")
        print(f"  - Output: {output_dir}")
        print("  - Analysis will be performed by Claude agents")

        # Create analysis context for this crash
        context = {
            "crash_input": str(crash_input),
            "repo_path": str(self.repo_dir),
            "traces_dir": str(traces_dir),
            "gcov_dir": str(gcov_dir),
            "rr_dir": str(rr_dir),
            "hypotheses_dir": str(hypotheses_dir),
        }

        context_file = output_dir / "analysis_context.json"
        with open(context_file, "w") as f:
            json.dump(context, f, indent=2)

    def _create_analysis_context(self) -> None:
        """Create context file for Claude agents."""
        context = {
            "working_dir": str(self.output_dir),
            "repo_path": str(self.repo_dir),
            "traces_dir": str(self.traces_dir),
            "gcov_dir": str(self.gcov_dir),
            "rr_dir": str(self.rr_dir),
            "hypotheses_dir": str(self.hypotheses_dir),
            "bug_report": self.result.bug_report.to_dict() if self.result.bug_report else None,
            "crashes": self.result.crashes,
            "config": {
                "enable_function_tracing": self.config.enable_function_tracing,
                "enable_coverage": self.config.enable_coverage,
                "enable_rr_recording": self.config.enable_rr_recording,
            },
        }

        context_file = self.output_dir / "analysis_context.json"
        with open(context_file, "w") as f:
            json.dump(context, f, indent=2)

        print(f"\n[*] Analysis context saved to: {context_file}")
        print("[*] Claude agents can now perform root-cause analysis")

    def _save_result(self) -> None:
        """Save analysis result."""
        result_file = self.output_dir / "result.json"
        with open(result_file, "w") as f:
            json.dump(self.result.to_dict(), f, indent=2)


def run_crash_analysis(
    bug_url: Optional[str] = None,
    git_url: Optional[str] = None,
    crash_dir: Optional[str] = None,
    repo_path: Optional[str] = None,
    branch: str = "main",
    build_cmd: Optional[str] = None,
    output_dir: Optional[str] = None,
) -> CrashAnalysisResult:
    """
    Convenience function to run crash analysis.

    Args:
        bug_url: URL to bug report
        git_url: Git repository URL
        crash_dir: Local crash directory
        repo_path: Local repository path
        branch: Git branch to checkout
        build_cmd: Custom build command
        output_dir: Output directory

    Returns:
        CrashAnalysisResult
    """
    config = CrashAnalysisConfig(
        bug_url=bug_url,
        git_url=git_url,
        crash_dir=Path(crash_dir) if crash_dir else None,
        repo_path=Path(repo_path) if repo_path else None,
        branch=branch,
        build_cmd=build_cmd,
        output_dir=Path(output_dir) if output_dir else None,
    )

    orchestrator = CrashAnalysisOrchestrator(config)
    return orchestrator.run()
