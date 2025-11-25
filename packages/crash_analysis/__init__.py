"""
RAPTOR Crash Analysis Package

Provides deep root-cause analysis for crashes from bug reports or fuzzing output.
"""

from .orchestrator import CrashAnalysisOrchestrator
from .bug_fetcher import BugFetcher, BugReport
from .build_detector import BuildDetector

__all__ = [
    'CrashAnalysisOrchestrator',
    'BugFetcher',
    'BugReport',
    'BuildDetector',
]
