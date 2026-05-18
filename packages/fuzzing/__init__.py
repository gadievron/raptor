#!/usr/bin/env python3
"""RAPTOR Fuzzing Package.

Multi-fuzzer orchestration with capability detection, target identification,
and harness generation.
"""

from .afl_runner import AFLRunner
from .crash_collector import CrashCollector, Crash
from .corpus_manager import CorpusManager
from .capability import CapabilityReport, probe as probe_capabilities, select_fuzzer
from .target_detector import TargetInfo, detect as detect_target
from .orchestrator import FuzzingOrchestrator, CampaignPlan
from .libfuzzer_runner import LibFuzzerRunner, LibFuzzerResult, LibFuzzerStats
from .harness_generator import HarnessGenerator, HarnessSpec, GeneratedHarness
from .telemetry import FuzzingTelemetry, CampaignStats, FuzzEvent
from packages.binary_analysis import (
    BinaryUnderstand,
    BinaryContextMap,
    FunctionInfo as BinaryFunctionInfo,
    analyse_binary_context,
)

__all__ = [
    "AFLRunner",
    "CrashCollector",
    "Crash",
    "CorpusManager",
    "CapabilityReport",
    "probe_capabilities",
    "select_fuzzer",
    "TargetInfo",
    "detect_target",
    "FuzzingOrchestrator",
    "CampaignPlan",
    "LibFuzzerRunner",
    "LibFuzzerResult",
    "LibFuzzerStats",
    "HarnessGenerator",
    "HarnessSpec",
    "GeneratedHarness",
    "FuzzingTelemetry",
    "CampaignStats",
    "FuzzEvent",
    "BinaryUnderstand",
    "BinaryContextMap",
    "BinaryFunctionInfo",
    "analyse_binary_context",
]
