#!/usr/bin/env python3
"""RAPTOR Fuzzing Package.

Multi-fuzzer orchestration with capability detection, target identification,
and harness generation.
"""

from .afl_runner import AFLRunner
from .crash_collector import CrashCollector, Crash
from .corpus_manager import CorpusManager
from .seed_corpus import (
    DEFAULT_MAX_FILE_SIZE,
    SeedCorpusOptions,
    prepare_builtin_seed_corpus,
    prepare_seed_corpus,
)
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
    "DEFAULT_MAX_FILE_SIZE",
    "AFLRunner",
    "BinaryContextMap",
    "BinaryFunctionInfo",
    "BinaryUnderstand",
    "CampaignPlan",
    "CampaignStats",
    "CapabilityReport",
    "CorpusManager",
    "Crash",
    "CrashCollector",
    "FuzzEvent",
    "FuzzingOrchestrator",
    "FuzzingTelemetry",
    "GeneratedHarness",
    "HarnessGenerator",
    "HarnessSpec",
    "LibFuzzerResult",
    "LibFuzzerRunner",
    "LibFuzzerStats",
    "SeedCorpusOptions",
    "TargetInfo",
    "analyse_binary_context",
    "detect_target",
    "prepare_builtin_seed_corpus",
    "prepare_seed_corpus",
    "probe_capabilities",
    "select_fuzzer",
]
