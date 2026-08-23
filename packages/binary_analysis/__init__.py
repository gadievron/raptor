#!/usr/bin/env python3
"""
RAPTOR Binary Analysis Package

Provides binary analysis capabilities including crash analysis, debugging, and disassembly.
"""

from .radare2_understand import (
    BinaryContextMap,
    BinaryUnderstand,
    FunctionInfo,
    RecoveredClassInfo,
    RecoveredMethodInfo,
    analyse_binary_context,
    probe_capability as probe_radare2_capability,
)
from core.evidence import BinaryEvidenceRecord, EvidenceTier
from .graph_store import BinaryGraphStore, graph_summary as binary_graph_summary
from .manifest import BinaryManifest, RuntimeSignal, build_manifest
from .ingress import ExternalIngressCandidate, recover_external_ingress
from .fuzz_suitability import assess_fuzz_suitability
from .harness import generate_binary_harness, render_harness_report
from .parser_boundary import extract_parser_boundaries
from .topology import build_component_topology, discover_sibling_artifacts
from .investigation import build_investigation, render_investigation_report, write_investigation
from .pipeline import (
    BinaryAnalysisResult,
    analyse_blackbox_binary,
    append_fuzz_evidence_to_run,
    append_runtime_evidence_to_run,
)


def __getattr__(name):
    if name == "CrashAnalyser":
        from .crash_analyser import CrashAnalyser
        return CrashAnalyser
    if name == "CrashContext":
        from .crash_analyser import CrashContext
        return CrashContext
    if name == "GDBDebugger":
        from .debugger import GDBDebugger
        return GDBDebugger
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


__all__ = [
    'BinaryAnalysisResult',
    'BinaryContextMap',
    'BinaryEvidenceRecord',
    'BinaryGraphStore',
    'BinaryManifest',
    'BinaryUnderstand',
    'CrashAnalyser',
    'CrashContext',
    'EvidenceTier',
    'ExternalIngressCandidate',
    'FunctionInfo',
    'GDBDebugger',
    'RecoveredClassInfo',
    'RecoveredMethodInfo',
    'RuntimeSignal',
    'analyse_binary_context',
    'analyse_blackbox_binary',
    'append_fuzz_evidence_to_run',
    'append_runtime_evidence_to_run',
    'assess_fuzz_suitability',
    'binary_graph_summary',
    'build_component_topology',
    'build_investigation',
    'build_manifest',
    'discover_sibling_artifacts',
    'extract_parser_boundaries',
    'generate_binary_harness',
    'probe_radare2_capability',
    'recover_external_ingress',
    'render_harness_report',
    'render_investigation_report',
    'write_investigation',
]
