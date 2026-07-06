#!/usr/bin/env python3
"""
RAPTOR Binary Analysis Package

Provides binary analysis capabilities including crash analysis, debugging, and disassembly.
"""

from .crash_analyser import CrashAnalyser, CrashContext
from .debugger import GDBDebugger
from .radare2_understand import (
    BinaryContextMap,
    BinaryUnderstand,
    FunctionInfo,
    RecoveredClassInfo,
    RecoveredMethodInfo,
    analyse_binary_context,
    probe_capability as probe_radare2_capability,
)
from .evidence import EvidenceRecord, EvidenceTier
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

__all__ = [
    'CrashAnalyser',
    'CrashContext',
    'GDBDebugger',
    'BinaryContextMap',
    'BinaryUnderstand',
    'FunctionInfo',
    'RecoveredClassInfo',
    'RecoveredMethodInfo',
    'analyse_binary_context',
    'probe_radare2_capability',
    'BinaryAnalysisResult',
    'BinaryGraphStore',
    'BinaryManifest',
    'EvidenceRecord',
    'EvidenceTier',
    'RuntimeSignal',
    'ExternalIngressCandidate',
    'analyse_blackbox_binary',
    'append_fuzz_evidence_to_run',
    'append_runtime_evidence_to_run',
    'binary_graph_summary',
    'build_manifest',
    'recover_external_ingress',
    'assess_fuzz_suitability',
    'generate_binary_harness',
    'render_harness_report',
    'extract_parser_boundaries',
    'build_component_topology',
    'discover_sibling_artifacts',
    'build_investigation',
    'render_investigation_report',
    'write_investigation',
]
