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
    analyse_binary_context,
    probe_capability as probe_radare2_capability,
)

__all__ = [
    'CrashAnalyser',
    'CrashContext',
    'GDBDebugger',
    'BinaryContextMap',
    'BinaryUnderstand',
    'FunctionInfo',
    'analyse_binary_context',
    'probe_radare2_capability',
]
