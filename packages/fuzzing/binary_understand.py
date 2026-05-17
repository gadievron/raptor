"""Compatibility wrapper for binary radare2 analysis.

The implementation now lives in packages.binary_analysis.radare2_understand
so non-fuzzing workflows can use the same binary context map.
"""

from packages.binary_analysis.radare2_understand import (
    BinaryContextMap,
    BinaryUnderstand,
    FunctionInfo,
    _DANGEROUS_IMPORTS,
    _ENTRY_POINT_HINTS,
    analyse_binary_context,
    probe_capability,
)

__all__ = [
    "BinaryContextMap",
    "BinaryUnderstand",
    "FunctionInfo",
    "_DANGEROUS_IMPORTS",
    "_ENTRY_POINT_HINTS",
    "analyse_binary_context",
    "probe_capability",
]
