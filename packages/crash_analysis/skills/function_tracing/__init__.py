"""
Function Call Tracing Skill

Instrument C/C++ with -finstrument-functions for execution tracing and Perfetto visualization.
"""

from pathlib import Path

SKILL_DIR = Path(__file__).parent
TRACE_INSTRUMENT_C = SKILL_DIR / "trace_instrument.c"
TRACE_TO_PERFETTO_CPP = SKILL_DIR / "trace_to_perfetto.cpp"

__all__ = ['SKILL_DIR', 'TRACE_INSTRUMENT_C', 'TRACE_TO_PERFETTO_CPP']
