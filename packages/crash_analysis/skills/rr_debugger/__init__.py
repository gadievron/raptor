"""
rr Deterministic Debugger Skill

Record-replay debugging with reverse execution capabilities.
"""

from pathlib import Path

SKILL_DIR = Path(__file__).parent
CRASH_TRACE_PY = SKILL_DIR / "crash_trace.py"

__all__ = ['SKILL_DIR', 'CRASH_TRACE_PY']
