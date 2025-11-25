"""
Crash Analysis Skills

Instrumentation and debugging tools for crash analysis:
- function_tracing: GCC -finstrument-functions based tracing
- gcov_coverage: Code coverage with gcov
- rr_debugger: Deterministic record-replay debugging
"""

from pathlib import Path

SKILLS_DIR = Path(__file__).parent

__all__ = ['SKILLS_DIR']
