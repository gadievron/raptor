"""System prompts for /understand multi-model dispatch.

Prompts live as Python module-level strings rather than markdown so:
- They're versioned with the dispatch code (no skill-prose drift).
- They're easy to format with safe interpolation (no f-string in the
  middle of a prompt — we use explicit .format() with a fixed key set).
- Tests can import them.
"""

from packages.code_understanding.prompts.hunt_system import HUNT_SYSTEM_PROMPT
from packages.code_understanding.prompts.trace_system import TRACE_SYSTEM_PROMPT

__all__ = [
    "HUNT_SYSTEM_PROMPT",
    "TRACE_SYSTEM_PROMPT",
]
