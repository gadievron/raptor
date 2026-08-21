"""Session-level UX helpers.

Currently one concern: the interactivity gate that decides whether the
running session may present structured operator prompts
(:mod:`core.ux.interactivity`).
"""

from core.ux.interactivity import (
    INTERACTIVE,
    NON_INTERACTIVE,
    NONINTERACTIVE_ENV,
    session_interactivity,
    session_may_ask,
)

__all__ = [
    "INTERACTIVE",
    "NON_INTERACTIVE",
    "NONINTERACTIVE_ENV",
    "session_interactivity",
    "session_may_ask",
]
