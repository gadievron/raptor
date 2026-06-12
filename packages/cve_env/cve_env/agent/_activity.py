"""Tool-activity tracker for the connectivity circuit-breaker.

The SDK is SILENT during a long in-process MCP tool call (``include_partial_
messages`` is off and there is no transport keepalive), so the inter-message
idle-timeout in ``llm._run_query_once`` must EXCLUDE tool-execution time or it
would false-abort legitimate 600-900s builds (docker_build / compose /
image_resolve).

The tool wrappers in ``agent/tools.py`` mark start/end here. The idle watchdog
never fires while a tool is in flight, and otherwise measures idle from the
last tool's END — so it bounds ONLY true API-wait gaps (a dead/unreachable
Anthropic endpoint).

Single-process, single-agent-per-CVE model → a plain module global is correct
(each ``cve-env build`` is its own subprocess; reset() is called per query).
"""

from __future__ import annotations

import time

_in_flight: int = 0
_last_activity: float = 0.0
# Monotonic timestamp when the CURRENT in-flight batch began (the 0→1
# transition); 0.0 when idle. Lets the connectivity breaker bound how long a
# single tool may stay in flight (``inflight_age``) so a WEDGED handler (e.g. a
# docker subprocess stuck on a dead VM socket that run_with_timeout could not
# reap) trips the breaker instead of being exempted to the external wall.
_oldest_start: float = 0.0


def reset() -> None:
    """Reset state at the start of each SDK query (called by _run_query_once)."""
    global _in_flight, _last_activity, _oldest_start
    _in_flight = 0
    _last_activity = time.monotonic()
    _oldest_start = 0.0


def tool_start() -> None:
    """Mark that an MCP tool handler has begun executing."""
    global _in_flight, _oldest_start
    if _in_flight == 0:
        _oldest_start = time.monotonic()
    _in_flight += 1


def tool_end() -> None:
    """Mark that an MCP tool handler has finished (stamps last-activity)."""
    global _in_flight, _last_activity, _oldest_start
    _in_flight = max(0, _in_flight - 1)
    _last_activity = time.monotonic()
    if _in_flight == 0:
        _oldest_start = 0.0


def tool_in_flight() -> bool:
    """True iff at least one MCP tool handler is currently executing."""
    return _in_flight > 0


def inflight_age() -> float:
    """Seconds the OLDEST currently-in-flight tool has been running (0.0 if idle).

    Measured from the 0→1 transition, so nested start/start/end report the age of
    the FIRST start until the count returns to zero. Used by the breaker's
    tool-in-flight MAX bound."""
    if _in_flight <= 0:
        return 0.0
    return time.monotonic() - _oldest_start


def last_activity() -> float:
    """``time.monotonic()`` timestamp of the most recent tool end / reset."""
    return _last_activity
