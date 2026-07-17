"""Frida dynamic-instrumentation substrate for RAPTOR.

Hosts the host-side runner, CLI, and curated hook templates. The
runner attaches to (or spawns) a target via the frida Python bindings,
loads a JS hook script, captures events emitted via ``send(...)`` into
``events.jsonl``, and renders a short ``frida-report.md`` summary into
a lifecycle-managed run directory.

Not in scope:
  * Vendoring ``frida-server`` for any target architecture - the
    operator installs frida-server on the target; ``raptor doctor``
    reports availability of the host-side ``frida`` CLI.
  * LLM-autonomous instrumentation. A later integration plugs this
    substrate into ``/agentic`` and ``/validate``; the standalone
    runner is the prerequisite, not the consumer.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Iterator, Optional

__all__ = ["available", "parse_events"]

_available: Optional[bool] = None


def available(*, force: bool = False) -> bool:
    """True when frida is usable — either the CLI is on PATH or
    frida-python is importable (covers pipx/venv installs where
    the Python bindings aren't in RAPTOR's interpreter but the
    CLI wrapper is).

    Cached after first call. Pass ``force=True`` to re-probe (e.g.
    after a mid-session ``pip install frida-tools``). Pipeline consumers
    (``/agentic``, ``/validate``) gate dynamic-enrichment passes on this
    rather than try/except at every call site.
    """
    global _available
    if _available is not None and not force:
        return _available
    if shutil.which("frida") is not None:
        _available = True
        return True
    try:
        import frida  # type: ignore  # noqa: F401
        _available = True
    except ImportError:
        _available = False
    return _available


def parse_events(
    path: Path, *, max_lines: int = 500_000,
) -> Iterator[dict[str, Any]]:
    """Yield parsed records from an ``events.jsonl`` file.

    Skips malformed lines (truncated writes from a killed run).
    Consumers get structured dicts with ``ts``, ``type``, and
    template-dependent ``payload`` or ``error`` keys.

    Processing stops after *max_lines* non-empty lines to bound memory
    on very large event logs.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            count = 0
            for line in f:
                line = line.strip()
                if not line:
                    continue
                count += 1
                if count > max_lines:
                    return
                try:
                    yield json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError:
        return
