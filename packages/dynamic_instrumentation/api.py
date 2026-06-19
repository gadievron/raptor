"""Programmatic API for RAPTOR dynamic instrumentation (Frida).

Callable both from the ``/frida`` skill (``python3 -c "from
packages.dynamic_instrumentation.api import ..."``) and from other packages
(fuzzing crash triage, exploit_feasibility runtime confirmation). Mirrors the
``packages/exploit_feasibility/api.py`` shape: small, well-typed entry points
that hide the sandbox/driver mechanics.

Posture: targets are spawned (RAPTOR launches them), not attached to arbitrary
running PIDs - RAPTOR instruments binaries the operator chose, under the
sandbox, network blocked by default. See ``runner.py`` for the isolation model.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import agents, coverage as _coverage, runner

logger = logging.getLogger(__name__)


def is_available() -> bool:
    """True when Frida instrumentation can run on this host (binding present)."""
    from .capability import probe
    return probe().available


def trace_functions(
    binary: str,
    symbols: List[str],
    *,
    output_dir: str,
    timeout: float = 30.0,
    spawn_args: Optional[List[str]] = None,
    profile: str = "debug",
) -> Dict[str, Any]:
    """Spawn ``binary`` and trace entry into each named function, capturing the
    first four integer-width arguments. Returns a dict with ``trace`` (one
    record per call), ``unresolved`` symbols, ``events_path``, ``profile_used``
    and the raw driver ``result``."""
    if not symbols:
        raise ValueError("trace_functions: at least one symbol required")
    agent_js = agents.trace_agent(symbols)
    run = runner.run_agent(
        binary, agent_js, output_dir=output_dir, timeout=timeout,
        spawn_args=spawn_args, profile=profile,
    )
    trace: List[dict] = []
    unresolved: List[str] = []
    try:
        for line in Path(run["events_path"]).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            if msg.get("type") != "send":
                continue
            p = msg.get("payload") or {}
            if p.get("error"):
                unresolved.append(p.get("fn", "?"))
            elif "fn" in p:
                trace.append({"fn": p["fn"], "args": p.get("args", []),
                              "addr": p.get("addr")})
    except (OSError, ValueError):
        pass
    return {
        "binary": binary,
        "trace": trace,
        "unresolved": sorted(set(unresolved)),
        "call_count": len(trace),
        "events_path": run["events_path"],
        "profile_used": run["profile_used"],
        "result": run["result"],
    }


def collect_coverage(
    binary: str,
    *,
    output_dir: str,
    modules: Optional[List[str]] = None,
    timeout: float = 30.0,
    spawn_args: Optional[List[str]] = None,
    profile: str = "debug",
    store: Any = None,
    checklist: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Spawn ``binary`` under Stalker block-coverage, write a drcov file, and
    (when ``store`` is given) resolve it to source and mark the CoverageStore
    via the existing ``import_drcov`` path. Returns drcov path, record count
    and (if marked) source-line count.

    ``store``/``checklist`` are the standard ``core.coverage`` objects; omit
    them to just produce the drcov file (e.g. for Lighthouse/IDA)."""
    agent_js = agents.coverage_agent(modules)
    run = runner.run_agent(
        binary, agent_js, output_dir=output_dir,
        events_name="frida-coverage-events.jsonl", agent_name="coverage.js",
        timeout=timeout, spawn_args=spawn_args, profile=profile,
    )
    drcov_path = str(Path(output_dir) / "frida.drcov")
    n_bbs = _coverage.write_drcov(run["events_path"], drcov_path)
    out: Dict[str, Any] = {
        "binary": binary,
        "drcov_path": drcov_path if n_bbs else None,
        "basic_blocks": n_bbs,
        "events_path": run["events_path"],
        "profile_used": run["profile_used"],
        "result": run["result"],
    }
    if n_bbs and store is not None:
        out["lines_marked"] = _coverage.import_to_store(
            store, drcov_path, binary, checklist or {}, tool="frida")
    return out
