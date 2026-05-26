"""Operator-facing summary of canonical Witnesses on disk.

A run can produce two kinds of Witness:

  * ``source=fuzz`` — AFL++ crashes recorded by ``raptor_fuzzing.py``
    after collection.
  * ``source=llm_emit_run`` — exploit PoCs emitted by
    ``CrashAnalysisAgent`` (and ``AutonomousSecurityAgentV2``),
    optionally with executed-outcome detail when
    ``--execute-exploits`` was passed.

Without this module, witnesses are written to
``<out>/witnesses/`` but no operator-facing surface mentions them
— the substrate is invisible. This module turns the on-disk
manifest set into a short summary block suitable for the end-of-
run console output.

Failures are non-fatal: a missing directory, an unreadable
manifest, an unexpected schema field — none should crash the
host's final-summary print. The witness records are downstream-
facing; the on-disk artefacts remain the canonical record either
way.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def build_witness_summary(
    witnesses_dir: Optional[Path],
) -> Dict[str, Any]:
    """Read the manifest set under ``witnesses_dir`` and group counts.

    Returns a structured dict consumers can render however suits
    their surface (console table, JSON report, HTML, etc.):

      ``{
          "total": int,
          "by_source": {<source>: int, ...},
          "by_outcome": {<outcome>: int, ...},
          "executed": int,    # how many witnesses observed an
                              # outcome other than NOT_RUN
          "compiled": int,    # how many had compiled=True in
                              # outcome_detail (LLM-emit-run only)
        }``

    Empty store / missing directory returns the zero-valued shape
    rather than raising — keeps the call site clean.
    """
    empty: Dict[str, Any] = {
        "total": 0,
        "by_source": {},
        "by_outcome": {},
        "executed": 0,
        "compiled": 0,
    }

    if witnesses_dir is None or not Path(witnesses_dir).is_dir():
        return empty

    try:
        from core.witness import WitnessStore, WitnessOutcome
    except ImportError as e:
        logger.debug("core.witness unavailable (%s) — empty summary", e)
        return empty

    try:
        store = WitnessStore(Path(witnesses_dir))
    except Exception as e:  # noqa: BLE001 — best-effort
        logger.warning(
            "build_witness_summary: WitnessStore open failed: "
            "%s: %s; empty summary returned", type(e).__name__, e,
        )
        return empty

    total = 0
    by_source: Dict[str, int] = {}
    by_outcome: Dict[str, int] = {}
    executed = 0
    compiled = 0

    try:
        for w in store.list_witnesses():
            total += 1
            src = w.source.value
            out = w.observed_outcome.value
            by_source[src] = by_source.get(src, 0) + 1
            by_outcome[out] = by_outcome.get(out, 0) + 1
            if w.observed_outcome is not WitnessOutcome.NOT_RUN:
                executed += 1
            if isinstance(w.outcome_detail, dict) \
                    and w.outcome_detail.get("compiled") is True:
                compiled += 1
    except Exception as e:  # noqa: BLE001 — best-effort iteration
        logger.warning(
            "build_witness_summary: iteration aborted at %d "
            "witnesses (%s: %s); returning partial counts",
            total, type(e).__name__, e,
        )

    return {
        "total": total,
        "by_source": by_source,
        "by_outcome": by_outcome,
        "executed": executed,
        "compiled": compiled,
    }


def render_witness_summary(
    witnesses_dir: Optional[Path],
    *,
    indent: str = "   ",
) -> str:
    """Render a console-friendly summary block; empty string when
    there are no witnesses.

    Format (indented to match the surrounding fuzz/agentic summary
    cadence):

        Witnesses recorded: <N>
           By source:
              fuzz: 12
              llm_emit_run: 7
           By outcome:
              exit_signal: 12
              not_run: 5
              sanitizer_report: 2
           Compiled: 5/7 LLM exploits
           Executed: 14/19

    The "Compiled" and "Executed" lines only show when there's an
    llm_emit_run witness in the store — otherwise they'd always
    read ``0/0`` and clutter the fuzz-only view.
    """
    s = build_witness_summary(witnesses_dir)
    if s["total"] == 0:
        return ""

    out = [f"Witnesses recorded: {s['total']}"]
    if s["by_source"]:
        out.append(f"{indent}By source:")
        for src, cnt in sorted(s["by_source"].items()):
            out.append(f"{indent}   {src}: {cnt}")
    if s["by_outcome"]:
        out.append(f"{indent}By outcome:")
        for outcome, cnt in sorted(s["by_outcome"].items()):
            out.append(f"{indent}   {outcome}: {cnt}")

    llm_count = s["by_source"].get("llm_emit_run", 0)
    if llm_count:
        out.append(
            f"{indent}Compiled: {s['compiled']}/{llm_count} "
            f"LLM exploits"
        )
        out.append(
            f"{indent}Executed: {s['executed']}/{s['total']}"
        )

    return "\n".join(out)
