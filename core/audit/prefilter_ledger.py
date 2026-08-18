"""Per-run ledger of prefilter kill decisions.

The cheapest gates in the funnel — ``_is_trivially_clean``, the
trivial-wrapper check, the sink-unreachable gate, and the triage SKIP
bucket — kill functions before any LLM or verification tool ever sees
them. Until now those decisions left only a free-text ``body`` marker
in the journal and an aggregate counter: no structured record of WHAT
was killed by WHICH gate, and no measurement of whether the gates are
right.

This module:

* records every kill as a structured row (file, function, gate,
  reason, language, sloc);
* spot-audits a bounded sample of C/C++ kills against the
  compiler-analyzer channel (``run_compiler_analyzer_sweep``):
  analyzer-quiet on the function corroborates the kill,
  analyzer-noisy contradicts it — contradictions are REPORTED, not
  auto-reverted;
* writes ``<out_dir>/prefilter-kills.jsonl`` plus a summary block so
  the kill decisions carry an error bar instead of disappearing
  silently.

Everything is best-effort: a ledger failure must never affect the run.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

GATE_TRIVIALLY_CLEAN = "trivially_clean"
GATE_TRIVIAL_WRAPPER = "trivial_wrapper"
GATE_SINK_UNREACHABLE = "sink_unreachable"
GATE_TRIAGE_SKIP = "triage_skip"
GATE_OTHER = "other"

LEDGER_FILENAME = "prefilter-kills.jsonl"

# Spot-audit budget: how many killed C/C++ functions get one
# compiler-analyzer corroboration run each. Deliberately small — the
# analyzer costs up to ~2 min per TU worst-case; this is an error-bar
# sample, not a re-review pass.
CORROBORATION_SAMPLE = 3

# The corroboration family: null-dereference is the broadest
# ``reliable=True`` family in COMPILER_CWE_MAP (analyzer-quiet is
# meaningful evidence, not just absence of a narrow check).
CORROBORATION_CWE = "CWE-476"

_C_EXTENSIONS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")


def gate_for_skip_reason(reason: str) -> str:
    """Map a ``PrefilterResult.skip_reason`` to its gate name."""
    r = (reason or "").lower()
    if r.startswith("simple accessor"):
        return GATE_TRIVIALLY_CLEAN
    if "wrapper" in r:
        return GATE_TRIVIAL_WRAPPER
    if "no sink path" in r:
        return GATE_SINK_UNREACHABLE
    return GATE_OTHER


def make_kill_record(
    *,
    file: str,
    function: str,
    gate: str,
    reason: str,
    language: str = "",
    sloc: int = 0,
    line_start: int = 0,
    line_end: int = 0,
) -> dict[str, Any]:
    """One structured ledger row for a killed function."""
    return {
        "file": file,
        "function": function,
        "gate": gate,
        "reason": reason,
        "language": language,
        "sloc": sloc,
        "line_start": line_start,
        "line_end": line_end,
        "corroboration": "not_sampled",
    }


def _sample(records: list[dict[str, Any]], size: int) -> list[dict[str, Any]]:
    """Deterministic, evenly-strided sample of C/C++ kills.

    Sorted order + striding keeps the sample reproducible across
    re-runs of the same ledger (no RNG state) while still spreading it
    over files rather than clustering on the first directory.
    """
    eligible = sorted(
        (
            r for r in records
            if r.get("file", "").lower().endswith(_C_EXTENSIONS)
            and r.get("line_start", 0)
        ),
        key=lambda r: (r.get("file", ""), r.get("function", "")),
    )
    if not eligible or size <= 0:
        return []
    if len(eligible) <= size:
        return eligible
    stride = len(eligible) / size
    return [eligible[int(i * stride)] for i in range(size)]


def corroborate_sample(
    records: list[dict[str, Any]],
    target_path: Path,
    *,
    out_dir: Path | None = None,
    sample_size: int = CORROBORATION_SAMPLE,
) -> int:
    """Spot-audit a sample of kills against the compiler analyzer.

    Mutates the sampled records in place:

    * ``corroboration``: ``analyzer_quiet`` (kill corroborated) /
      ``analyzer_noisy`` (analyzer found a diagnostic in the killed
      function — contradiction, reported for the operator) /
      ``analyzer_inconclusive`` / ``analyzer_error``.
    * ``corroboration_channel``: e.g. ``compiler:CWE-476``.

    Returns the number of functions actually corroborated (any
    outcome). Skips fast when no analyzer is installed.
    """
    try:
        from core.audit.compiler_sweep import (
            _clang_path,
            _gcc_analyzer,
            run_compiler_analyzer_sweep,
        )
    except ImportError:
        return 0

    try:
        if _gcc_analyzer() is None and _clang_path() is None:
            logger.debug(
                "prefilter ledger: no compiler analyzer installed — "
                "corroboration skipped",
            )
            return 0
    except Exception:  # noqa: BLE001 — probe failure = channel unavailable
        return 0

    sampled = _sample(records, sample_size)
    audited = 0
    for rec in sampled:
        try:
            sweep = run_compiler_analyzer_sweep(
                target_path=Path(target_path),
                file_path=rec["file"],
                function_name=rec["function"],
                hypothesis="",
                cwe=CORROBORATION_CWE,
                line_start=rec.get("line_start", 0),
                line_end=rec.get("line_end", 0),
                out_dir=out_dir,
            )
        except Exception:
            logger.debug(
                "prefilter ledger: corroboration failed for %s:%s",
                rec.get("file"), rec.get("function"), exc_info=True,
            )
            rec["corroboration"] = "analyzer_error"
            rec["corroboration_channel"] = f"compiler:{CORROBORATION_CWE}"
            audited += 1
            continue

        outcome = getattr(sweep, "outcome", "error")
        if outcome == "confirmed":
            rec["corroboration"] = "analyzer_noisy"
        elif outcome == "refuted":
            rec["corroboration"] = "analyzer_quiet"
        elif outcome == "inconclusive":
            rec["corroboration"] = "analyzer_inconclusive"
        else:
            rec["corroboration"] = "analyzer_error"
        rec["corroboration_channel"] = f"compiler:{CORROBORATION_CWE}"
        audited += 1

    return audited


def summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate the ledger: per-gate counts + corroboration outcome."""
    by_gate: dict[str, int] = {}
    corroborated = 0
    contradicted = 0
    sampled = 0
    for r in records:
        by_gate[r.get("gate", GATE_OTHER)] = (
            by_gate.get(r.get("gate", GATE_OTHER), 0) + 1
        )
        c = r.get("corroboration", "not_sampled")
        if c != "not_sampled":
            sampled += 1
        if c == "analyzer_quiet":
            corroborated += 1
        elif c == "analyzer_noisy":
            contradicted += 1
    return {
        "total_kills": len(records),
        "by_gate": by_gate,
        "sampled": sampled,
        "corroborated": corroborated,
        "contradicted": contradicted,
    }


def write_ledger(
    records: list[dict[str, Any]],
    out_dir: Path,
) -> Path | None:
    """Write the ledger JSONL (summary row first). Best-effort."""
    if not records:
        return None
    try:
        path = Path(out_dir) / LEDGER_FILENAME
        with path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(
                {"summary": summarise(records)}, sort_keys=True,
            ) + "\n")
            for rec in records:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return path
    except Exception:
        logger.debug("prefilter ledger write failed", exc_info=True)
        return None


def format_summary(records: list[dict[str, Any]]) -> str:
    """One operator-facing log line for the end-of-run report."""
    s = summarise(records)
    gates = ", ".join(
        f"{g}={n}" for g, n in sorted(s["by_gate"].items())
    )
    line = (
        f"prefilter kills: {s['total_kills']} ({gates}); "
        f"spot-audit: {s['sampled']} sampled, "
        f"{s['corroborated']} corroborated"
    )
    if s["contradicted"]:
        line += (
            f", {s['contradicted']} CONTRADICTED by analyzer "
            f"(see {LEDGER_FILENAME})"
        )
    return line
