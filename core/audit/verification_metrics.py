"""Diagnostic outcomes and reuse for deterministic, memo-eligible checks.

Checker outcomes are not final finding verdicts or ground-truth accuracy.
LLM costs stay in llm-telemetry.jsonl; unknown per-check costs stay null.
"""

from __future__ import annotations

import argparse
import logging
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from core.hash import sha256_string
from core.json import dumps_canonical
from core.json.jsonl import append_jsonl, load_jsonl

logger = logging.getLogger(__name__)
ATTEMPTS_FILENAME = "verification-attempts.jsonl"


def record_attempt(out_dir, tool, key_parts, result, *, origin, elapsed_s, error=None):
    """Best-effort observation; never change a checker result or retry policy."""
    if out_dir is None:
        return
    try:
        details = getattr(result, "details", None) or {}
        errors = getattr(result, "errors", None) or []
        reason = (error or details.get("reason") or details.get("skip_reason") or details.get("source_scope_status")
                  or "; ".join(str(item) for item in errors))
        # An unhashable input cannot identify equivalent work. Do not give
        # all unkeyed attempts the same apparent duplicate-work identity.
        input_id = (sha256_string(dumps_canonical([tool, key_parts]))
                    if all(value is not None for value in key_parts.values()) else None)
        record = {
            "event": "verification_attempt", "ts": time.time(), "tool": tool,
            "file": getattr(result, "file_path", None) or key_parts.get("path"),
            "function": getattr(result, "function_name", None) or key_parts.get("function"),
            "rule_id": getattr(result, "rule_id", None),
            "input_id": input_id,
            "origin": origin, "outcome": "error" if error else getattr(result, "outcome", "unknown"),
            "reason": str(reason or "")[:500],
            "elapsed_s": max(0.0, elapsed_s),
            "cost_usd": None,
        }
        path = Path(out_dir) / ATTEMPTS_FILENAME
        path.parent.mkdir(parents=True, exist_ok=True)
        append_jsonl(path, record, compact=True, mode=0o600)
    except Exception:
        logger.debug("verification attempt could not be recorded", exc_info=True)


def summarize_attempts(records) -> dict[str, Any]:
    """Summarize observed attempts, without equating tool hits with real bugs."""
    tools = defaultdict(lambda: {"attempts": 0, "outcomes": Counter(),
                                 "origins": Counter(), "reasons": Counter(), "elapsed_s": 0.0})
    fresh_inputs = Counter()
    total = 0
    for record in records:
        if not isinstance(record, dict) or record.get("event") != "verification_attempt":
            continue
        total += 1
        tool = str(record.get("tool") or "unknown")
        bucket = tools[tool]
        bucket["attempts"] += 1
        bucket["outcomes"][record.get("outcome") or "unknown"] += 1
        bucket["origins"][record.get("origin") or "unknown"] += 1
        if record.get("reason"):
            bucket["reasons"][record["reason"]] += 1
        bucket["elapsed_s"] += float(record.get("elapsed_s") or 0)
        if record.get("input_id") and record.get("origin") in {"fresh", "unmemoized"}:
            fresh_inputs[(tool, record["input_id"])] += 1
    return {
        "coverage": "deterministic memo-eligible checks only; checker outcomes are not final verdicts",
        "attempts": total,
        "tools": dict(tools),
        "repeated_fresh_inputs": sum(count - 1 for count in fresh_inputs.values()),
        "cost_usd": None,
        "cost_note": "Per-check cost is unattributed; consult LLM telemetry caller totals. Summed call times are not run wall time.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize deterministic verification outcomes and cache reuse from audit run directories.",
        epilog="Examples: python -m core.audit.verification_metrics out/audit-1\n"
               "          python -m core.audit.verification_metrics out/group-a out/group-b",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("run_dirs", nargs="+", type=Path,
                        help="Audit run directories containing verification-attempts.jsonl")
    args = parser.parse_args(argv)
    records = []
    missing = []
    for directory in dict.fromkeys(directory.resolve() for directory in args.run_dirs):
        path = directory / ATTEMPTS_FILENAME
        if not path.is_file():
            missing.append(str(path))
            continue
        if path.stat().st_size > 64 * 1024 * 1024:
            parser.error(f"verification trail exceeds the 64 MiB report limit: {path}")
        records.extend(load_jsonl(path, max_line_bytes=16 * 1024, max_total_bytes=64 * 1024 * 1024))
    report = summarize_attempts(records)
    report["missing_trails"] = missing
    print(dumps_canonical(report))
    return int(bool(missing))


if __name__ == "__main__":
    raise SystemExit(main())
