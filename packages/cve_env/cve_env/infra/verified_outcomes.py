"""Surface fully-verified environment builds as verified outcomes.

A ``success`` outcome means the verify DAG passed INCLUDING the
version-assertion exec_check and the functional smoke — a live,
behaviourally confirmed instance of the vulnerable version. Append it
to the run-local ``verified-outcomes.jsonl`` (source 3 of
``core.labeled_attempts.view.collect_outcomes``) so
``libexec/raptor-verified-outcomes`` surfaces /cve-env confirmations
alongside /fuzz, /agentic, /crash-analysis, /validate, and /cve-diff.

``Oracle.RUNTIME`` marks the evidence class: live-environment
behavioural checks. ``reproducible=False`` — the checks ran against a
point-in-time container on live registries; the recorded image
reference is what makes a re-run *possible*, not the record itself.
The ``tier`` evidence field carries the runtime that produced the
verification (``docker`` today; ``sandbox`` = witness-grade arrives
with the series-3 RuntimeHandle).

Invoked only by the RAPTOR shim after a build run — the operator
facade and the bench write nothing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def write_build_outcome(
    output_dir: Path,
    outcome: dict[str, Any],
    *,
    tier: str = "docker",
) -> bool:
    """Append one Oracle.RUNTIME record for a fully-verified build.

    ``outcome`` is the outcome-sidecar dict. Returns True when a record
    was written; False on skip (non-success status) or I/O trouble.
    Never raises.
    """
    try:
        if outcome.get("status") != "success":
            return False
        cve_id: str | None = outcome.get("cve_id")
        if not cve_id:
            return False

        from core.labeled_attempts.view import (
            VERIFIED_OUTCOMES_FILENAME,
            Oracle,
            OutcomeStatus,
            VerifiedOutcome,
        )

        record = VerifiedOutcome(
            finding_id=cve_id,
            oracle=Oracle.RUNTIME,
            status=OutcomeStatus.VERIFIED,
            reproducible=False,
            evidence={
                "tier": tier,
                "method": outcome.get("method"),
                # --describe runs: the environment was operator-
                # asserted, not CVE-pinned — a weaker oracle consumers
                # must be able to see, not just infer from a DESC- id.
                "operator_described": bool(
                    outcome.get("operator_described")),
                "verify_passed": bool(outcome.get("verify_passed")),
                "num_turns": outcome.get("num_turns"),
                "total_cost_usd": outcome.get("total_cost_usd"),
                "tool_names_called": outcome.get("tool_names_called"),
            },
            produced_by="cve-env",
        )
        path = Path(output_dir) / VERIFIED_OUTCOMES_FILENAME
        with Path(path).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record.to_dict(), default=str) + "\n")
        return True
    except Exception:  # noqa: BLE001 — surfacing must never break the run
        logger.debug(
            "verified-outcome write failed for %s",
            outcome.get("cve_id", "?"), exc_info=True,
        )
        return False
