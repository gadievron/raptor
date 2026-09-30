"""Machine-readable study-failure record (``study-failure.json``).

A study run that ends WITHOUT producing ``domain-model.json`` must
fail loudly at the root cause, not one consumer later as a bare
"no model" symptom. The study-side drivers exit nonzero AND drop
this record next to where the model would have been; downstream
consumers (the engagement chain's study stage) read it so their
stage-failure reason names the actual cause — e.g. an LLM budget
that exhausted before any Phase 2 batch completed.

Reason tokens (machine-matched; ``detail`` carries the prose):

- ``llm_budget_exhausted`` — the spend cap stopped the study before
  it produced any model.
- ``no_domain_model`` — the run exited cleanly but never produced
  ``domain-model.json`` (no study scope derived, or it stopped
  before Phase 2).
- ``study_error`` — the study raised; ``detail`` carries the error.

Lifecycle: writers clear any stale record when a run starts and
again when a run succeeds, so a present record always describes the
LATEST failed run. Writing is best-effort — the record is diagnosis;
the failure signal itself is the driver's nonzero exit.

``detail`` may embed target-derived bytes (exception messages quote
model output and file names), so it is stored raw and escaped at
render by every consumer — the ``core.security.log_sanitisation``
escape-at-render contract.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: File name of the record, resolved inside the study output dir —
#: the same directory ``domain-model.json`` would have landed in.
STUDY_FAILURE_FILENAME = "study-failure.json"

#: Schema tag stamped on every record.
STUDY_FAILURE_SCHEMA = "study-failure/1"

#: Detail excerpt bound, both directions: not larger because
#: exception messages can embed whole LLM payload fragments and the
#: record wants the cause, not the transcript; not smaller because a
#: zero-yield budget message must survive intact — the phase-2 guard
#: wraps the original cap message ("batch N/M: … spent + estimated >
#: limit") in its own prose, which already runs a few hundred
#: characters, and consumers re-bound the detail to their own
#: display caps anyway (the chain note clamps to 300).
_DETAIL_MAX_CHARS = 500

#: Load-side byte budget — a record is a few hundred bytes; anything
#: near this bound is not one of ours.
_RECORD_MAX_BYTES = 64 * 1024


def write_study_failure(
    output_dir: Path, reason: str, detail: str = "",
) -> None:
    """Write ``study-failure.json`` into ``output_dir``. Best-effort.

    ``reason`` is a machine-matched token (module docstring);
    ``detail`` is bounded human-readable prose (stored raw, escaped
    at render by consumers). Never raises: the record is diagnosis
    riding a failure path that must still reach its nonzero exit.
    """
    if len(detail) > _DETAIL_MAX_CHARS:
        detail = detail[:_DETAIL_MAX_CHARS] + " …[truncated]"
    record = {
        "schema": STUDY_FAILURE_SCHEMA,
        "reason": reason,
        "detail": detail,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        from core.json import save_json
        save_json(output_dir / STUDY_FAILURE_FILENAME, record)
    except Exception:  # noqa: BLE001 — see docstring
        logger.warning(
            "could not write %s", STUDY_FAILURE_FILENAME, exc_info=True,
        )


def clear_study_failure(output_dir: Path) -> None:
    """Remove a stale record. Best-effort, missing-tolerant.

    Called at run start (this run's outcome is not yet known) and on
    success (a produced model supersedes any earlier failure).
    """
    try:
        (output_dir / STUDY_FAILURE_FILENAME).unlink(missing_ok=True)
    except OSError:
        logger.warning(
            "could not clear %s", STUDY_FAILURE_FILENAME, exc_info=True,
        )


def load_study_failure(output_dir: Path) -> dict[str, Any] | None:
    """Load the record from ``output_dir``; ``None`` when absent.

    Also ``None`` for a malformed, over-budget, or wrong-shaped file
    — consumers fall back to their generic failure text, they never
    fail on a diagnosis artefact.
    """
    path = output_dir / STUDY_FAILURE_FILENAME
    try:
        from core.json import load_json_bounded
        data = load_json_bounded(path, max_bytes=_RECORD_MAX_BYTES)
    except (OSError, ValueError):
        # Missing file, unreadable file, over-budget, malformed JSON
        # (JsonBudgetExceededError subclasses ValueError).
        return None
    if not isinstance(data, dict) or not isinstance(
            data.get("reason"), str):
        return None
    if not isinstance(data.get("detail", ""), str):
        data["detail"] = ""
    return data
