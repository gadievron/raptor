"""Per-question study answer ledger (``study-answers.json``).

One record per reading-list question the study consumer processed,
carrying the answer text, its provenance tier, the receipt (verbatim
source pointer), the original assumption it may contradict, the
agreement-gate outcome, and whether a mechanical spot-check overrode
an LLM summary.  The ledger is the traceability spine: re-reviews
read it to present sourced answers alongside original assumptions,
and verdicts thread the receipts into their evidence chain so one bad
answer's blast radius is discoverable.

Written only by the study consumer (Thread B is the sole writer of
study artifacts in a run directory).
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

ANSWERS_FILENAME = "study-answers.json"


@dataclass
class StudyAnswer:
    """One processed study question and what became of it."""

    question: str
    source_file: str = ""
    source_function: str = ""
    #: The assumption context the review declared (never overwritten
    #: by the answer — contradiction quarantine presents both).
    assumption: str = ""
    answer: str = ""
    #: verbatim | mechanical | llm_summarized | llm_prior
    tier: str = ""
    receipt: dict | None = None
    #: resolved | unresolvable | inconclusive | pending
    status: str = "pending"
    reason: str = ""
    resolved_concept_id: str = ""
    #: True when a mechanical spot-check displaced an LLM summary.
    spot_check_override: bool = False
    #: Agreement-gate outcome for flip-causing answers:
    #: {"agreed": bool, "reason": str} — absent when the gate did
    #: not apply (non-flip path or mechanical tier).
    agreement: dict | None = None
    #: "compile-probe unavailable/failed: <reason>" when the compiler
    #: channel was attempted but could not produce a verdict — the
    #: question keeps whatever state the remaining pipeline assigns.
    probe_note: str = ""
    created_at: float = field(default_factory=time.time)


def _path(out_dir: Path) -> Path:
    return Path(out_dir) / ANSWERS_FILENAME


def load_answers(out_dir: Path) -> list[dict]:
    p = _path(out_dir)
    if not p.is_file():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(raw, dict):
        answers = raw.get("answers", [])
        return answers if isinstance(answers, list) else []
    return []


def append_answers(out_dir: Path, answers: list[StudyAnswer]) -> int:
    """Append *answers* to the ledger (atomic write).  A question
    already present is updated in place (last write wins) rather than
    duplicated."""
    if not answers:
        return 0
    existing = load_answers(out_dir)
    by_question = {
        a.get("question"): i for i, a in enumerate(existing)
        if isinstance(a, dict)
    }
    added = 0
    for ans in answers:
        rec = asdict(ans)
        idx = by_question.get(ans.question)
        if idx is None:
            existing.append(rec)
            by_question[ans.question] = len(existing) - 1
            added += 1
        else:
            existing[idx] = rec
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(out), suffix=".tmp", prefix="study-answers-",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"answers": existing}, f, indent=2)
            f.write("\n")
        Path(tmp).rename(_path(out))
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return added


def answers_for_function(
    out_dir: Path, file: str, function: str,
) -> list[dict]:
    """Ledger records originating from ``file:function``."""
    return [
        a for a in load_answers(out_dir)
        if a.get("source_file") == file
        and a.get("source_function") == function
    ]
