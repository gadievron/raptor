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

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.json import save_json

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
    from core.json import load_json
    raw = load_json(p, max_bytes=8 * 1024 * 1024)
    if isinstance(raw, dict):
        answers = raw.get("answers", [])
        return answers if isinstance(answers, list) else []
    return []


def append_answers(out_dir: Path, answers: list[StudyAnswer]) -> int:
    """Append *answers* to the ledger (atomic write).  A record with
    the same (question, source_file, source_function) is updated in
    place (last write wins) rather than duplicated.

    The key carries the origin, not the question text alone: the same
    generic question asked from two different functions is two ledger
    records (the ledger is the traceability spine — a per-function
    record silently replaced by another function's answer breaks both
    re-review presentation and receipt threading, and the survivor
    may state the OPPOSITE contract)."""
    if not answers:
        return 0
    existing = load_answers(out_dir)
    by_key = {
        (a.get("question"), a.get("source_file", ""),
         a.get("source_function", "")): i
        for i, a in enumerate(existing)
        if isinstance(a, dict)
    }
    added = 0
    for ans in answers:
        rec = asdict(ans)
        key = (ans.question, ans.source_file, ans.source_function)
        idx = by_key.get(key)
        if idx is None:
            existing.append(rec)
            by_key[key] = len(existing) - 1
            added += 1
        else:
            existing[idx] = rec
    save_json(_path(Path(out_dir)), {"answers": existing})
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
