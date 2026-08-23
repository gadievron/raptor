"""Finding-grade journal emission for per-finding analyses.

Shared by the analysis agent (sequential and prep flows journal via
``AutonomousSecurityAgentV2._emit_journal_entry``, which delegates
here) and the Phase-4 orchestration tail (``raptor_agentic`` calls
:func:`journal_orchestrated_results` after ``orchestrate()`` returns).

Every entry is FINDING-GRADE (``producer="agentic"``): it records the
analysis of ONE scanner finding located in a function, never a
function review. The kind-aware audit gap fold excludes these from
coverage; they surface instead as prior claims in audit review context
and as ``agentic``-labelled tool coverage in the store.

Orchestrated entries land at the RUN ROOT (the agent's own entries
land in its ``--out`` dir, ``autonomous/`` under /agentic) — both
locations are covered by the run-completion index merge and by the
gap-audit post-pass's ``--prior-journal`` handoff.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def derive_verdict(analysis: dict[str, Any] | None) -> str:
    """Map an analysis dict's verdict bools to the journal verdict enum."""
    if not analysis:
        return "error"
    is_tp = analysis.get("is_true_positive")
    if is_tp is False:
        return "clean"
    if is_tp is True:
        return "finding" if analysis.get("is_exploitable") else "suspicious"
    return "error"


def build_journal_body(
    analysis: dict[str, Any] | None,
    *,
    message: str | None = None,
    has_dataflow: bool = False,
) -> str:
    """Compose the journal entry body from the LLM's reasoning."""
    parts: list[str] = []
    analysis = analysis or {}

    reasoning = analysis.get("reasoning") or analysis.get("explanation")
    if reasoning:
        parts.append(str(reasoning).strip())

    severity = analysis.get("severity_assessment")
    if severity:
        parts.append(f"Severity: {severity}")

    if has_dataflow:
        dv = analysis.get("dataflow_validation") or {}
        if dv:
            fp = dv.get("false_positive")
            if fp is not None:
                parts.append(f"Dataflow validation: false_positive={fp}")

    if not parts and message:
        parts.append(f"Scanner message: {message}")

    return "\n\n".join(parts)


def emit_finding_journal_entry(
    *,
    out_dir: Path,
    repo_path: Path,
    checklist: dict[str, Any] | None,
    file_path: str | None,
    start_line: int | None,
    analysis: dict[str, Any] | None,
    cwe_id: str | None = None,
    tool: str | None = None,
    message: str | None = None,
    model: str | None = None,
    has_dataflow: bool = False,
    verdict: str | None = None,
) -> str | None:
    """Emit one finding-grade ``ReviewJournalEntry`` into ``out_dir``.

    ``verdict`` overrides the derivation from ``analysis`` — panel
    records (multi_model_analyses) carry no ``is_true_positive``, so
    their verdicts are mapped by the caller.

    Returns the resolved function name on success, None otherwise.
    Best-effort — any exception is logged and swallowed so journal
    failures cannot break an analysis loop.
    """
    try:
        from core.annotations import compute_function_hash
        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            now_iso,
        )
        from core.inventory.lookup import lookup_function

        if not file_path or not start_line or not checklist:
            return None

        repo_path = Path(repo_path)
        func = lookup_function(
            checklist, file_path, int(start_line),
            repo_root=str(repo_path),
        )
        if not func or not func.get("name"):
            return None

        name = func["name"]
        line_start = func.get("line_start")
        line_end = func.get("line_end")

        if verdict is None:
            verdict = derive_verdict(analysis)
        body = build_journal_body(
            analysis, message=message, has_dataflow=has_dataflow,
        )

        source_hash = ""
        if line_start and line_end:
            src = (repo_path / file_path).resolve()
            if src.is_relative_to(repo_path.resolve()):
                source_hash = compute_function_hash(
                    src, line_start, line_end,
                ) or ""

        entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id=Path(out_dir).name,
            file=file_path,
            function=name,
            verdict=verdict,
            source_hash=source_hash,
            line_start=line_start or 0,
            line_end=line_end,
            cwe=cwe_id,
            body=body,
            model=model,
            evidence_tools=[tool or "unknown"],
            # Finding-grade marker: this entry records the analysis of
            # ONE scanner finding, not a function review. See the
            # module docstring and core.coverage.journal.
            # is_function_grade.
            producer="agentic",
        )
        append_entry(Path(out_dir), entry)
        return name
    except Exception:
        logger.debug("journal entry emit error", exc_info=True)
        return None


def _panel_verdict(analysis: dict[str, Any]) -> str | None:
    """Verdict for one panel member's ``multi_model_analyses`` record.

    Panel records carry ``is_exploitable`` + ``ruling`` + ``reasoning``
    but no ``is_true_positive``: exploitable maps to ``finding``; not
    exploitable maps to ``clean`` when the ruling names a false
    positive, else ``suspicious`` (true positive, not exploitable —
    matching :func:`derive_verdict`'s split); an absent boolean means
    the member produced no verdict and is skipped.
    """
    is_exploitable = analysis.get("is_exploitable")
    if is_exploitable is True:
        return "finding"
    if is_exploitable is not False:
        return None
    ruling = analysis.get("ruling")
    status = ruling.get("status") if isinstance(ruling, dict) else ruling
    s = str(status or "").strip().lower()
    if "false_positive" in s or "not_a_vulnerability" in s or s == "fp":
        return "clean"
    return "suspicious"


#: Result statuses that represent a completed analysis worth journaling.
#: ``analysis_inconsistent`` / ``error`` / ``skipped_*`` records carry
#: no reviewable verdict — journaling them would fabricate review
#: evidence for findings the LLM never (coherently) analysed.
_JOURNALABLE_STATUSES = frozenset({"analysed"})

#: Analysis fields lifted from an orchestrated result record into the
#: journal entry body/verdict.
_ANALYSIS_KEYS = (
    "is_true_positive",
    "is_exploitable",
    "reasoning",
    "explanation",
    "severity_assessment",
    "dataflow_validation",
)


def journal_orchestrated_results(
    out_dir: Path,
    repo_path: Path,
    results: list,
    checklist: dict[str, Any] | None = None,
) -> int:
    """Journal Phase-4 orchestrated per-finding analyses.

    The orchestrator analyses findings without journaling (it has no
    per-finding journal writer of its own), so in the default
    orchestrated mode the review journal used to carry only the prep
    phase's mechanical suppressions. This walks the merged report
    ``results`` after ``orchestrate()`` returns and emits one
    finding-grade entry per ANALYSED record at the run root.

    Entries are gated on the canonical per-result ``status`` stamp
    (``analysed``); records without the stamp fall back to requiring a
    boolean ``is_true_positive`` (the schema-required verdict field).
    Returns the number of entries written. Best-effort.
    """
    if checklist is None:
        from core.json import load_json
        checklist = load_json(Path(out_dir) / "checklist.json")
    if not isinstance(checklist, dict):
        logger.debug(
            "orchestrated journal: no usable checklist — skipping",
        )
        return 0

    emitted = 0
    for result in results or []:
        if not isinstance(result, dict):
            continue
        status = result.get("status")
        if status is not None:
            if status not in _JOURNALABLE_STATUSES:
                continue
        elif not isinstance(result.get("is_true_positive"), bool):
            continue
        analysis = {
            k: result[k] for k in _ANALYSIS_KEYS if result.get(k) is not None
        }
        name = emit_finding_journal_entry(
            out_dir=Path(out_dir),
            repo_path=Path(repo_path),
            checklist=checklist,
            file_path=result.get("file_path") or result.get("file"),
            start_line=result.get("start_line") or result.get("line"),
            analysis=analysis,
            cwe_id=result.get("cwe_id"),
            tool=result.get("tool"),
            message=result.get("message"),
            model=result.get("analysed_by") or result.get("model"),
            has_dataflow=bool(result.get("dataflow_validation")),
        )
        if name is None:
            continue
        emitted += 1

        # Multi-model runs: journal each panel member's own verdict
        # too. The index key includes the model, so per-model history
        # is preserved instead of collapsing to the merged verdict —
        # a disagreeing second model's clean/finding stays queryable.
        panel = result.get("multi_model_analyses")
        if not isinstance(panel, list) or len(panel) < 2:
            continue
        primary_model = result.get("analysed_by") or result.get("model")
        for member in panel:
            if not isinstance(member, dict):
                continue
            member_model = member.get("model")
            if not member_model or member_model == primary_model:
                # The primary's post-pipeline verdict is the entry
                # emitted above; re-journaling its dispatch-time
                # record would double-count (and can be stale).
                continue
            member_verdict = _panel_verdict(member)
            if member_verdict is None:
                continue
            if emit_finding_journal_entry(
                out_dir=Path(out_dir),
                repo_path=Path(repo_path),
                checklist=checklist,
                file_path=result.get("file_path") or result.get("file"),
                start_line=result.get("start_line") or result.get("line"),
                analysis={"reasoning": member.get("reasoning")},
                cwe_id=result.get("cwe_id"),
                tool=result.get("tool"),
                message=result.get("message"),
                model=member_model,
                verdict=member_verdict,
            ) is not None:
                emitted += 1
    if emitted:
        logger.info(
            "journaled %d orchestrated per-finding analyses into %s",
            emitted, Path(out_dir) / "review-journal.jsonl",
        )
    return emitted
