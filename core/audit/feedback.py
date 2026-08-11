"""/validate → /audit feedback loop (Reflexion pattern).

Reads a /validate report (Stage-D ``stage-d.json`` or final
``findings.json``), matches findings back to audit annotations
by file+function, and updates:

1. **Annotation status** — downgrades disproven findings, upgrades
   missed ones, appends corroboration notes for confirmed findings.
2. **Annotation body** — appends a ``### /validate feedback`` block
   with the validation verdict, reason, and extracted lesson.
3. **coverage-audit.json** — syncs the status change so the gap
   list reflects the corrected state.
4. **Audit log** — records each feedback action for the critique
   pass and reporting.

Status transitions:
  - ``ruled_out`` or ``is_true_positive=False`` → annotation
    ``finding``/``suspicious`` downgraded to ``clean``
  - ``confirmed``/``exploitable`` when annotation was ``clean`` →
    upgraded to ``finding``
  - ``confirmed``/``exploitable`` when annotation was already
    ``finding`` → no status change, corroboration appended
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DISPROVEN_STATUSES = frozenset({
    "ruled_out", "false_positive", "disproven",
})

_CONFIRMED_STATUSES = frozenset({
    "confirmed", "exploitable",
})


def import_validation_results(
    *,
    validation_report: Path,
    annotations_dir: Path,
    audit_out_dir: Optional[Path] = None,
    target_path: Optional[Path] = None,
) -> Dict[str, int]:
    """Import /validate results into the review journal.

    Args:
        validation_report: Path to /validate output — accepts
            ``findings.json`` (flat list or ``{"findings": [...]}``)
            or ``stage-d.json`` (``{"findings": [...],"summary":...}``).
        annotations_dir: Path to the audit annotations directory.
            Consulted for human-source annotation vetoes only.
        audit_out_dir: If provided, appends correction journal
            entries + the ``feedback`` audit-log event here. When
            omitted, the correction entries are written under
            ``annotations_dir.parent`` as a best-effort fallback.
        target_path: Root of the target codebase. Used to recompute
            the source hash for correction entries so
            ``source_drifted`` can be surfaced when the source has
            changed since the prior review (amendment §6).

    Returns:
        Dict with counts: updated, downgraded, upgraded, corroborated,
        skipped.
    """
    # Prior LLM verdict lives in the review journal (design:
    # "annotations are human-only, LLMs use schemas and JSON"). The
    # human-authored annotation is still consulted so operator notes
    # with a conclusion status can veto Reflexion — but no annotation
    # is ever written back (see amendment §1 D3 + A5).
    from core.annotations.storage import read_annotation
    from .journal import (
        ReviewJournalEntry, VALID_VERDICTS, append_entry,
        latest_entries, now_iso,
    )
    from .record import _compute_hash

    try:
        with open(validation_report, encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("failed to load validation report %s: %s", validation_report, exc)
        return {"updated": 0, "downgraded": 0, "upgraded": 0, "corroborated": 0, "skipped": 0}

    findings = _extract_findings(report)
    findings = _deduplicate_findings(findings)

    counts = {
        "updated": 0,
        "downgraded": 0,
        "upgraded": 0,
        "corroborated": 0,
        "skipped": 0,
    }

    # Load prior LLM verdicts once — one journal read per audit-out
    # dir instead of per finding.
    prior_by_key: Dict[str, ReviewJournalEntry] = {}
    if audit_out_dir:
        try:
            prior_by_key = latest_entries(audit_out_dir)
        except Exception:  # noqa: BLE001
            prior_by_key = {}

    for finding in findings:
        file_path = finding.get("file", "")
        function_name = finding.get("function", "")
        if not file_path or not function_name:
            counts["skipped"] += 1
            continue

        # Human notes with a conclusion-status veto Reflexion — the
        # operator's judgement stands. Amendment A5: only annotations
        # whose status matches the LLM's verdict vocabulary
        # (``VALID_VERDICTS``) veto; non-conclusion statuses
        # (``todo``, ``investigating``, free-form) don't block
        # Reflexion because the operator hasn't asserted anything.
        human_ann = read_annotation(annotations_dir, file_path, function_name)
        if human_ann and human_ann.metadata.get("source") == "human":
            hstatus = (human_ann.metadata.get("status") or "").strip().lower()
            if hstatus in VALID_VERDICTS:
                logger.info(
                    "Skipping feedback for %s:%s — human annotation "
                    "asserts %r",
                    file_path, function_name, hstatus,
                )
                counts["skipped"] += 1
                continue

        key = f"{file_path}:{function_name}"
        prior_entry = prior_by_key.get(key)
        audit_status = prior_entry.verdict if prior_entry else ""
        prior_body = prior_entry.body if prior_entry else ""

        # Legacy path: run dirs created before the annotation → journal
        # migration still carry LLM verdicts as annotations. When
        # there's no journal entry, fall back to the LLM annotation
        # so the Reflexion loop still fires on pre-migration state.
        # The corrected verdict is still written to the journal
        # (never back to the annotation) — annotations remain
        # human-only for new writes.
        if not audit_status and human_ann and (
            human_ann.metadata.get("source") == "llm"
        ):
            audit_status = human_ann.metadata.get("status", "")
            prior_body = human_ann.body

        if not audit_status:
            # No prior LLM verdict AND no human note — nothing to
            # correct. The Reflexion pattern requires a prior claim
            # to update; a bare finding without one is a new signal
            # for the next audit run, not feedback.
            counts["skipped"] += 1
            continue

        validate_verdict = _classify_verdict(finding)
        transition = _compute_transition(audit_status, validate_verdict)

        reason = _sanitize_markdown(_extract_reason(finding))
        lesson = _extract_lesson(finding, audit_status, validate_verdict)

        # Write a NEW journal entry recording the corrected verdict
        # + lesson. The journal is append-only, so
        # ``latest_entries`` naturally returns this entry on the
        # next call — no in-place mutation, no annotation write.
        new_verdict = transition["new_status"] or audit_status

        # Recompute source_hash at correction time. If it differs
        # from the prior entry's hash, the source has drifted since
        # the original review — surface via ``source_drifted=True``
        # instead of silently inheriting the stale hash. Amendment
        # §6 (Phase 3.5 belt-and-braces).
        target_path_arg = target_path or (
            audit_out_dir.parent if audit_out_dir else Path(".")
        )
        recomputed_hash = _compute_hash(
            Path(target_path_arg), file_path,
            (prior_entry.line_start if prior_entry else 0) or 0,
            prior_entry.line_end if prior_entry else None,
        ) or ""
        prior_hash = (prior_entry.source_hash if prior_entry else "") or ""
        source_drifted = bool(
            recomputed_hash and prior_hash
            and recomputed_hash != prior_hash
        )

        new_entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id=(prior_entry.run_id if prior_entry else "") or "",
            file=file_path,
            function=function_name,
            verdict=new_verdict,
            source_hash=recomputed_hash or prior_hash,
            line_start=prior_entry.line_start if prior_entry else 0,
            line_end=prior_entry.line_end if prior_entry else None,
            cwe=prior_entry.cwe if prior_entry else None,
            strategies=list(prior_entry.strategies) if prior_entry else [],
            body=prior_body or "",
            model=prior_entry.model if prior_entry else None,
            prior_review=audit_status,
            lesson=lesson or None,
            validate_verdict=validate_verdict,
            validate_reason=reason or None,
            source_drifted=source_drifted if source_drifted else None,
            producer=(prior_entry.producer if prior_entry else None)
                     or "audit",
        )
        try:
            append_entry(audit_out_dir or annotations_dir.parent, new_entry)
        except Exception:  # noqa: BLE001
            logger.debug(
                "journal append failed for %s:%s",
                file_path, function_name, exc_info=True,
            )

        counts["updated"] += 1
        counts[transition["kind"]] += 1

        if audit_out_dir:
            _update_audit_state(
                audit_out_dir, file_path, function_name,
                transition, validate_verdict, reason,
            )

    return counts


def _deduplicate_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Keep only the last finding per (file, function) pair."""
    seen: Dict[tuple, int] = {}
    for idx, finding in enumerate(findings):
        key = (finding.get("file", ""), finding.get("function", ""))
        seen[key] = idx
    return [findings[i] for i in sorted(seen.values())]


def _sanitize_markdown(text: str) -> str:
    """Strip markdown heading markers from untrusted text.

    Prevents injection of ``## function_name`` sections that the
    annotation parser would interpret as real function headings.
    """
    lines = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            line = stripped.lstrip("#").lstrip()
        if "<!-- meta:" in line:
            line = line.replace("<!--", "").replace("-->", "")
        lines.append(line)
    return "\n".join(lines)


def _extract_findings(report: Any) -> List[Dict[str, Any]]:
    """Normalise different /validate output shapes into a flat list."""
    if isinstance(report, list):
        return report
    if isinstance(report, dict):
        if "findings" in report:
            return report["findings"]
        if "results" in report:
            return report["results"]
    return []


def _classify_verdict(finding: Dict[str, Any]) -> str:
    """Map /validate's various status fields to a canonical verdict.

    Returns one of: ``disproven``, ``confirmed``, ``unknown``.
    """
    ruling = finding.get("ruling", {})
    if isinstance(ruling, dict):
        status = ruling.get("status", "")
    else:
        status = str(ruling)

    if status in _DISPROVEN_STATUSES:
        return "disproven"
    if status in _CONFIRMED_STATUSES:
        return "confirmed"

    if finding.get("is_true_positive") is False:
        return "disproven"
    if finding.get("is_true_positive") is True:
        return "confirmed"

    return "unknown"


def _compute_transition(
    audit_status: str,
    validate_verdict: str,
) -> Dict[str, Any]:
    """Decide what status transition to make.

    Returns dict with ``kind`` (downgraded/upgraded/corroborated),
    ``new_status`` (or None if no change), and ``description``.
    """
    if validate_verdict == "disproven":
        if audit_status in ("finding", "suspicious"):
            return {
                "kind": "downgraded",
                "new_status": "clean",
                "description": (
                    f"Downgraded {audit_status} → clean "
                    f"(/validate disproved)"
                ),
            }
        return {
            "kind": "corroborated",
            "new_status": None,
            "description": (
                f"/validate disproved but audit status was already "
                f"{audit_status!r}"
            ),
        }

    if validate_verdict == "confirmed":
        if audit_status == "clean":
            return {
                "kind": "upgraded",
                "new_status": "finding",
                "description": (
                    "Upgraded clean → finding "
                    "(/validate confirmed a missed vulnerability)"
                ),
            }
        if audit_status in ("finding", "suspicious"):
            return {
                "kind": "corroborated",
                "new_status": None,
                "description": (
                    f"/validate confirmed — corroborates audit "
                    f"status {audit_status!r}"
                ),
            }
        return {
            "kind": "corroborated",
            "new_status": None,
            "description": f"/validate confirmed (audit status: {audit_status!r})",
        }

    return {
        "kind": "corroborated",
        "new_status": None,
        "description": f"/validate verdict unknown (audit status: {audit_status!r})",
    }


def _extract_reason(finding: Dict[str, Any]) -> str:
    """Pull the human-readable reason from the /validate finding."""
    ruling = finding.get("ruling", {})
    if isinstance(ruling, dict):
        reason = ruling.get("reason", "")
        if not reason:
            synth = ruling.get("evidence_synthesis", {})
            reason = synth.get("synthesis", "")
        if not reason:
            disq = ruling.get("disqualifier", "")
            if disq:
                reason = f"Disqualifier: {disq}"
        if reason:
            return reason

    if finding.get("false_positive_reason"):
        return finding["false_positive_reason"]
    if finding.get("reasoning"):
        return finding["reasoning"]
    return ""


def _extract_lesson(
    finding: Dict[str, Any],
    audit_status: str,
    validate_verdict: str,
) -> str:
    """Generate a lesson-learned string for the feedback block.

    The lesson captures WHY the audit was wrong so future runs
    can adjust (Reflexion pattern).
    """
    if validate_verdict == "disproven" and audit_status == "finding":
        ruling = finding.get("ruling", {})
        if isinstance(ruling, dict):
            disq = ruling.get("disqualifier", "")
            if disq == "D-0":
                return "Lesson: hypothesis was wrong — re-examine evidence."
            if disq == "D-1":
                return "Lesson: code was test/mock/example, not production."
            if disq in ("D-1.5", "D-2"):
                return "Lesson: preconditions make this unreachable."
            if disq == "D-3":
                return "Lesson: finding was hedged — require concrete proof."
            if disq == "D-4":
                return "Lesson: real bug but no security impact."
        return "Lesson: check /validate's reasoning for correction."

    if validate_verdict == "confirmed" and audit_status == "clean":
        return (
            "Lesson: missed vulnerability — review strategy may need "
            "broader scope or different tool checks."
        )

    return ""


def _format_feedback_block(
    validate_verdict: str,
    reason: str,
    lesson: str,
    transition: Dict[str, Any],
) -> str:
    """Format the feedback block appended to the annotation body."""
    lines = ["### /validate feedback"]
    lines.append(f"Verdict: {validate_verdict}")
    lines.append(f"Transition: {transition['description']}")
    if reason:
        lines.append(f"Reason: {reason}")
    if lesson:
        lines.append(lesson)
    return "\n".join(lines)


def _update_audit_state(
    audit_out_dir: Path,
    file_path: str,
    function_name: str,
    transition: Dict[str, Any],
    validate_verdict: str,
    reason: str,
) -> None:
    """Append a ``feedback`` event to the audit log.

    Under the annotation → journal migration, the corrected verdict
    itself is persisted by the caller (a fresh journal entry with
    ``prior_review`` + ``lesson`` + ``validate_verdict`` fields is
    appended). This helper only records the operational event —
    which finding triggered feedback and how the transition was
    classified — into ``.audit-log.jsonl`` for cross-run analysis.
    ``coverage-audit.json`` was removed; the journal is authoritative.
    """
    from core.audit.record import append_audit_log
    append_audit_log(audit_out_dir, {
        "action": "feedback",
        "key": f"{file_path}:{function_name}",
        "file": file_path,
        "function": function_name,
        "validate_verdict": validate_verdict,
        "transition": transition["kind"],
        "new_status": transition.get("new_status"),
        "reason": reason,
    })
