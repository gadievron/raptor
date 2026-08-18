"""/validate → /audit feedback loop (Reflexion pattern).

Reads a /validate report (Stage-D ``stage-d.json`` or final
``findings.json``), matches findings back to prior audit review
verdicts (from the review journal) by file+function, and writes:

1. **Journal correction entries** — a NEW append-only
   ``ReviewJournalEntry`` per corrected verdict, carrying the
   validation verdict, ``prior_review`` provenance, and the
   extracted lesson. ``latest_entries`` then returns the corrected
   verdict on the next read; nothing is mutated in place.
2. **Audit log** — a ``feedback`` event per transition for the
   critique pass and reporting.

Annotations are read-only veto inputs here: a human-authored
annotation with a conclusion status blocks the Reflexion downgrade,
but annotation files are never written back (amendment §1 D3 + A5),
and coverage-audit.json no longer exists — the journal is
authoritative.

Verdict transitions (recorded in the correction entry):
  - ``ruled_out`` or ``is_true_positive=False`` → prior
    ``finding``/``suspicious`` downgraded to ``clean``
  - ``confirmed``/``exploitable`` when prior verdict was ``clean`` →
    upgraded to ``finding``
  - ``confirmed``/``exploitable`` when prior verdict was already
    ``finding`` → no status change, corroboration recorded
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

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
    audit_out_dir: Path | None = None,
    target_path: Path | None = None,
) -> dict[str, int]:
    """Import /validate results into the review journal.

    Args:
        validation_report: Path to /validate output — accepts
            ``findings.json`` (flat list or ``{"findings": [...]}``),
            ``stage-d.json`` (``{"findings": [...],"summary":...}``),
            or a ``{"results": [...]}`` wrapper.
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
    from core.annotations import is_human_grade
    from core.annotations.storage import read_annotation

    from .journal import (
        VALID_VERDICTS,
        ReviewJournalEntry,
        append_entry,
        latest_entries,
        make_function_key,
        now_iso,
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
    prior_by_key: dict[str, ReviewJournalEntry] = {}
    if audit_out_dir:
        try:
            prior_by_key = latest_entries(audit_out_dir)
        except Exception:  # noqa: BLE001
            prior_by_key = {}

    # Keys that received a confirmed verdict in THIS import. A later
    # disproven finding for the same function must not downgrade past
    # them (dedup no longer collapses same-function findings, so both
    # can appear in one report).
    confirmed_keys: set = set()

    # Reliability records for the VALIDATE_FEEDBACK scorecard producer
    # — the live writer of audit:<CWE> cells (see
    # core/llm/scorecard/validate_feedback.py). Collected in the loop,
    # recorded once at the end; never blocks the import.
    scorecard_records: list[dict[str, Any]] = []

    for finding in findings:
        file_path = finding.get("file", "")
        function_name = finding.get("function", "")
        if not file_path or not function_name:
            counts["skipped"] += 1
            continue

        # Human notes with a conclusion-status veto Reflexion — the
        # operator's judgement stands. The veto requires human GRADE
        # (source=human plus an interactive-TTY provenance stamp, or
        # a legacy pre-stamp note), not just the caller-asserted
        # source string — a non-interactive add claiming human is
        # the laundering shape and gets machine tier below instead.
        # Amendment A5: only annotations whose status matches the
        # LLM's verdict vocabulary (``VALID_VERDICTS``) veto;
        # non-conclusion statuses (``todo``, ``investigating``,
        # free-form) don't block Reflexion because the operator
        # hasn't asserted anything.
        human_ann = read_annotation(annotations_dir, file_path, function_name)
        if human_ann and is_human_grade(human_ann.metadata):
            hstatus = (human_ann.metadata.get("status") or "").strip().lower()
            if hstatus in VALID_VERDICTS:
                logger.info(
                    "Skipping feedback for %s:%s — human annotation "
                    "asserts %r",
                    file_path, function_name, hstatus,
                )
                counts["skipped"] += 1
                continue

        key = make_function_key(file_path, function_name)
        prior_entry = prior_by_key.get(key)
        audit_status = prior_entry.verdict if prior_entry else ""
        prior_body = prior_entry.body if prior_entry else ""

        # Machine-tier path: annotations without human grade — legacy
        # pre-migration LLM verdicts, agent-sourced notes, and human
        # claims stamped non-interactive — don't veto, but they stay
        # useful: when there's no journal entry, their status serves
        # as the prior claim so the Reflexion loop still fires. The
        # corrected verdict is still written to the journal (never
        # back to the annotation) — annotations remain human-only
        # for new writes.
        if not audit_status and human_ann and not is_human_grade(
            human_ann.metadata,
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

        # A downgrade to clean must refer to the SAME finding the
        # journal entry records, and can never override a confirmed
        # verdict for the same function within this import — a
        # disproven decoy (different CWE/line, or processed after a
        # confirmed sibling) must not erase real feedback.
        decoy_vetoed = False
        if transition.get("new_status") == "clean":
            if key in confirmed_keys:
                transition = {
                    "kind": "corroborated",
                    "new_status": None,
                    "description": (
                        "/validate disproved one finding but another "
                        "was confirmed for this function in the same "
                        f"import — keeping {audit_status!r}"
                    ),
                }
            elif not _disproven_matches_entry(finding, prior_entry):
                transition = {
                    "kind": "corroborated",
                    "new_status": None,
                    "description": (
                        "/validate disproved a finding whose CWE/line "
                        "does not match the journal entry — keeping "
                        f"{audit_status!r}"
                    ),
                }
                decoy_vetoed = True
        if validate_verdict == "confirmed":
            confirmed_keys.add(key)

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
        except Exception:
            logger.debug(
                "journal append failed for %s:%s",
                file_path, function_name, exc_info=True,
            )

        counts["updated"] += 1
        counts[transition["kind"]] += 1

        # Reliability event for the model that made the prior claim.
        # Decoy-vetoed disprovals carry no signal about THIS verdict
        # (the disproven finding wasn't the one the journal records).
        prior_model = prior_entry.model if prior_entry else None
        if prior_model and not decoy_vetoed:
            scorecard_records.append({
                "model": prior_model,
                "cwe": prior_entry.cwe if prior_entry else None,
                "prior_verdict": audit_status,
                "validate_verdict": validate_verdict,
                "file": file_path,
                "function": function_name,
                "reason": reason,
            })

        if audit_out_dir:
            _update_audit_state(
                audit_out_dir, file_path, function_name,
                transition, validate_verdict, reason,
            )

    if scorecard_records:
        try:
            from core.llm.scorecard.validate_feedback import (
                record_validate_feedback_outcomes,
            )
            record_validate_feedback_outcomes(scorecard_records)
        except Exception:
            logger.debug("validate-feedback scorecard recording failed",
                         exc_info=True)

    return counts


def _deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep only the last finding per finding identity.

    Identity is the finding id when present, else
    ``(file, function, cwe, line)``. Keying on ``(file, function)``
    alone discarded the feedback of a confirmed finding whenever a
    later disproven finding (a different CWE or line in the same
    function) shared the pair — the transition logic then only ever
    saw the decoy.
    """
    seen: dict[tuple, int] = {}
    for idx, finding in enumerate(findings):
        fid = finding.get("id") or finding.get("finding_id")
        if fid:
            key = ("id", str(fid))
        else:
            key = (
                finding.get("file", ""),
                finding.get("function", ""),
                _finding_cwe(finding),
                _finding_line(finding),
            )
        seen[key] = idx
    return [findings[i] for i in sorted(seen.values())]


def _finding_cwe(finding: dict[str, Any]) -> str:
    """Normalised CWE number from a finding ('787' from 'CWE-787')."""
    raw = finding.get("cwe") or finding.get("cwe_id") or ""
    digits = "".join(c for c in str(raw) if c.isdigit())
    return digits


def _finding_line(finding: dict[str, Any]) -> int | None:
    """Line number from a finding, or None when absent."""
    for field in ("line", "line_start"):
        value = finding.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return None


def _disproven_matches_entry(
    finding: dict[str, Any],
    prior_entry: Any | None,
) -> bool:
    """Whether a disproven finding refers to the journal entry's finding.

    A downgrade to clean is only justified when /validate disproved
    the SAME finding the journal entry records. When both sides carry
    a CWE and they differ — or both carry line data and the finding's
    line falls outside the entry's span — the disproven finding is a
    different issue (e.g. a decoy in the same function) and must not
    erase the entry's verdict. Missing data on either side stays
    lenient: the historical downgrade behaviour is preserved when
    there is nothing to compare.
    """
    if prior_entry is None:
        return True

    finding_cwe = _finding_cwe(finding)
    entry_cwe = "".join(
        c for c in str(prior_entry.cwe or "") if c.isdigit()
    )
    if finding_cwe and entry_cwe and finding_cwe != entry_cwe:
        return False

    line = _finding_line(finding)
    start = prior_entry.line_start or 0
    end = prior_entry.line_end
    has_span = start > 0 and isinstance(end, int) and end >= start
    if line is None or not has_span:
        return True
    return start <= line <= end


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


def _extract_findings(report: Any) -> list[dict[str, Any]]:
    """Normalise different /validate output shapes into a flat list."""
    if isinstance(report, list):
        return report
    if isinstance(report, dict):
        if "findings" in report:
            return report["findings"]
        if "results" in report:
            return report["results"]
    return []


def _classify_verdict(finding: dict[str, Any]) -> str:
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
) -> dict[str, Any]:
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


def _extract_reason(finding: dict[str, Any]) -> str:
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
    finding: dict[str, Any],
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


def _update_audit_state(
    audit_out_dir: Path,
    file_path: str,
    function_name: str,
    transition: dict[str, Any],
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
