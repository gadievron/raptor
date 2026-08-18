"""Fail-open census pre-pass — checklist seeding for the channel.

Design §6: a bounded, detection-grade leg-1 × leg-2 sweep that runs in
the audit prep phase (the same slot as the consistency pre-pass) and
attaches ``fail_open_leads`` to the enclosing functions' checklist gap
dicts — extra keys on the gap, the ``reachable_sinks`` /
``consistency_leads`` precedent, never a new checklist item kind.

Why seeding must GENERATE candidates: the phase-1 field receipts (the
final-audit and head-to-head runs) show a quiet tier — 0 and 5
dispatches respectively, all inconclusive — because the channel only
ran when the LLM spontaneously phrased a fail-open hypothesis. The
census turns every silent-handler-around-a-role-bound-region in a
reviewed file into a rendered prompt lead ("a broad except at line 84
wraps token verification — form a hypothesis or discharge it"), so the
LLM either hypothesizes (channel dispatch is then automatic via the
keyword classifier / CWE map) or explicitly marks it clean. Leads that
never reach a review are journaled as ``fail_open_lead:undischarged``
telemetry — absence is signal.

Scope: the handler-outcome family only (Python except/suppress, Java
catch clauses, Go recover()-to-continue). The ignored-return /
discarded-error census over ALL callees is the consistency
programme's (CWE-252 premise split) — its acknowledged-discard
handoffs already inject fail-open hypotheses for security-role
callees, and this module must not duplicate that sweep.

The census is permanently detection-only: leads, never verdicts.
Role binding deliberately passes no enclosing source, so Tier-B hook
mechanics (a whole-file match would smear a role over every handler
in the file) participate only at adjudication time; naming-grade
evidence is enough for a lead.

Bounds (§9): ``MAX_FAIL_OPEN_LEADS`` per run, ``MAX_LEADS_PER_FILE``
per file, ranked by role-evidence strength then breadth; wall-clock
budget with a ``budget_exceeded`` telemetry flag (surfaced as a
``skipped`` tier count, not an error).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from .fail_open_lang import (
    HandlerOutcome,
    go_recover_handlers,
    java_handlers,
    language_for_path,
    python_handlers,
)
from .fail_open_roles import (
    GRADE_REGISTRY,
    RoleContext,
    bind_role,
)

logger = logging.getLogger(__name__)

MAX_FAIL_OPEN_LEADS = 40
MAX_LEADS_PER_FILE = 5
CENSUS_BUDGET_S = 60.0

# Handler-outcome census languages (see module docstring for why the
# C/Go ignored-return sweep is deliberately absent).
CENSUS_LANGUAGES = frozenset({"python", "java", "go"})


def _handlers_for(
    language: str, source: str, file_path: str,
) -> list[HandlerOutcome]:
    if language == "python":
        return python_handlers(source, file_path)
    if language == "java":
        return java_handlers(source, file_path) or []
    if language == "go":
        return go_recover_handlers(source, file_path) or []
    return []


def _lead_from(handler: HandlerOutcome, role: Any) -> dict[str, Any]:
    return {
        "file": handler.file,
        "function": handler.enclosing_function,
        "line": handler.line,
        "idiom": handler.idiom,
        "outcome_kind": handler.outcome_kind,
        "broad": handler.broad,
        "caught": list(handler.caught),
        "role_kind": role.kind,
        "role_source": role.source,
        "role_grade": role.grade,
        "matched": role.matched,
        "snippet": handler.evidence_snippet[:200],
    }


def _rank_leads(leads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Registry-grade roles first, then broad handlers, stable by
    (file, line); run and per-file caps applied."""
    ranked = sorted(
        leads,
        key=lambda ld: (
            ld.get("role_grade") != GRADE_REGISTRY,
            not ld.get("broad", False),
            ld.get("file", ""),
            ld.get("line", 0),
        ),
    )
    per_file: dict[str, int] = {}
    capped: list[dict[str, Any]] = []
    for lead in ranked:
        if len(capped) >= MAX_FAIL_OPEN_LEADS:
            break
        fp = lead.get("file", "")
        if per_file.get(fp, 0) >= MAX_LEADS_PER_FILE:
            continue
        per_file[fp] = per_file.get(fp, 0) + 1
        capped.append(lead)
    return capped


def run_fail_open_census(
    source_texts: dict[str, str],
    *,
    out_dir: Path | None = None,
    annotations_dir: Path | None = None,
    inventory: dict[str, Any] | None = None,
    context_map: dict[str, Any] | None = None,
    budget_s: float = CENSUS_BUDGET_S,
) -> dict[str, Any]:
    """Run the census over the review set's source files.

    Returns ``{"leads": [...], "telemetry": {...}}``. Never raises for
    a single bad file; never blocks prep past ``budget_s`` (the
    remainder is abandoned with ``budget_exceeded`` telemetry).
    """
    t0 = time.monotonic()
    telemetry: dict[str, Any] = {
        "files_scanned": 0,
        "handlers_seen": 0,
        "permissive_seen": 0,
        "role_bound": 0,
        "leads_seeded": 0,
        "by_language": {},
        "budget_exceeded": False,
    }
    ctx = RoleContext(
        out_dir=out_dir,
        annotations_dir=annotations_dir,
        inventory=inventory,
        context_map=context_map,
    )
    leads: list[dict[str, Any]] = []
    for file_path, source in sorted(source_texts.items()):
        if time.monotonic() - t0 > budget_s:
            telemetry["budget_exceeded"] = True
            break
        language = language_for_path(file_path)
        if language not in CENSUS_LANGUAGES:
            continue
        telemetry["files_scanned"] += 1
        try:
            handlers = _handlers_for(language, source, file_path)
        except Exception:
            logger.debug("fail_open census: analyzer failed for %s",
                         file_path, exc_info=True)
            continue
        telemetry["handlers_seen"] += len(handlers)
        for handler in handlers:
            if not handler.is_permissive:
                continue
            telemetry["permissive_seen"] += 1
            try:
                role = bind_role(
                    handler.try_calls,
                    handler.enclosing_function,
                    file_path,
                    language=language,
                    context=ctx,
                    # No enclosing source: Tier-B mechanics bind at
                    # adjudication time (module docstring).
                    enclosing_source="",
                )
            except Exception:
                logger.debug("fail_open census: role bind failed",
                             exc_info=True)
                continue
            if role is None:
                continue
            telemetry["role_bound"] += 1
            lang_counts = telemetry["by_language"]
            lang_counts[language] = lang_counts.get(language, 0) + 1
            leads.append(_lead_from(handler, role))

    capped = _rank_leads(leads)
    telemetry["leads_seeded"] = len(capped)
    telemetry["wall_time_s"] = round(time.monotonic() - t0, 3)
    return {"leads": capped, "telemetry": telemetry}


def seed_fail_open_leads(
    gaps: list[dict[str, Any]],
    leads: list[dict[str, Any]],
    *,
    boost: float = 2.0,
) -> int:
    """Attach leads to their gaps (gap-extra-key pattern) and notch the
    priority score — the ``seed_consistency_leads`` shape."""
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for lead in leads:
        by_key.setdefault(
            (lead.get("file", ""),
             _tail(lead.get("function", ""))), [],
        ).append(lead)
    seeded = 0
    for gap in gaps:
        key = (gap.get("file", ""), _tail(gap.get("name", "")))
        gap_leads = by_key.get(key)
        if not gap_leads:
            continue
        gap.setdefault("fail_open_leads", []).extend(
            gap_leads[:MAX_LEADS_PER_FILE],
        )
        gap["priority_score"] = (
            float(gap.get("priority_score") or 0.0) + boost
        )
        seeded += len(gap_leads[:MAX_LEADS_PER_FILE])
    return seeded


def _tail(name: str) -> str:
    """Dotted method names (Python analyzer emits ``Class.method``)
    match checklist entries by their tail."""
    return name.rsplit(".", 1)[-1] if name else ""
