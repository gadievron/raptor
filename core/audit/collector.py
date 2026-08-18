"""Collector — batches per-review I/O for the audit orchestrator.

Buffers ``append_audit_log`` (N file opens) writes that flush once at
the end of the review loop, and dual-writes each review to the journal.

``record_review`` (one file per function, no contention) stays
per-call — batching it adds complexity for no gain.
"""

from __future__ import annotations

import contextlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .journal import (
    ReviewJournalEntry,
    append_entry,
    compute_domain_model_hash,
    flush_journal,
    now_iso,
)

logger = logging.getLogger(__name__)


def append_journal_for_outcome(
    *,
    out_dir: Path,
    target_path: Path,
    run_id: str,
    outcome: Any,
    gap: dict[str, Any],
    checked_by: list[str] | None = None,
    domain_model_hash: str | None = None,
    producer: str | None = None,
) -> None:
    """Append one ``ReviewJournalEntry`` for a completed review outcome.

    Shared by ``Collector.submit`` (which caches the domain-model
    hash across a batch) and orchestrator's per-call
    ``_commit_outcome`` (which passes ``None`` and pays the compute
    cost per call — cheap, a single file hash). Extracted to keep
    every review outcome — batched or per-call — flowing into the
    review journal, since the design makes the journal the LLM
    review record.

    ``checked_by`` is vestigial: accepted for call-site compatibility
    (orchestrator still passes it) but NOT persisted — the journal
    schema has no checked_by column; model attribution lands via
    ``entry.model``.

    ``producer`` distinguishes /audit vs /agentic write sites so
    ``import_journal`` doesn't have to guess from run_id string
    prefixes (amendment §1 A2 / final review Finding #2). Default
    ``"audit"`` matches the historical convention — /agentic call
    sites pass ``"agentic"`` explicitly.

    Best-effort: any failure logs at DEBUG and swallows so an
    unrelated review can't be lost when a hash / concept lookup
    misbehaves.
    """
    if producer is None:
        producer = "audit"
    source_hash = ""
    try:
        from .record import _compute_hash
        h = _compute_hash(
            target_path,
            outcome.file,
            gap.get("line_start", 0),
            gap.get("line_end"),
        )
        if h:
            source_hash = h
    except (ImportError, OSError):
        pass
    except Exception:
        logger.debug("source hash computation failed for %s", outcome.file, exc_info=True)

    hypotheses_list: list[dict[str, str]] = []
    if getattr(outcome, "hypotheses", None):
        hypotheses_list = outcome.hypotheses
    elif getattr(outcome, "hypothesis", None):
        hypotheses_list = [
            {"mechanism": outcome.hypothesis, "confidence": "unknown"},
        ]

    evidence_tools: list[str] = []
    if getattr(outcome, "evidence_tool", ""):
        evidence_tools = [outcome.evidence_tool]
    dispatched = getattr(outcome, "tools_dispatched", None)
    if dispatched:
        evidence_tools = sorted(set(evidence_tools) | dispatched)

    reading_list_items: list[str] = []
    review_result = getattr(outcome, "review_result", None)
    if review_result and review_result.get("reading_list"):
        reading_list_items = [
            item.get("question", str(item))
            for item in review_result["reading_list"]
            if isinstance(item, dict)
        ]

    study_receipts: list[dict] = []
    if review_result and review_result.get("study_receipts"):
        study_receipts = [
            r for r in review_result["study_receipts"]
            if isinstance(r, dict)
        ]

    domain_concepts: list[str] = []
    invariants_available: list[str] = []
    try:
        from core.concepts.audit_bridge import (
            _find_domain_model,
            _guard_in_scope,
            _relevance_score,
        )
        dm = _find_domain_model(out_dir)
        if dm:
            for section in ("concepts", "invariants"):
                for item in dm.get(section, []):
                    score = _relevance_score(
                        item, outcome.file, outcome.function, "",
                    )
                    if score > 1.0:
                        domain_concepts.append(
                            item.get("id") or item.get("concept", ""),
                        )
            for inv in dm.get("invariants", []):
                inv_role = inv.get("role", "boost")
                if inv_role == "guard" and not _guard_in_scope(
                    inv, outcome.file or "",
                ):
                    continue
                inv_id = inv.get("id", "")
                if inv_id:
                    invariants_available.append(inv_id)
    except ImportError:
        pass
    except Exception:
        logger.debug("domain model context failed for %s:%s", outcome.file, outcome.function, exc_info=True)

    if domain_model_hash is None:
        try:
            domain_model_hash = compute_domain_model_hash(out_dir)
        except (ImportError, OSError):
            domain_model_hash = None
        except Exception:
            logger.debug("domain model hash failed", exc_info=True)
            domain_model_hash = None

    verdict_rationale = None
    counter_hypothesis = None
    if review_result:
        verdict_rationale = review_result.get("verdict_rationale") or None
        counter_hypothesis = review_result.get("counter_hypothesis") or None

    # Reduced-context and reused verdicts are journaled with their
    # provenance so cross-run verdict reuse can (a) refuse to treat a
    # reduced-context verdict as durable coverage and (b) keep a
    # chain of reuses pointing at the run that actually reviewed.
    context_reduced = bool(getattr(outcome, "context_reduced", False)) or None
    reused = bool(getattr(outcome, "reused", False)) or None
    reused_from_run = (getattr(outcome, "reused_from_run", "") or None) if reused else None

    # Promotion-without-tool-evidence alarm: the journal write is the
    # chokepoint every review outcome flows through, so an evidence-less
    # ``finding`` here means the tool-gated promotion invariant was
    # bypassed upstream.  Alarm-only — the entry is still written.
    try:
        from .promotion_alarm import check_and_emit
        check_and_emit(
            out_dir, outcome, stage="journal-write", run_id=run_id,
        )
    except Exception:
        logger.debug("promotion alarm hook failed", exc_info=True)

    entry = ReviewJournalEntry(
        ts=now_iso(),
        run_id=run_id,
        file=outcome.file,
        function=outcome.function,
        verdict=outcome.status,
        source_hash=source_hash,
        line_start=gap.get("line_start", 0),
        line_end=gap.get("line_end"),
        cwe=review_result.get("cwe") if review_result else None,
        strategies=gap.get("strategies", []),
        domain_model_hash=domain_model_hash,
        domain_concepts_available=domain_concepts,
        invariants_available=invariants_available,
        hypotheses=hypotheses_list,
        body=getattr(outcome, "body", "") or "",
        reading_list_items=reading_list_items,
        study_receipts=study_receipts,
        model=getattr(outcome, "model", None) or None,
        evidence_tools=evidence_tools,
        cost_usd=getattr(outcome, "cost_usd", None) or None,
        duration_s=getattr(outcome, "duration_s", None) or None,
        verdict_rationale=verdict_rationale,
        counter_hypothesis=counter_hypothesis,
        context_reduced=context_reduced,
        reused=reused,
        reused_from_run=reused_from_run,
        producer=producer,
    )
    try:
        append_entry(out_dir, entry)
    except Exception:
        logger.debug(
            "journal append failed for %s:%s",
            outcome.file, outcome.function, exc_info=True,
        )


@dataclass
class Collector:
    """Buffers review outcomes and batches disk writes."""

    out_dir: Path
    target_path: Path
    run_id: str = ""

    _log_entries: list[dict[str, Any]] = field(default_factory=list)
    _flushed: bool = field(default=False)
    _domain_model_hash: str | None = field(default=None, repr=False)

    def submit(
        self,
        outcome: Any,
        gap: dict[str, Any],
        *,
        batch: bool = False,
    ) -> None:
        # Journal is the sole LLM review store (see amendment §2).
        # ``record_review``'s coverage-audit.json write and
        # ``mark_checked``'s checklist stamp were removed at Phase-3
        # completion; the journal captures verdict/body/context and
        # the coverage store imports it at run completion. Model
        # attribution travels via ``entry.model`` — there is no
        # separate checked_by record.
        self._append_journal_entry(outcome, gap)

        entry: dict[str, Any] = {
            "action": "orchestrator_review",
            "key": f"{outcome.file}:{outcome.function}:{gap.get('line_start', 0)}",
            "status": outcome.status,
            "model": outcome.model,
            "cost_usd": outcome.cost_usd,
            "duration_s": outcome.duration_s,
        }
        if outcome.hypothesis:
            entry["hypothesis"] = outcome.hypothesis
        if outcome.hypotheses:
            entry["hypotheses"] = outcome.hypotheses
        if outcome.evidence_tool:
            entry["evidence_tool"] = outcome.evidence_tool
        if outcome.review_result and outcome.review_result.get("preconditions"):
            entry["preconditions"] = outcome.review_result["preconditions"]
        strategies = gap.get("strategies")
        if strategies:
            entry["strategies"] = strategies
        if batch:
            entry["batch"] = True
        self._log_entries.append(entry)

        # ── SAGE: store hypothesis verdict ───────────────────────────────
        src_hash = gap.get("_sage_source_hash", "")
        if src_hash and outcome.status != "error" and outcome.hypothesis:
            try:
                from core.sage.hooks import store_audit_hypothesis_verdict
                store_audit_hypothesis_verdict(
                    repo_path=str(self.target_path),
                    file_path=outcome.file,
                    function=outcome.function,
                    hypothesis=outcome.hypothesis,
                    status=outcome.status,
                    evidence_tool=outcome.evidence_tool or "",
                    source_hash=src_hash,
                )
            except Exception:
                logger.debug(
                    "SAGE hypothesis store failed for %s:%s",
                    outcome.file, outcome.function, exc_info=True,
                )

    def _append_journal_entry(
        self,
        outcome: Any,
        gap: dict[str, Any],
    ) -> None:
        """Append the review outcome to the journal (batch-cached hash)."""
        append_journal_for_outcome(
            out_dir=self.out_dir,
            target_path=self.target_path,
            run_id=self.run_id,
            outcome=outcome,
            gap=gap,
            domain_model_hash=self._get_domain_model_hash(),
        )

    def _get_domain_model_hash(self) -> str | None:
        """Compute and cache the domain-model.json content hash."""
        if self._domain_model_hash is not None:
            return self._domain_model_hash or None
        from .journal import compute_domain_model_hash
        h = compute_domain_model_hash(self.out_dir)
        self._domain_model_hash = h or ""
        return h

    def invalidate_domain_model_cache(self) -> None:
        """Call after the domain model changes (e.g. JIT study loop)."""
        self._domain_model_hash = None
        # cache_clear() cannot raise; only a partial install (import
        # failure) can legitimately fail here.
        with contextlib.suppress(ImportError):
            from core.concepts.audit_bridge import _load_cached
            _load_cached.cache_clear()

    def flush(self) -> None:
        """Write all buffered state to disk in bulk."""
        if self._flushed:
            return

        try:
            try:
                flush_journal(self.out_dir)
            except Exception:
                logger.debug("journal fsync failed", exc_info=True)

            if self._log_entries:
                self._flush_audit_log()
        finally:
            self._flushed = True

    def _flush_audit_log(self) -> None:
        log_path = self.out_dir / ".audit-log.jsonl"
        lines = [json.dumps(e, separators=(",", ":")) for e in self._log_entries]
        with open(log_path, "a") as f:
            f.write("\n".join(lines) + "\n")
