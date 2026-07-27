"""Collector — batches per-review I/O for the audit orchestrator.

Buffers ``append_audit_log`` (N file opens) writes that flush once at
the end of the review loop, and dual-writes each review to the journal.

``record_review`` (one file per function, no contention) stays
per-call — batching it adds complexity for no gain.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gaps import mark_checked
from .journal import ReviewJournalEntry, append_entry, flush_journal, now_iso
from .record import record_review

logger = logging.getLogger(__name__)


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
        checked_by = ["audit"]
        if outcome.model:
            checked_by.append(outcome.model)

        record_review(
            out_dir=self.out_dir,
            target_path=self.target_path,
            file_path=outcome.file,
            function_name=outcome.function,
            status=outcome.status,
            body=outcome.body,
            line_start=gap.get("line_start", 0),
            line_end=gap.get("line_end"),
            strategies=gap.get("strategies"),
            checked_by=checked_by,
        )

        if outcome.status != "error":
            mark_checked(
                self.out_dir, outcome.file, outcome.function, checked_by,
            )

        self._append_journal_entry(outcome, gap, checked_by)

        entry: dict[str, Any] = {
            "action": "orchestrator_review",
            "key": f"{outcome.file}:{outcome.function}",
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

    def _append_journal_entry(
        self,
        outcome: Any,
        gap: dict[str, Any],
        checked_by: list[str],
    ) -> None:
        """Dual-write: append a journal entry alongside checked_by."""
        source_hash = ""
        try:
            from .record import _compute_hash
            h = _compute_hash(
                self.target_path,
                outcome.file,
                gap.get("line_start", 0),
                gap.get("line_end"),
            )
            if h:
                source_hash = h
        except Exception:
            pass

        hypotheses_list: list[dict[str, str]] = []
        if outcome.hypotheses:
            hypotheses_list = outcome.hypotheses
        elif outcome.hypothesis:
            hypotheses_list = [{"claim": outcome.hypothesis, "status": "unknown"}]

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

        domain_concepts: list[str] = []
        invariants_available: list[str] = []
        try:
            from core.concepts.audit_bridge import (
                _find_domain_model, _guard_in_scope, _relevance_score,
            )
            dm = _find_domain_model(self.out_dir)
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
                    if inv_role == "guard":
                        if not _guard_in_scope(inv, outcome.file or ""):
                            continue
                    inv_id = inv.get("id", "")
                    if inv_id:
                        invariants_available.append(inv_id)
        except Exception:
            pass

        entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id=self.run_id,
            file=outcome.file,
            function=outcome.function,
            verdict=outcome.status,
            source_hash=source_hash,
            line_start=gap.get("line_start", 0),
            line_end=gap.get("line_end"),
            cwe=review_result.get("cwe") if review_result else None,
            strategies=gap.get("strategies", []),
            domain_model_hash=self._get_domain_model_hash(),
            domain_concepts_available=domain_concepts,
            invariants_available=invariants_available,
            hypotheses=hypotheses_list,
            body=outcome.body,
            reading_list_items=reading_list_items,
            model=outcome.model or None,
            evidence_tools=evidence_tools,
            cost_usd=outcome.cost_usd or None,
            duration_s=outcome.duration_s or None,
        )
        try:
            append_entry(self.out_dir, entry)
        except Exception:
            logger.debug("journal append failed for %s:%s", outcome.file, outcome.function, exc_info=True)

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
        try:
            from core.concepts.audit_bridge import _load_cached
            _load_cached.cache_clear()
        except Exception:
            pass

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
