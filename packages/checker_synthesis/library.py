"""Persistent rule library for checker synthesis.

Proven rules (dual control passed, triage ran) are promoted from
per-run ``checkers/`` directories into ``out/rule-library/`` so they
survive across runs.  On the next synthesis attempt for the same CWE,
the library is checked first — if a rule with high TP rate exists, it
is replayed directly (zero LLM cost for synthesis).

Storage layout::

    out/rule-library/
        manifest.json          # index of all promoted rules
        semgrep/               # .yml rule files
        coccinelle/            # .cocci rule files

``manifest.json`` is the authoritative index.  Rule files are
artefacts referenced by path from the manifest.  Both are written
atomically so concurrent runs never see partial state.

The library works without SAGE — it is a flat JSON store with file
artefacts.  SAGE can overlay cross-machine sync later; the manifest
is the local source of truth either way.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.atomic_fs import write_text_atomically

from .cwe_families import cwe_siblings
from .models import CheckerSynthesisResult, Match, MatchTriage

logger = logging.getLogger(__name__)

_DEFAULT_LIBRARY_DIR = Path("out/rule-library")

_REPLAY_TP_THRESHOLD = 0.80
_MIN_TARGETS_FOR_PRUNE = 3
_MIN_TARGETS_FOR_REPLAY = 1


def _body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def _rule_extension(engine: str) -> str:
    return ".yml" if engine == "semgrep" else ".cocci"


@dataclass
class TargetRecord:
    target_hash: str
    ts: str
    matches: int
    variants: int
    tp_rate: Optional[float]
    target_profile: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "target_hash": self.target_hash,
            "ts": self.ts,
            "matches": self.matches,
            "variants": self.variants,
            "tp_rate": self.tp_rate,
        }
        if self.target_profile:
            d["target_profile"] = self.target_profile
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TargetRecord":
        return cls(
            target_hash=d["target_hash"],
            ts=d.get("ts", ""),
            matches=d.get("matches", 0),
            variants=d.get("variants", 0),
            tp_rate=d.get("tp_rate"),
            target_profile=d.get("target_profile", ""),
        )


@dataclass
class LibraryEntry:
    rule_id: str
    engine: str
    cwe: str
    body_hash: str
    rule_path: str
    rationale: str
    seed_file: str
    seed_function: str
    dual_control: bool
    promoted_at: str
    tp_rate: float
    fp_rate: float
    total_variants: int
    total_matches: int = 0
    targets: List[TargetRecord] = field(default_factory=list)
    archived: bool = False
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "rule_id": self.rule_id,
            "engine": self.engine,
            "cwe": self.cwe,
            "body_hash": self.body_hash,
            "rule_path": self.rule_path,
            "rationale": self.rationale,
            "seed_file": self.seed_file,
            "seed_function": self.seed_function,
            "dual_control": self.dual_control,
            "promoted_at": self.promoted_at,
            "tp_rate": self.tp_rate,
            "fp_rate": self.fp_rate,
            "total_variants": self.total_variants,
            "total_matches": self.total_matches,
            "targets": [t.to_dict() for t in self.targets],
            "archived": self.archived,
        }
        if self.source:
            d["source"] = self.source
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LibraryEntry":
        return cls(
            rule_id=d["rule_id"],
            engine=d["engine"],
            cwe=d["cwe"],
            body_hash=d["body_hash"],
            rule_path=d["rule_path"],
            rationale=d.get("rationale", ""),
            seed_file=d.get("seed_file", ""),
            seed_function=d.get("seed_function", ""),
            dual_control=d.get("dual_control", False),
            promoted_at=d.get("promoted_at", ""),
            tp_rate=d.get("tp_rate", 0.0),
            fp_rate=d.get("fp_rate", 0.0),
            total_variants=d.get("total_variants", 0),
            total_matches=d.get("total_matches") or d.get("total_variants", 0),
            targets=[TargetRecord.from_dict(t) for t in d.get("targets", [])],
            archived=d.get("archived", False),
            source=d.get("source", ""),
        )


def _compute_rates(
    triage: List[MatchTriage],
) -> Tuple[float, float, int]:
    classified = [t for t in triage if t.status in ("variant", "false_positive")]
    if not classified:
        return 0.0, 0.0, 0
    variants = sum(1 for t in classified if t.status == "variant")
    fps = sum(1 for t in classified if t.status == "false_positive")
    total = len(classified)
    return variants / total, fps / total, variants


class RuleLibrary:
    """Persistent rule library backed by a manifest.json file."""

    def __init__(self, library_dir: Optional[Path] = None) -> None:
        self._dir = Path(library_dir) if library_dir else _DEFAULT_LIBRARY_DIR
        self._manifest_path = self._dir / "manifest.json"
        self._entries: Optional[List[LibraryEntry]] = None
        self._lock = threading.Lock()

    @property
    def library_dir(self) -> Path:
        return self._dir

    def _ensure_dirs(self) -> None:
        (self._dir / "semgrep").mkdir(parents=True, exist_ok=True)
        (self._dir / "coccinelle").mkdir(parents=True, exist_ok=True)

    def _load(self) -> List[LibraryEntry]:
        if self._entries is not None:
            return self._entries
        if not self._manifest_path.exists():
            self._entries = []
            return self._entries
        try:
            data = json.loads(self._manifest_path.read_text(encoding="utf-8"))
            self._entries = [LibraryEntry.from_dict(e) for e in data.get("rules", [])]
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
            logger.warning("rule library manifest corrupt, starting fresh: %s", exc)
            self._entries = []
        return self._entries

    def _save(self) -> None:
        self._ensure_dirs()
        entries = self._load()
        data = {"rules": [e.to_dict() for e in entries]}
        write_text_atomically(
            self._manifest_path,
            json.dumps(data, indent=2, sort_keys=False) + "\n",
            tmp_prefix=".manifest-",
        )

    def find(self, cwe: str, engine: str) -> List[LibraryEntry]:
        """Find active library rules matching a CWE and engine.

        Uses the CWE family mapper so a rule promoted for CWE-564
        is also found when querying CWE-89 (both SQL injection).
        """
        family = set(cwe_siblings(cwe))
        return [
            e for e in self._load()
            if e.cwe in family and e.engine == engine and not e.archived
        ]

    def find_replayable(self, cwe: str, engine: str) -> List[LibraryEntry]:
        """Find rules suitable for replay (high TP, enough targets).

        Sorted by TP rate descending, then by number of targets tested
        (more evidence = higher confidence). Caller typically takes [0].
        """
        candidates = [
            e for e in self.find(cwe, engine)
            if e.tp_rate >= _REPLAY_TP_THRESHOLD
            and len(e.targets) >= _MIN_TARGETS_FOR_REPLAY
            and e.dual_control
        ]
        candidates.sort(key=lambda e: (e.tp_rate, len(e.targets)), reverse=True)
        return candidates

    def get_by_body_hash(self, body_hash: str) -> Optional[LibraryEntry]:
        """Look up by rule body hash (dedup key)."""
        for e in self._load():
            if e.body_hash == body_hash:
                return e
        return None

    def promote(
        self,
        result: CheckerSynthesisResult,
        *,
        target_hash: str = "",
        timestamp: str = "",
        source: str = "",
    ) -> Optional[LibraryEntry]:
        """Promote a synthesis result into the library.

        Returns the new/updated LibraryEntry, or None if the result
        doesn't meet promotion criteria (no rule, dual control failed,
        no triage).
        """
        if result.rule is None or result.rule_path is None:
            return None
        if not result.dual_control:
            return None
        if not result.triage:
            return None

        with self._lock:
            return self._promote_locked(result, target_hash=target_hash,
                                        timestamp=timestamp, source=source)

    def _promote_locked(
        self,
        result: CheckerSynthesisResult,
        *,
        target_hash: str = "",
        timestamp: str = "",
        source: str = "",
    ) -> Optional[LibraryEntry]:
        self._ensure_dirs()
        rule = result.rule
        bh = _body_hash(rule.body)

        existing = self.get_by_body_hash(bh)
        if existing is not None:
            self._update_entry(existing, result, target_hash, timestamp)
            self._save()
            return existing

        rel_path = f"{rule.engine}/{rule.rule_id}{_rule_extension(rule.engine)}"
        dest = self._dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)

        if result.rule_path and Path(result.rule_path).exists():
            shutil.copy2(str(result.rule_path), str(dest))
        else:
            write_text_atomically(dest, rule.body, tmp_prefix=".rule-")

        tp_rate, fp_rate, variant_count = _compute_rates(result.triage)

        targets: List[TargetRecord] = []
        if target_hash:
            targets.append(TargetRecord(
                target_hash=target_hash,
                ts=timestamp,
                matches=len(result.matches),
                variants=variant_count,
                tp_rate=tp_rate if result.triage else None,
            ))

        entry = LibraryEntry(
            rule_id=rule.rule_id,
            engine=rule.engine,
            cwe=result.seed.cwe,
            body_hash=bh,
            rule_path=rel_path,
            rationale=rule.rationale,
            seed_file=result.seed.file,
            seed_function=result.seed.function,
            dual_control=True,
            promoted_at=timestamp,
            tp_rate=tp_rate,
            fp_rate=fp_rate,
            total_variants=variant_count,
            targets=targets,
            source=source,
        )

        self._load().append(entry)
        self._save()
        logger.info(
            "promoted rule %s to library (cwe=%s, engine=%s, tp=%.0f%%)",
            rule.rule_id, result.seed.cwe, rule.engine, tp_rate * 100,
        )
        return entry

    def _update_entry(
        self,
        entry: LibraryEntry,
        result: CheckerSynthesisResult,
        target_hash: str,
        timestamp: str,
    ) -> None:
        tp_rate, fp_rate, variant_count = _compute_rates(result.triage)
        if target_hash:
            already = {t.target_hash for t in entry.targets}
            if target_hash not in already:
                entry.targets.append(TargetRecord(
                    target_hash=target_hash,
                    ts=timestamp,
                    matches=len(result.matches),
                    variants=variant_count,
                    tp_rate=tp_rate if result.triage else None,
                ))
        entry.total_variants += variant_count
        self._recompute_aggregate(entry)

    def update(
        self,
        rule_id: str,
        target_hash: str,
        matches: List[Match],
        triage: List[MatchTriage],
        timestamp: str = "",
    ) -> Optional[LibraryEntry]:
        """Update effectiveness after replaying a library rule."""
        entries = self._load()
        entry = next((e for e in entries if e.rule_id == rule_id), None)
        if entry is None:
            return None

        tp_rate, fp_rate, variant_count = _compute_rates(triage)
        already = {t.target_hash for t in entry.targets}
        if target_hash and target_hash not in already:
            entry.targets.append(TargetRecord(
                target_hash=target_hash,
                ts=timestamp,
                matches=len(matches),
                variants=variant_count,
                tp_rate=tp_rate if triage else None,
            ))
        entry.total_variants += variant_count
        self._recompute_aggregate(entry)
        self._auto_archive(entry)
        self._save()
        return entry

    def _recompute_aggregate(self, entry: LibraryEntry) -> None:
        rated = [t for t in entry.targets if t.tp_rate is not None]
        if not rated:
            return
        total_matches = sum(t.matches for t in rated) or 1
        entry.tp_rate = sum(
            t.tp_rate * t.matches for t in rated
        ) / total_matches
        entry.fp_rate = 1.0 - entry.tp_rate

    def _auto_archive(self, entry: LibraryEntry) -> None:
        if len(entry.targets) < _MIN_TARGETS_FOR_PRUNE:
            return
        if entry.total_variants == 0:
            entry.archived = True
            logger.info(
                "archived rule %s: 0 variants across %d targets",
                entry.rule_id, len(entry.targets),
            )

    def rule_path(self, entry: LibraryEntry) -> Path:
        """Absolute path to the rule file on disk."""
        return self._dir / entry.rule_path

    def all_entries(self) -> List[LibraryEntry]:
        """All entries including archived."""
        return list(self._load())

    def active_entries(self) -> List[LibraryEntry]:
        """Non-archived entries only."""
        return [e for e in self._load() if not e.archived]

    def add_rule(
        self,
        rule_id: str,
        engine: str,
        body: str,
        *,
        cwe: str = "",
        rationale: str = "",
        seed_file: str = "",
        seed_function: str = "",
        source: str = "",
        timestamp: str = "",
    ) -> LibraryEntry:
        """Add a rule directly (no CheckerSynthesisResult needed).

        Used by /audit which builds rules via its own synthesis adapter
        and doesn't always have a full CheckerSynthesisResult.  Deduplicates
        by body hash — returns the existing entry if the rule body already
        exists.
        """
        with self._lock:
            self._ensure_dirs()
            bh = _body_hash(body)

            existing = self.get_by_body_hash(bh)
            if existing is not None:
                return existing

            ext = _rule_extension(engine)
            rel_path = f"{engine}/{rule_id}{ext}"
            dest = self._dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            write_text_atomically(dest, body, tmp_prefix=".rule-")

            entry = LibraryEntry(
                rule_id=rule_id,
                engine=engine,
                cwe=cwe,
                body_hash=bh,
                rule_path=rel_path,
                rationale=rationale,
                seed_file=seed_file,
                seed_function=seed_function,
                dual_control=False,
                promoted_at=timestamp,
                tp_rate=0.0,
                fp_rate=0.0,
                total_variants=0,
                source=source,
            )
            self._load().append(entry)
            self._save()
            return entry

    def record_match(self, rule_id: str, is_tp: bool) -> None:
        """Record a single match result (simpler API than update()).

        Increments total_variants if TP, recomputes rates.
        """
        with self._lock:
            entries = self._load()
            entry = next((e for e in entries if e.rule_id == rule_id), None)
            if entry is None:
                return
            entry.total_matches += 1
            if is_tp:
                entry.total_variants += 1
            entry.tp_rate = entry.total_variants / entry.total_matches
            entry.fp_rate = 1.0 - entry.tp_rate
            self._save()

    def retire_low_precision(
        self, *, threshold: float = 0.3, min_evidence: int = 5,
    ) -> List[str]:
        """Archive rules below the precision threshold.

        Only considers rules with enough evidence (total matches across
        targets). Returns list of archived rule_ids.
        """
        retired: List[str] = []
        for entry in self._load():
            if entry.archived:
                continue
            total_matches = sum(t.matches for t in entry.targets)
            if total_matches < min_evidence:
                continue
            if entry.tp_rate < threshold:
                entry.archived = True
                retired.append(entry.rule_id)
                logger.info(
                    "retired rule %s: tp_rate=%.0f%% below threshold %.0f%%",
                    entry.rule_id, entry.tp_rate * 100, threshold * 100,
                )
        if retired:
            self._save()
        return retired

    def graduate(self, engine_rules_dir: Path) -> List[str]:
        """Promote high-confidence rules to the engine rules directory.

        Graduated rules run as first-class scanner rules in /scan and
        /agentic. Requires: >=2 true positives, >=3 total matches,
        precision >=80%.

        Returns list of graduated rule_ids.
        """
        graduated: List[str] = []
        for entry in self._load():
            if entry.archived:
                continue
            total_matches = sum(t.matches for t in entry.targets)
            if entry.total_variants < 2 or total_matches < 3:
                continue
            if entry.tp_rate < 0.80:
                continue

            if entry.engine == "semgrep":
                dest = engine_rules_dir / "semgrep" / "rules" / f"{entry.rule_id}.yaml"
            elif entry.engine == "coccinelle":
                dest = engine_rules_dir / "coccinelle" / f"{entry.rule_id}.cocci"
            else:
                dest = engine_rules_dir / entry.engine / f"{entry.rule_id}.rule"

            if dest.exists():
                continue

            src = self._dir / entry.rule_path
            if not src.exists():
                continue

            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dest))
                graduated.append(entry.rule_id)
                logger.info(
                    "graduated rule %s → %s (tp=%.0f%%, %d variants)",
                    entry.rule_id, dest, entry.tp_rate * 100,
                    entry.total_variants,
                )
            except OSError:
                logger.warning(
                    "failed to graduate %s", entry.rule_id, exc_info=True,
                )
        return graduated

    def summary(self) -> str:
        """One-line summary for log output."""
        entries = self._load()
        active = [e for e in entries if not e.archived]
        archived = len(entries) - len(active)
        if not entries:
            return "Rule library: empty"
        rated = [e for e in active if e.tp_rate > 0]
        avg = sum(e.tp_rate for e in rated) / len(rated) if rated else 0.0
        return (
            f"Rule library: {len(active)} active, {archived} archived, "
            f"avg precision {avg:.0%}"
        )

    def stats(self) -> Dict[str, Any]:
        """Summary statistics for /sage status or reports."""
        entries = self._load()
        active = [e for e in entries if not e.archived]
        return {
            "total_rules": len(entries),
            "active_rules": len(active),
            "archived_rules": len(entries) - len(active),
            "engines": {
                "semgrep": sum(1 for e in active if e.engine == "semgrep"),
                "coccinelle": sum(1 for e in active if e.engine == "coccinelle"),
            },
            "total_variants_found": sum(e.total_variants for e in active),
            "avg_tp_rate": (
                sum(e.tp_rate for e in active) / len(active)
                if active else 0.0
            ),
        }
