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
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.atomic_fs import write_bytes_atomically, write_text_atomically
from core.json import load_json, save_json

from .cwe_families import cwe_siblings

if TYPE_CHECKING:
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


# A path component that cannot traverse: no separators, no leading dot
# (rejects "..", hidden files), filesystem-safe charset.
_SAFE_COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


def _safe_component(value: str, *, what: str) -> str:
    """Confine ``value`` to a single, traversal-free path component.

    ``rule_id`` and ``engine`` become file-name components under the
    library (and, at graduation, under the engine rules dir). The main
    synthesis path slugifies rule ids, but this class is a public
    chokepoint whose ids also arrive from persisted manifests and
    replayed metadata stores — none of which are re-validated
    upstream. An id like ``../../x`` or ``/abs/path`` would otherwise
    write LLM-synthesized rule content to an arbitrary path.

    Values already safe pass through unchanged; anything else is
    slugified with the same character policy as the synthesis-side
    slug (non ``[A-Za-z0-9_.-]`` runs become ``_``, leading/trailing
    ``_``/``.`` stripped, empty falls back to ``x``).
    """
    if _SAFE_COMPONENT_RE.fullmatch(value or ""):
        return value
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "").strip("_.")
    slug = slug or "x"
    logger.warning(
        "%s %r is not a safe path component — sanitised to %r",
        what, value, slug,
    )
    return slug


def _require_within(base: Path, candidate: Path, *, what: str) -> Path:
    """Belt-and-braces containment check for a write destination."""
    resolved = candidate.resolve()
    if not resolved.is_relative_to(base.resolve()):
        msg = f"{what} escapes {base}: {candidate}"
        raise ValueError(msg)
    return candidate


@dataclass
class TargetRecord:
    target_hash: str
    ts: str
    matches: int
    variants: int
    tp_rate: float | None
    target_profile: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
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
    def from_dict(cls, d: dict[str, Any]) -> TargetRecord:
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
    # Per-match feedback verdicts (record_match). Kept separate from
    # the raw counters: total_matches also counts untriaged sweep
    # hits, and dividing a verdict count by it let one feedback call
    # collapse a proven rule's tp_rate. These blend into the precision
    # aggregate as one-verdict samples instead.
    feedback_variants: int = 0
    feedback_classified: int = 0
    targets: list[TargetRecord] = field(default_factory=list)
    archived: bool = False
    source: str = ""
    # Mechanical-control tier at persist time: "library" only when
    # every control passed (positive + dual + fix-mutant / verified
    # ground-truth negative). Legacy manifests without the field
    # deserialise as "sweep_once" — fail-closed for graduation.
    rule_tier: str = "sweep_once"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
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
            "feedback_variants": self.feedback_variants,
            "feedback_classified": self.feedback_classified,
            "targets": [t.to_dict() for t in self.targets],
            "archived": self.archived,
            "rule_tier": self.rule_tier,
        }
        if self.source:
            d["source"] = self.source
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> LibraryEntry:
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
            total_matches=d.get("total_matches", d.get("total_variants", 0)),
            feedback_variants=d.get("feedback_variants", 0),
            feedback_classified=d.get("feedback_classified", 0),
            targets=[TargetRecord.from_dict(t) for t in d.get("targets", [])],
            archived=d.get("archived", False),
            source=d.get("source", ""),
            # Legacy manifests predate the field. dual_control=True
            # could only be stamped by promote(), whose gate already
            # required rule_tier="library" at persist time; add_rule
            # always stamped dual_control=False. So the flag is a
            # sound tier witness for old rows; everything else stays
            # sweep_once (fail-closed).
            rule_tier=d.get(
                "rule_tier",
                "library" if d.get("dual_control") else "sweep_once",
            ),
        )


def _compute_rates(
    triage: list[MatchTriage],
) -> tuple[float, float, int]:
    classified = [t for t in triage if t.status in ("variant", "false_positive")]
    if not classified:
        return 0.0, 0.0, 0
    variants = sum(1 for t in classified if t.status == "variant")
    fps = sum(1 for t in classified if t.status == "false_positive")
    total = len(classified)
    return variants / total, fps / total, variants


class RuleLibrary:
    """Persistent rule library backed by a manifest.json file."""

    def __init__(self, library_dir: Path | None = None) -> None:
        self._dir = Path(library_dir) if library_dir else _DEFAULT_LIBRARY_DIR
        self._manifest_path = self._dir / "manifest.json"
        self._entries: list[LibraryEntry] | None = None
        self._lock = threading.Lock()

    @property
    def library_dir(self) -> Path:
        return self._dir

    def _ensure_dirs(self) -> None:
        (self._dir / "semgrep").mkdir(parents=True, exist_ok=True)
        (self._dir / "coccinelle").mkdir(parents=True, exist_ok=True)

    def _dest_rel_path(self, engine: str, rule_id: str, body_hash: str) -> str:
        """Collision-free manifest-relative path for a new rule file.

        The dedup key is the BODY hash, but the file name derives from
        the rule id — two different bodies can legitimately share a
        rule id (same seed re-synthesised across runs or CVEs). Writing
        both to one path would leave the earlier manifest entry
        pointing at the later entry's body (hash/disk mismatch; a
        replay of the first entry silently runs the second entry's
        rule), so a second body under a taken name gets a body-hash
        suffix instead.
        """
        engine = _safe_component(engine, what="engine")
        rule_id = _safe_component(rule_id, what="rule id")
        ext = _rule_extension(engine)
        rel_path = f"{engine}/{rule_id}{ext}"
        taken = {
            e.rule_path for e in self._load() if e.body_hash != body_hash
        }
        if rel_path in taken:
            rel_path = f"{engine}/{rule_id}-{body_hash[:8]}{ext}"
        return rel_path

    def _load(self) -> list[LibraryEntry]:
        if self._entries is not None:
            return self._entries
        if not self._manifest_path.exists():
            self._entries = []
            return self._entries
        try:
            # ValueError covers malformed JSON and the byte-budget
            # refusal; the manifest is written by _save via save_json.
            data = load_json(
                self._manifest_path, strict=True,
                max_bytes=64 * 1024 * 1024,
            )
            self._entries = [LibraryEntry.from_dict(e) for e in data.get("rules", [])]
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            logger.warning("rule library manifest corrupt, starting fresh: %s", exc)
            self._entries = []
        return self._entries

    def _save(self) -> None:
        self._ensure_dirs()
        entries = self._load()
        data = {"rules": [e.to_dict() for e in entries]}
        save_json(self._manifest_path, data)

    def find(self, cwe: str, engine: str) -> list[LibraryEntry]:
        """Find active library rules matching a CWE and engine.

        Uses the CWE family mapper so a rule promoted for CWE-564
        is also found when querying CWE-89 (both SQL injection).
        """
        family = set(cwe_siblings(cwe))
        return [
            e for e in self._load()
            if e.cwe in family and e.engine == engine and not e.archived
        ]

    def find_replayable(self, cwe: str, engine: str) -> list[LibraryEntry]:
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

    def get_by_body_hash(self, body_hash: str) -> LibraryEntry | None:
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
    ) -> LibraryEntry | None:
        """Promote a synthesis result into the library.

        Returns the new/updated LibraryEntry, or None if the result
        doesn't meet promotion criteria (no rule, dual control failed,
        rule_tier below "library" — e.g. missing fixtures or a failed
        fix-mutant control — or no triage).
        """
        if result.rule is None or result.rule_path is None:
            return None
        if not result.dual_control:
            return None
        # Fail-closed library gate: synthesise_and_run only stamps
        # rule_tier="library" when every mechanical control passed
        # (positive + dual + fix-mutant).  getattr keeps foreign /
        # legacy result objects without the field excluded too.
        if getattr(result, "rule_tier", "sweep_once") != "library":
            logger.info(
                "promote refused for %s: rule_tier=%r (library "
                "requires all mechanical controls to pass)",
                result.rule.rule_id,
                getattr(result, "rule_tier", "sweep_once"),
            )
            return None
        if not result.triage:
            return None

        with self._lock:
            entry = self._promote_locked(result, target_hash=target_hash,
                                         timestamp=timestamp, source=source)
        if entry is not None:
            self._store_metadata_in_sage(entry, result)
        return entry

    def _store_metadata_in_sage(
        self,
        entry: LibraryEntry,
        result: CheckerSynthesisResult,
    ) -> None:
        """Index the graduated rule in SAGE (best-effort, never raises).

        The library manifest stays the local source of truth; SAGE
        holds an index row so future runs can replay proven rules via
        ``core.audit.checker_synthesis._sage_replay_rule``. That recall
        side only trusts HMAC-verified rows, so the store hook stamps
        the decision fields (engine/cwe/rule_id/body-hash/counts) at
        write time.
        """
        try:
            from core.sage.hooks import store_proven_rule_metadata
        except ImportError:
            return
        try:
            classified = [
                t for t in result.triage
                if t.status in ("variant", "false_positive")
            ]
            tp_count = sum(1 for t in classified if t.status == "variant")
            fp_count = sum(
                1 for t in classified if t.status == "false_positive"
            )
            store_proven_rule_metadata(
                engine=entry.engine,
                cwe=entry.cwe,
                rule_id=entry.rule_id,
                rule_body_hash=entry.body_hash,
                rule_path=str(self.rule_path(entry)),
                tp_count=tp_count,
                fp_count=fp_count,
                total_matches=len(result.matches),
                dual_control_passed=entry.dual_control,
                targets_tested=max(len(entry.targets), 1),
            )
        except Exception:
            logger.debug("SAGE proven-rule store failed", exc_info=True)

    def _promote_locked(
        self,
        result: CheckerSynthesisResult,
        *,
        target_hash: str = "",
        timestamp: str = "",
        source: str = "",
    ) -> LibraryEntry | None:
        self._ensure_dirs()
        rule = result.rule
        bh = _body_hash(rule.body)

        existing = self.get_by_body_hash(bh)
        if existing is not None:
            self._update_entry(existing, result, target_hash, timestamp)
            self._save()
            return existing

        rel_path = self._dest_rel_path(rule.engine, rule.rule_id, bh)
        dest = _require_within(
            self._dir, self._dir / rel_path, what="rule file path",
        )
        dest.parent.mkdir(parents=True, exist_ok=True)

        # The manifest's body_hash is computed from rule.body, so the
        # persisted file must hold exactly those bytes. The per-run
        # rule_path file is preferred as the source only when it still
        # matches — a refinement loop may have overwritten it with a
        # later iteration's body, and copying that would store one
        # rule's body under another rule's hash.
        source_bytes: bytes | None = None
        if result.rule_path and Path(result.rule_path).exists():
            candidate = Path(result.rule_path).read_bytes()
            if _body_hash(candidate.decode("utf-8", errors="replace")) == bh:
                source_bytes = candidate
        if source_bytes is not None:
            # Tempfile + rename so concurrent runs never see a
            # partially-copied rule file (module contract: manifest
            # AND rule files are written atomically).
            write_bytes_atomically(dest, source_bytes, tmp_prefix=".rule-")
        else:
            write_text_atomically(dest, rule.body, tmp_prefix=".rule-")

        tp_rate, fp_rate, variant_count = _compute_rates(result.triage)

        targets: list[TargetRecord] = []
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
            total_matches=len(result.matches),
            targets=targets,
            source=source,
            rule_tier="library",
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
        tp_rate, _fp_rate, variant_count = _compute_rates(result.triage)
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
        entry.total_matches += len(result.matches)
        # Only called from the promote() path, whose gate already
        # required every mechanical control — an existing add_rule
        # (sweep_once) copy of the same body is upgraded in place.
        entry.dual_control = True
        entry.rule_tier = "library"
        self._recompute_aggregate(entry)

    def update(
        self,
        rule_id: str,
        target_hash: str,
        matches: list[Match],
        triage: list[MatchTriage],
        timestamp: str = "",
    ) -> LibraryEntry | None:
        """Update effectiveness after replaying a library rule.

        Locked like promote/add_rule/record_match: this is a
        read-modify-write over shared entry state, and an unlocked
        interleave with a concurrent writer in the same process can
        drop the other thread's mutation at save time. (Cross-process
        writers remain last-writer-wins — the manifest is a whole-file
        atomic store, not a merge log.)
        """
        with self._lock:
            entries = self._load()
            entry = next((e for e in entries if e.rule_id == rule_id), None)
            if entry is None:
                return None

            tp_rate, _fp_rate, variant_count = _compute_rates(triage)
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
            entry.total_matches += len(matches)
            self._recompute_aggregate(entry)
            self._auto_archive(entry)
            self._save()
            return entry

    def _recompute_aggregate(self, entry: LibraryEntry) -> None:
        # Per-target triage rates weighted by match count, blended
        # with record_match feedback as one-verdict samples. Including
        # the feedback counters here means a later update() no longer
        # silently discards previously recorded feedback.
        rated = [t for t in entry.targets if t.tp_rate is not None]
        weight = sum(t.matches for t in rated)
        weighted_tp = sum(t.tp_rate * t.matches for t in rated)
        denominator = weight + entry.feedback_classified
        if denominator <= 0:
            return
        entry.tp_rate = (
            weighted_tp + entry.feedback_variants
        ) / denominator
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

    def all_entries(self) -> list[LibraryEntry]:
        """All entries including archived."""
        return list(self._load())

    def active_entries(self) -> list[LibraryEntry]:
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
        dual_control: bool = False,
        rule_tier: str = "sweep_once",
    ) -> LibraryEntry:
        """Add a rule directly (no CheckerSynthesisResult needed).

        Used by /audit which builds rules via its own synthesis adapter
        and doesn't always have a full CheckerSynthesisResult.  Deduplicates
        by body hash — returns the existing entry if the rule body already
        exists.

        Tier gate (same policy as :meth:`promote`): callers thread the
        synthesis result's ``dual_control`` / ``rule_tier`` through, and
        ``rule_tier="library"`` is only accepted alongside
        ``dual_control=True`` — otherwise it is downgraded to
        ``sweep_once`` with a warning. Defaults keep legacy callers
        fail-closed: an add_rule entry without control evidence can
        never graduate to the engine rules dir.
        """
        if rule_tier == "library" and not dual_control:
            logger.warning(
                "add_rule %s: rule_tier='library' requires "
                "dual_control=True — downgrading to sweep_once",
                rule_id,
            )
            rule_tier = "sweep_once"
        if rule_tier not in ("library", "sweep_once"):
            rule_tier = "sweep_once"
        with self._lock:
            self._ensure_dirs()
            bh = _body_hash(body)

            existing = self.get_by_body_hash(bh)
            if existing is not None:
                return existing

            rel_path = self._dest_rel_path(engine, rule_id, bh)
            dest = _require_within(
                self._dir, self._dir / rel_path, what="rule file path",
            )
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
                dual_control=dual_control,
                promoted_at=timestamp,
                tp_rate=0.0,
                fp_rate=0.0,
                total_variants=0,
                source=source,
                rule_tier=rule_tier,
            )
            self._load().append(entry)
            self._save()
            return entry

    def record_match(self, rule_id: str, is_tp: bool) -> None:
        """Record a single triaged match result (simpler API than update()).

        The verdict lands in the feedback counters and moves precision
        by one sample via the shared aggregate. Dividing the verdict
        count by ``total_matches`` instead (which also counts untriaged
        sweep hits) let a single true-positive report collapse a proven
        rule's tp_rate below the replay and retirement thresholds.
        """
        with self._lock:
            entries = self._load()
            entry = next((e for e in entries if e.rule_id == rule_id), None)
            if entry is None:
                return
            entry.total_matches += 1
            entry.feedback_classified += 1
            if is_tp:
                entry.total_variants += 1
                entry.feedback_variants += 1
            self._recompute_aggregate(entry)
            self._save()

    def retire_low_precision(
        self, *, threshold: float = 0.3, min_evidence: int = 5,
    ) -> list[str]:
        """Archive rules below the precision threshold.

        Only considers rules with enough evidence (total matches across
        targets). Returns list of archived rule_ids. Locked — this is a
        read-modify-write over shared entry state (see :meth:`update`).
        """
        retired: list[str] = []
        with self._lock:
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

    def graduate(self, engine_rules_dir: Path) -> list[str]:
        """Promote high-confidence rules to the engine rules directory.

        Graduated rules run as first-class scanner rules in /scan and
        /agentic. Requires the mechanical-control tier (dual_control
        AND rule_tier="library" — precision statistics alone cannot
        substitute for the controls, since record_match feedback can
        inflate tp_rate on a rule that never proved it distinguishes
        fixed from unfixed code) plus the precision thresholds:
        >=2 true positives, >=3 total matches, precision >=80%.

        Returns list of graduated rule_ids.
        """
        graduated: list[str] = []
        for entry in self._load():
            if entry.archived:
                continue
            if not entry.dual_control or entry.rule_tier != "library":
                continue
            total_matches = sum(t.matches for t in entry.targets)
            if entry.total_variants < 2 or total_matches < 3:
                continue
            if entry.tp_rate < 0.80:
                continue

            # rule_id / engine come from the persisted manifest, which
            # is not re-validated on load — confine them to single
            # path components and require the final destination to
            # stay inside the engine rules dir before writing.
            rule_id = _safe_component(entry.rule_id, what="rule id")
            engine = _safe_component(entry.engine, what="engine")
            if entry.engine == "semgrep":
                dest = engine_rules_dir / "semgrep" / "rules" / f"{rule_id}.yaml"
            elif entry.engine == "coccinelle":
                dest = engine_rules_dir / "coccinelle" / f"{rule_id}.cocci"
            else:
                dest = engine_rules_dir / engine / f"{rule_id}.rule"
            try:
                dest = _require_within(
                    engine_rules_dir, dest, what="graduated rule path",
                )
                src = _require_within(
                    self._dir, self._dir / entry.rule_path,
                    what="library rule path",
                )
            except ValueError:
                logger.warning(
                    "refusing to graduate %s: unsafe path",
                    entry.rule_id, exc_info=True,
                )
                continue

            if dest.exists():
                continue

            if not src.exists():
                continue

            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                # Same atomicity contract as promote: /scan and
                # /agentic may load engine rules while a graduate
                # runs — they must never read a partial rule file.
                write_bytes_atomically(
                    dest, src.read_bytes(), tmp_prefix=".rule-",
                )
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

    def stats(self) -> dict[str, Any]:
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
