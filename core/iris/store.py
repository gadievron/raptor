"""Persistent project-level storage for IRIS taint specs.

Specs are keyed by project output directory and checklist fingerprint.
When the target's source files change (SHA mismatch), low-confidence
specs are evicted while tool-confirmed ones are kept for re-validation.

Storage layout::

    <project_output_dir>/iris-specs/specs.json

The project output dir is the *parent* of a run's output dir — the same
convention used by joern CPG sharing and annotation directories.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.evidence import EvidenceTier, TIER_RANK, stronger

from .assumptions import (
    SafetyAssumption,
    assumptions_from_list,
)
from .specs import TaintSpec, _specs_from_list
import contextlib

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 2
_STORE_DIR = "iris-specs"
_STORE_FILE = "specs.json"


@dataclass
class RoundRecord:
    """Summary of one synthesis/refinement round.

    ``confirmed_keys`` / ``refuted_keys`` carry the per-round spec
    keys (``_spec_key`` format) so the store's merge step can drop
    refuted specs instead of resurrecting them from the add/upgrade-
    only merge on the next run.
    """

    round: int
    n_specs: int
    n_confirmed: int = 0
    n_refuted: int = 0
    n_errors: int = 0
    n_bypass: int = 0
    confirmed_keys: list[str] = field(default_factory=list)
    refuted_keys: list[str] = field(default_factory=list)


def _spec_key(spec: TaintSpec) -> str:
    return f"{spec.file}\0{spec.function}\0{spec.role}"


def checklist_sha(checklist: dict[str, Any]) -> str:
    """Compute a fingerprint from a checklist's file paths + hashes.

    Deterministic: sorted by path, each entry is ``path:sha256``.
    """
    parts = []
    for f in sorted(checklist.get("files") or [], key=lambda x: x.get("path", "")):
        path = f.get("path", "")
        sha = f.get("sha256", "")
        if path:
            parts.append(f"{path}:{sha}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _project_dir(out_dir: Path) -> Path:
    """Resolve the project output dir from a run's output dir.

    Convention: run dirs are timestamped subdirs of the project dir.
    """
    return out_dir.parent


def _store_path(out_dir: Path) -> Path:
    return _project_dir(out_dir) / _STORE_DIR / _STORE_FILE


def load_specs(
    out_dir: Path, *, target_path: "Path | None" = None,
) -> list[TaintSpec]:
    """Load specs from the project-level store.

    When *target_path* is given, returns empty if the stored specs were
    written for a different target (prevents cross-target contamination).

    Returns an empty list on first run or if the store doesn't exist.
    """
    path = _store_path(out_dir)
    if not path.is_file():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        logger.debug("iris.store: failed to load %s", path, exc_info=True)
        return []
    if not isinstance(data, dict):
        return []
    if target_path is not None:
        stored_target = data.get("target_path", "")
        if stored_target and str(Path(stored_target).resolve()) != str(target_path.resolve()):
            logger.debug(
                "iris.store: skipping specs for different target (%s vs %s)",
                stored_target, target_path,
            )
            return []
    return _specs_from_list(data.get("specs", []))


def load_assumptions(
    out_dir: Path,
    *,
    target_path: "Path | None" = None,
) -> list[SafetyAssumption]:
    """Load safety assumptions from the project-level store."""
    path = _store_path(out_dir)
    if not path.is_file():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        logger.debug("iris.store: failed to load assumptions from %s", path, exc_info=True)
        return []
    if not isinstance(data, dict):
        return []
    if target_path is not None:
        stored_target = data.get("target_path", "")
        if stored_target and str(Path(stored_target).resolve()) != str(target_path.resolve()):
            logger.debug(
                "iris.store: skipping assumptions for different target (%s vs %s)",
                stored_target, target_path,
            )
            return []
    return assumptions_from_list(data.get("assumptions", []))


def load_store_metadata(out_dir: Path) -> dict[str, Any]:
    """Load the full store envelope (specs + metadata)."""
    path = _store_path(out_dir)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def save_specs(
    out_dir: Path,
    specs: list[TaintSpec],
    *,
    cl_sha: str = "",
    round_num: int = 0,
    history: list[dict[str, Any]] | None = None,
    target_path: "Path | None" = None,
    assumptions: list[SafetyAssumption] | None = None,
) -> Path:
    """Persist specs atomically to the project-level store.

    Uses tempfile + rename for crash safety (same pattern as
    ``core.audit.project_context``).
    """
    store_dir = _project_dir(out_dir) / _STORE_DIR
    store_dir.mkdir(parents=True, exist_ok=True)
    dest = store_dir / _STORE_FILE

    envelope = {
        "version": _SCHEMA_VERSION,
        "checklist_sha": cl_sha,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "round": round_num,
        "specs": [s.to_dict() for s in specs],
        "history": history or [],
        "assumptions": [a.to_dict() for a in assumptions] if assumptions else [],
    }
    if target_path is not None:
        envelope["target_path"] = str(target_path.resolve())

    fd, tmp = tempfile.mkstemp(
        dir=str(store_dir),
        prefix=".specs.tmp.",
        suffix=".json",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
        os.replace(tmp, str(dest))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise

    logger.info("iris.store: saved %d specs to %s", len(specs), dest)
    return dest


def load_refined_specs(out_dir: Path) -> list[TaintSpec]:
    """Load the run-local refined-spec artifact.

    ``iris-taint-specs-refined.json`` is written into the *run* output
    dir by the audit orchestrator after the refine loop.  Reading it
    back (resumed / re-entered runs, and as a prior-spec source next
    to the project store) preserves refinement continuity even when
    the project store is absent.  Evidence tiers round-trip: the
    artifact rows carry ``evidence_tier`` and ``_specs_from_list``
    restores them (unknown / missing tier degrades to heuristic, never
    upward).
    """
    path = Path(out_dir) / "iris-taint-specs-refined.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        logger.debug(
            "iris.store: failed to load refined artifact %s",
            path, exc_info=True,
        )
        return []
    if not isinstance(data, list):
        return []
    return _specs_from_list(data)


def persist_refined_specs(
    out_dir: Path,
    refined: list[TaintSpec],
    *,
    cl_sha: str = "",
    history: list[dict[str, Any]] | None = None,
    assumptions: list[SafetyAssumption] | None = None,
    target_path: "Path | None" = None,
) -> "Path | None":
    """Merge refine-loop output into the project store.

    The caller-persist step for ``refine_loop``: loads the existing
    store envelope, merges the refined specs in (higher evidence tier
    wins — ``merge_specs``), and saves with envelope metadata
    preserved:

    * prior ``history`` rounds are kept, new round records appended;
    * stored assumptions are merged (``merge_assumptions``);
    * ``checklist_sha`` / ``target_path`` are only replaced when the
      caller provides them.

    Cross-target guard: when the store belongs to a different target
    the merge is skipped (returns ``None``) rather than contaminating
    another project's specs.

    Safe to call before the suppression-direction readers because
    those are tier-gated (``core.iris.api.SUPPRESSION_MIN_TIER``):
    a heuristic-tier refined sanitiser lands in the store as prompt
    context only and cannot flow into suppression.
    """
    if not refined:
        return None
    meta = load_store_metadata(out_dir)
    stored_target = meta.get("target_path", "")
    if (
        target_path is not None
        and stored_target
        and str(Path(stored_target).resolve()) != str(Path(target_path).resolve())
    ):
        logger.debug(
            "iris.store: refusing refined-spec merge into store for "
            "different target (%s vs %s)", stored_target, target_path,
        )
        return None

    existing = _specs_from_list(meta.get("specs", []))
    merged = merge_specs(existing, refined)

    # Drop refuted specs at merge. The refine loop demotes refuted
    # specs in-run, but the merge above is add/upgrade-only — store
    # copies of refuted specs used to resurrect as prior_specs on the
    # next run, polluting prompts and burning tool cycles forever.
    # Same floor as refine's _demote_refuted: tool-confirmed
    # (>= XREF_BACKED) and operator-confirmed specs survive a
    # refuted round; a later confirmation clears the refutation.
    merged = _drop_refuted(merged, history or [])

    prior_history = [
        h for h in (meta.get("history") or []) if isinstance(h, dict)
    ]
    new_history = prior_history + [
        h for h in (history or []) if isinstance(h, dict)
    ]

    from .assumptions import merge_assumptions

    existing_assumptions = assumptions_from_list(meta.get("assumptions", []))
    merged_assumptions = merge_assumptions(
        existing_assumptions, list(assumptions or []),
    )

    try:
        prior_round = int(meta.get("round", 0) or 0)
    except (TypeError, ValueError):
        prior_round = 0

    resolved_target: Path | None = None
    if target_path is not None:
        resolved_target = Path(target_path)
    elif stored_target:
        resolved_target = Path(stored_target)

    # Evict specs whose file vanished from the target tree. Like the
    # refuted drop above this used to exist with zero persistence-path
    # callers, so deleted-file specs accumulated in the store
    # indefinitely. Existence-derived file set: cheap (one stat per
    # distinct spec file) and exactly what evict_stale needs.
    if resolved_target is not None and resolved_target.is_dir():
        current_files = {
            s.file for s in merged
            if s.file and (resolved_target / s.file).is_file()
        }
        merged = evict_stale(merged, current_files)

    return save_specs(
        out_dir,
        merged,
        cl_sha=cl_sha or meta.get("checklist_sha", ""),
        round_num=prior_round + len(history or []),
        history=new_history,
        target_path=resolved_target,
        assumptions=merged_assumptions or None,
    )


def _drop_refuted(
    specs: list[TaintSpec],
    history: list[dict[str, Any]],
) -> list[TaintSpec]:
    """Remove specs the refine rounds refuted (net of re-confirmation).

    ``history`` rows are RoundRecord dicts for THIS persist call, in
    round order; a key refuted in one round but confirmed in a later
    one is not dropped. Tool-confirmed (>= XREF_BACKED) and
    operator-confirmed specs are always kept — mirroring
    ``core.iris.refine._demote_refuted``'s floor.
    """
    refuted: set = set()
    for rec in history:
        if not isinstance(rec, dict):
            continue
        refuted.update(
            k for k in (rec.get("refuted_keys") or []) if isinstance(k, str)
        )
        refuted.difference_update(
            k for k in (rec.get("confirmed_keys") or []) if isinstance(k, str)
        )
    if not refuted:
        return specs
    kept: list[TaintSpec] = []
    dropped = 0
    for spec in specs:
        if (
            _spec_key(spec) in refuted
            and spec.source != "operator_confirmed"
            and TIER_RANK.get(spec.evidence_tier, 0)
                < TIER_RANK.get(EvidenceTier.XREF_BACKED, 0)
        ):
            dropped += 1
            continue
        kept.append(spec)
    if dropped:
        logger.info(
            "iris.store: dropped %d refuted spec(s) at merge", dropped,
        )
    return kept


def merge_specs(
    existing: list[TaintSpec],
    new: list[TaintSpec],
) -> list[TaintSpec]:
    """Merge new specs into existing, deduplicating by (function, file, role).

    On conflict, the spec with the higher evidence tier wins.  If tiers
    are equal, the new spec wins (fresher data) — unless the existing
    spec is operator-confirmed (``source == "operator_confirmed"``),
    which stays sticky on equal-tier merges.
    """
    by_key: dict[str, TaintSpec] = {}
    for spec in existing:
        by_key[_spec_key(spec)] = spec

    for spec in new:
        key = _spec_key(spec)
        old = by_key.get(key)
        if old is None:
            by_key[key] = spec
        else:
            winner_tier = stronger(old.evidence_tier, spec.evidence_tier)
            if winner_tier != old.evidence_tier or (winner_tier == spec.evidence_tier
                  and old.source != "operator_confirmed"):
                by_key[key] = spec
    return list(by_key.values())


def evict_stale(
    specs: list[TaintSpec],
    current_files: set[str],
    *,
    keep_above: EvidenceTier = EvidenceTier.XREF_BACKED,
) -> list[TaintSpec]:
    """Remove specs for files no longer in the project.

    Specs with ``evidence_tier >= keep_above`` are retained even if
    their file is gone — they may have been confirmed by a tool and
    the file rename might be a refactor, not a deletion.
    """
    kept = []
    evicted = 0
    for spec in specs:
        if (spec.file and spec.file in current_files) or TIER_RANK.get(spec.evidence_tier, 0) >= TIER_RANK.get(keep_above, 0):
            kept.append(spec)
        else:
            evicted += 1
    if evicted:
        logger.info("iris.store: evicted %d stale specs", evicted)
    return kept
