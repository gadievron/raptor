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
from dataclasses import dataclass
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
    """Summary of one synthesis/refinement round."""

    round: int
    n_specs: int
    n_confirmed: int = 0
    n_refuted: int = 0
    n_errors: int = 0
    n_bypass: int = 0


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


def merge_specs(
    existing: list[TaintSpec],
    new: list[TaintSpec],
) -> list[TaintSpec]:
    """Merge new specs into existing, deduplicating by (function, file, role).

    On conflict, the spec with the higher evidence tier wins.  If tiers
    are equal, the new spec wins (fresher data).
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
