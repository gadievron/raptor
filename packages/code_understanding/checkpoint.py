"""Per-model checkpoints for /understand --hunt / --trace.

The multi-model dispatch fans one task out to N models; before this
module, results lived only in memory until the final
``<mode>-result.json`` write, so an interruption at model N-1 of N
re-spent every completed model from zero. The checkpoint store
persists each model's finished result — atomically, as produced — so
``libexec/raptor-understand --resume <run-dir>`` re-enters the run,
returns the checkpointed models' items at $0 new spend (their
recorded cost is carried into the resumed run's continuous
accounting) and dispatches only the remainder.

Layout: ``<out>/understand-checkpoints/<slug>.json``, one file per
model, written by the dispatch wrapper's worker thread (distinct
files, atomic tempfile+rename each — no cross-thread interleaving).
Each checkpoint records the task fingerprint (mode + operator
pattern / pinned traces + target) so a checkpoint from a different
task, target, or mode can never be replayed into a resume, plus
whole-file hashes of the target files its items reference so the
substrate drift gate (:func:`core.run.resume.spans_drift`) can refuse
a resume against a changed tree.

The run-config pin (``understand-run-config.json``) and the
incremental spend floor ride the shared substrate
(:mod:`core.run.resume`).
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.json.utils import load_json, save_json
from core.run.resume import (
    SpanDriftRecord,
    _safe_target_join,
    _spend_value,
    hash_whole_file,
    load_run_config,
    persist_spend_floor,
    save_run_config,
)

logger = logging.getLogger(__name__)

RUN_CONFIG_FILENAME = "understand-run-config.json"
CHECKPOINT_DIRNAME = "understand-checkpoints"
TRACES_PIN_FILENAME = "understand-traces-pin.json"

# Byte budget for reading a checkpoint back. Hunt/trace item lists are
# bounded by the same ceiling the shim grants operator traces files.
_CHECKPOINT_MAX_BYTES = 64 * 1024 * 1024

# Cap on the number of item-referenced files hashed per checkpoint —
# item ``file`` fields are LLM output over a hostile tree, so the
# drift evidence must stay bounded work. Deterministic (sorted) so
# save and resume agree on which files carry evidence.
_MAX_DRIFT_FILES = 200

_CHECKPOINT_VERSION = 1


def task_fingerprint(mode: str, task_key: str, target: Path) -> str:
    """Identity of the work a checkpoint belongs to.

    ``task_key`` is the operator's hunt pattern, or the SHA-256 of the
    pinned traces content for --trace. Graph-seed enrichment is
    deliberately OUTSIDE the fingerprint: seeds are informational
    context that varies across segments by design, not task identity.
    """
    payload = "\0".join((mode, task_key, str(Path(target).resolve())))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def traces_task_key(traces: list[dict[str, Any]]) -> str:
    """Canonical content key for a trace task (sorted-key JSON SHA)."""
    from core.json import dumps_canonical
    canonical = dumps_canonical(traces)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def save_understand_run_config(
    out_dir: Path, config: dict[str, Any],
) -> Path:
    """Pin the run's resolved options (see substrate docstring)."""
    return save_run_config(out_dir, config, filename=RUN_CONFIG_FILENAME)


def load_understand_run_config(out_dir: Path) -> dict[str, Any] | None:
    """The pinned options, ``None`` when absent/corrupt/oversize."""
    return load_run_config(out_dir, filename=RUN_CONFIG_FILENAME)


@dataclass
class Checkpoint:
    """One model's persisted result."""

    model: str
    items: list[dict[str, Any]]
    cost_usd: float
    file_hashes: dict[str, str] = field(default_factory=dict)


def _model_slug(model_name: str) -> str:
    """Filesystem-safe per-model filename stem.

    Sanitisation can collide (``a/b`` vs ``a:b``), so a short digest
    of the exact name disambiguates.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", model_name)[:80] or "model"
    digest = hashlib.sha256(model_name.encode("utf-8")).hexdigest()[:8]
    return f"{safe}-{digest}"


class CheckpointStore:
    """Read/write per-model checkpoints for one run directory.

    ``save`` may be called concurrently from dispatch worker threads —
    each model writes its own file atomically, and the shared spend-
    floor bump is serialised by an in-process lock (the substrate's
    read-compare-write is single-writer by contract).
    """

    def __init__(
        self,
        out_dir: Path,
        *,
        mode: str,
        fingerprint: str,
        target: Path,
    ) -> None:
        self.out_dir = Path(out_dir)
        self.mode = mode
        self.fingerprint = fingerprint
        self.target = Path(target)
        self._dir = self.out_dir / CHECKPOINT_DIRNAME
        self._floor_lock = threading.Lock()
        self._segment: int | None = None

    # -- write path ---------------------------------------------------

    def save(
        self, model_name: str, items: list[dict[str, Any]],
        cost_usd: float,
    ) -> None:
        """Persist one model's finished result. Best-effort: a
        checkpoint failure costs resumability for that model, never
        the run."""
        try:
            file_hashes = self._hash_item_files(items)
            payload: dict[str, Any] = {
                "version": _CHECKPOINT_VERSION,
                "mode": self.mode,
                "fingerprint": self.fingerprint,
                "model": model_name,
                "items": items,
                "cost_usd": round(max(0.0, float(cost_usd)), 6),
                "file_hashes": file_hashes,
            }
            self._dir.mkdir(parents=True, exist_ok=True)
            save_json(self._dir / f"{_model_slug(model_name)}.json", payload)
        except Exception:
            logger.warning(
                "checkpoint persist failed for model %r — this model "
                "will re-run on resume", model_name, exc_info=True,
            )

    def bump_spend_floor(self, whole_run_spend_usd: float) -> None:
        """Raise the run's incremental spend floor (monotonic)."""
        with self._floor_lock:
            try:
                persist_spend_floor(
                    self.out_dir, whole_run_spend_usd,
                    segment=self._segment,
                )
            except Exception:
                logger.debug("spend floor bump failed", exc_info=True)

    def set_segment(self, segment: int | None) -> None:
        """Stamp subsequent floor bumps with the resume segment."""
        self._segment = segment

    def _hash_item_files(
        self, items: list[dict[str, Any]],
    ) -> dict[str, str]:
        """Whole-file drift evidence for the files the items reference.

        Item ``file`` fields are model output — treated as untrusted
        relative paths, confined under the target by the substrate's
        join at verify time. Unresolvable/unreadable files hash to
        ``""`` on both sides, so they carry no false drift.
        """
        rels: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            rel = item.get("file")
            if not isinstance(rel, str) or not rel:
                continue
            rel = self._relativise(rel)
            if rel is not None:
                rels.add(rel)
        hashes: dict[str, str] = {}
        for rel in sorted(rels)[:_MAX_DRIFT_FILES]:
            resolved = _safe_target_join(self.target, rel)
            hashes[rel] = (
                hash_whole_file(resolved)
                if resolved is not None and resolved.is_file() else ""
            )
        return hashes

    def _relativise(self, raw: str) -> str | None:
        """Normalise an item path to target-relative, or ``None``."""
        if "\x00" in raw:
            return None
        p = Path(raw)
        if p.is_absolute():
            try:
                return p.resolve().relative_to(
                    self.target.resolve()).as_posix()
            except (ValueError, OSError):
                return None
        return raw

    # -- read path ----------------------------------------------------

    def load(self, model_name: str) -> Checkpoint | None:
        """One model's checkpoint, validated against this store's
        mode/fingerprint. ``None`` when absent, corrupt, oversize, or
        belonging to a different task."""
        path = self._dir / f"{_model_slug(model_name)}.json"
        if not path.is_file():
            return None
        try:
            data = load_json(
                path, strict=True, max_bytes=_CHECKPOINT_MAX_BYTES,
            )
        except (OSError, ValueError):
            logger.warning("unreadable checkpoint %s", path, exc_info=True)
            return None
        return self._validate(data, model_name)

    def _validate(
        self, data: Any, model_name: str,
    ) -> Checkpoint | None:
        if not isinstance(data, dict):
            return None
        if data.get("version") != _CHECKPOINT_VERSION:
            return None
        if data.get("mode") != self.mode:
            return None
        if data.get("fingerprint") != self.fingerprint:
            return None
        if data.get("model") != model_name:
            return None
        items = data.get("items")
        if not isinstance(items, list) or not all(
            isinstance(i, dict) for i in items
        ):
            return None
        cost = _spend_value(data.get("cost_usd"))
        raw_hashes = data.get("file_hashes")
        file_hashes = {
            k: v for k, v in raw_hashes.items()
            if isinstance(k, str) and isinstance(v, str)
        } if isinstance(raw_hashes, dict) else {}
        return Checkpoint(
            model=model_name,
            items=items,
            cost_usd=0.0 if cost is None else cost,
            file_hashes=file_hashes,
        )

    def load_all(self, model_names: list[str]) -> dict[str, Checkpoint]:
        """Valid checkpoints for the given models, keyed by name."""
        found: dict[str, Checkpoint] = {}
        for name in model_names:
            ckpt = self.load(name)
            if ckpt is not None:
                found[name] = ckpt
        return found

    def drift_records(
        self, checkpoints: dict[str, Checkpoint],
    ) -> list[SpanDriftRecord]:
        """Whole-file drift records across the given checkpoints.

        One record per (file, model) with a non-empty stored hash —
        the substrate skips unverifiable (empty-hash) evidence, and
        equal hashes across models dedupe naturally at the verify
        step's per-file read.
        """
        seen: set[tuple[str, str]] = set()
        records: list[SpanDriftRecord] = []
        for name in sorted(checkpoints):
            for rel, stored in sorted(
                checkpoints[name].file_hashes.items()
            ):
                if not stored or (rel, stored) in seen:
                    continue
                seen.add((rel, stored))
                records.append(SpanDriftRecord(
                    file=rel,
                    label=name,
                    stored_hash=stored,
                ))
        return records
