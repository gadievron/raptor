"""Durable cross-segment checkpoint for memoized coccinelle sweeps.

The per-run :class:`~core.audit.sweep_memo.SweepMemo` dies with its
process, so a drained-and-resumed run re-pays every (rule, file)
spatch invocation the previous segment already completed. This module
persists the memo's coccinelle entries under the RUN DIRECTORY as an
append-only JSONL trail (``sweep-checkpoint.jsonl``) so a resumed
segment serves them from disk instead of re-spawning spatch.

Soundness contract (inherits the memo's, plus durability rules):

* Keys are the memo keys — CONTENT digests of the steering inputs
  (rendered rule bytes, target file bytes) plus plain scoping scalars
  (relative path, defines rendering). A changed rule or changed file
  produces a different key, so the stale record is simply never hit
  and the sweep re-runs. Nothing here trusts paths or mtimes.
* Only tools in :data:`CHECKPOINTABLE_TOOLS` persist. The coccinelle
  file sweep is a pure function of (rule bytes, file bytes, defines);
  the other memoizable step types carry inputs whose identity is only
  pinned per-process (CodeQL database rows, SMT verb vocabularies) and
  stay memo-only.
* ``error`` outcomes and results whose negative-control leg errored
  are never persisted — the same refusals as ``SweepMemo.put``, for
  the same reasons, made durable they would be strictly worse.
* Fail-open direction is fixed: a corrupt, unreadable, oversize, or
  version-mismatched checkpoint WARNS ONCE and loads NOTHING — the
  run recomputes every sweep (correct, just slower). No failure mode
  may cause a sweep to be SKIPPED on bad data. A corrupt trail is
  additionally rotated aside (``.corrupt`` suffix) so the segment's
  fresh records start a clean file and the next resume is not poisoned
  by the same bytes.
* Writes are concurrent-writer safe by construction: every record is
  one fully-formed line appended via ``core.json.append_jsonl``
  (O_APPEND + single ``os.write`` — line-atomic for these record
  sizes, O_NOFOLLOW against planted symlinks). There is no
  read-modify-write of shared file state, so parallel workers — and a
  future cross-file worker pool on the primary pass — compose with
  this trail unchanged.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import stat as _stat
import threading
from pathlib import Path
from typing import Any

from .sweep import SweepResult
from .sweep_memo import SweepMemo

logger = logging.getLogger(__name__)

CHECKPOINT_FILENAME = "sweep-checkpoint.jsonl"

#: Record schema version. Any mismatch invalidates the WHOLE trail
#: (fail-open to recompute) — bump on any shape change.
CHECKPOINT_VERSION = 1

#: Step types whose memoized results are durable. Deliberately only
#: coccinelle: its file sweep is a pure function of content-digested
#: inputs (see module docstring). Extending this set is the seam for
#: future step types — each addition must justify cross-process
#: result identity the way the memo docstring does per-run identity.
CHECKPOINTABLE_TOOLS: frozenset[str] = frozenset({"coccinelle"})

# One serialized record (key + full SweepResult payload + newline).
# Not lower: a confirmed sweep on a match-dense file legitimately
# carries hundreds of match dicts (~100-300 bytes each) and those hot
# files are exactly the ones worth not re-sweeping on resume — a
# small cap would evict the most valuable records. Not higher: the
# single-write O_APPEND line-atomicity concurrent writers rely on is
# only dependable for modest write sizes, and oversize outliers are
# cheaper to recompute than to carry in every future segment's load.
MAX_RECORD_BYTES = 64 * 1024

# Whole-trail size gate checked before load. Not lower: a kernel-scale
# run accumulates hundreds of thousands of small (rule, file) records
# across segments (~250 bytes typical), and refusing a legitimate
# ~100 MiB trail would throw away exactly the multi-hour sweep state
# this file exists to keep. Not higher: the trail is parsed and held
# in memory at segment start, so an unbounded (or hostile) file would
# stall resume and balloon the orchestrator's baseline RSS before any
# work starts.
MAX_CHECKPOINT_BYTES = 256 * 1024 * 1024

#: Outcomes a persisted result may carry. ``error`` is refused at
#: record time (mirrors ``SweepMemo.put``); anything else on load is
#: corruption.
_VALID_OUTCOMES: frozenset[str] = frozenset({
    "confirmed", "refuted", "inconclusive", "skipped",
})

_RESULT_FIELDS: tuple[str, ...] = (
    "tool", "file_path", "function_name", "outcome", "matches",
    "errors", "rule_id", "raw_output", "details",
)

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def tool_checkpointable(tool: str) -> bool:
    """Whether *tool*'s memoized sweep results are durable."""
    return tool in CHECKPOINTABLE_TOOLS


def _key_to_parts(key: tuple) -> tuple[str, dict[str, str | int]] | None:
    """(tool, parts-dict) for a memo key, or None when unserialisable.

    Memo keys are ``(tool, ((name, value), ...))`` with str/int values
    (see ``SweepMemo.make_key``). Anything else is refused — the
    checkpoint never guesses at a key shape it cannot round-trip.
    """
    if (
        not isinstance(key, tuple) or len(key) != 2
        or not isinstance(key[0], str) or not isinstance(key[1], tuple)
    ):
        return None
    parts: dict[str, str | int] = {}
    for item in key[1]:
        if not (isinstance(item, tuple) and len(item) == 2):
            return None
        name, value = item
        if not isinstance(name, str):
            return None
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return None
        parts[name] = value
    return key[0], parts


def _valid_parts(parts: Any) -> bool:
    if not isinstance(parts, dict) or not parts:
        return False
    for name, value in parts.items():
        if not isinstance(name, str):
            return False
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return False
    return True


def _valid_result_payload(payload: Any) -> bool:
    """Strict schema check for a persisted SweepResult payload."""
    if not isinstance(payload, dict):
        return False
    if set(payload) - set(_RESULT_FIELDS):
        return False
    for field in ("tool", "file_path", "function_name", "outcome"):
        if not isinstance(payload.get(field), str):
            return False
    if payload["outcome"] not in _VALID_OUTCOMES:
        return False
    matches = payload.get("matches", [])
    if not isinstance(matches, list) or any(
        not isinstance(m, dict) for m in matches
    ):
        return False
    errors = payload.get("errors", [])
    if not isinstance(errors, list) or any(
        not isinstance(e, str) for e in errors
    ):
        return False
    for optional in ("rule_id", "raw_output"):
        if payload.get(optional) is not None and not isinstance(
            payload[optional], str,
        ):
            return False
    if payload.get("details") is not None and not isinstance(
        payload["details"], dict,
    ):
        return False
    return True


def _key_digest(tool: str, parts: dict[str, str | int]) -> bytes:
    canonical = json.dumps(
        {"tool": tool, "parts": parts}, sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).digest()


class SweepCheckpoint:
    """Append-only durable layer under one run directory.

    Thread-safe. Never raises out of ``lookup``/``record`` — every
    failure degrades to "recompute" with at most one warning per
    failure class.
    """

    def __init__(
        self,
        run_dir: Path,
        *,
        max_record_bytes: int = MAX_RECORD_BYTES,
        max_total_bytes: int = MAX_CHECKPOINT_BYTES,
    ) -> None:
        self._path = Path(run_dir) / CHECKPOINT_FILENAME
        self._max_record_bytes = max_record_bytes
        self._max_total_bytes = max_total_bytes
        self._lock = threading.Lock()
        self._write_failed = False
        # (tool, sorted-parts tuple) memo key -> raw result payload.
        # Read-only after __init__: records written THIS segment are
        # served by the in-process SweepMemo; this dict only replays
        # PRIOR segments, so it never grows during the run.
        self._loaded: dict[tuple, dict[str, Any]] = {}
        # Digests of keys already on disk (loaded or written here) —
        # dedup so a resumed segment does not re-append every replayed
        # record.
        self._persisted: set[bytes] = set()
        self.replayed = 0
        self.recorded = 0
        self._load()

    # ── load side ────────────────────────────────────────────────────

    def _invalidate(self, reason: str) -> None:
        """WARN once, drop everything loaded, rotate the bad trail.

        Fail-open direction: recompute, never skip. Rotation (rename to
        ``.corrupt``) keeps the evidence and lets this segment start a
        clean trail so the NEXT resume is not re-poisoned.
        """
        self._loaded.clear()
        self._persisted.clear()
        logger.warning(
            "sweep checkpoint %s is unusable (%s) — ignoring it and "
            "re-sweeping everything (fail-open to recompute)",
            self._path, reason,
        )
        try:
            os.replace(self._path, str(self._path) + ".corrupt")
        except OSError:
            logger.debug(
                "sweep checkpoint rotation failed", exc_info=True,
            )

    def _load(self) -> None:
        try:
            fd = os.open(
                str(self._path), os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC,
            )
        except FileNotFoundError:
            return
        except OSError as exc:
            self._invalidate(f"unreadable: {exc.__class__.__name__}")
            return
        try:
            st = os.fstat(fd)
            if not _stat.S_ISREG(st.st_mode):
                os.close(fd)
                self._invalidate("not a regular file")
                return
            if st.st_size > self._max_total_bytes:
                os.close(fd)
                self._invalidate(
                    f"{st.st_size} bytes exceeds the "
                    f"{self._max_total_bytes}-byte load bound",
                )
                return
            with os.fdopen(fd, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self._invalidate(f"read failed: {exc.__class__.__name__}")
            return
        for line in data.split(b"\n"):
            if not line.strip():
                continue
            if len(line) > self._max_record_bytes:
                self._invalidate("record over the per-record byte bound")
                return
            try:
                rec = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                self._invalidate("malformed record line")
                return
            if not self._ingest(rec):
                self._invalidate("record failed schema validation")
                return

    def _ingest(self, rec: Any) -> bool:
        """Fold one parsed record into the loaded map. False = invalid."""
        if not isinstance(rec, dict):
            return False
        if rec.get("v") != CHECKPOINT_VERSION:
            return False
        tool = rec.get("tool")
        parts = rec.get("parts")
        payload = rec.get("result")
        if not isinstance(tool, str) or tool not in CHECKPOINTABLE_TOOLS:
            return False
        if not _valid_parts(parts) or not _valid_result_payload(payload):
            return False
        key = SweepMemo.make_key(tool, parts)
        if key is None:
            return False
        # Duplicate keys are legitimate (concurrent first dispatches
        # both persisting) — last record wins, like the memo's store.
        self._loaded[key] = payload
        self._persisted.add(_key_digest(tool, parts))
        return True

    # ── read side ────────────────────────────────────────────────────

    def lookup(self, key: tuple) -> SweepResult | None:
        """A fresh SweepResult replayed from a PRIOR segment, or None.

        Each call deep-copies the stored payload so no two consumers
        (nor the checkpoint itself) share mutable match/detail dicts.
        """
        payload = self._loaded.get(key)
        if payload is None:
            return None
        payload = copy.deepcopy(payload)
        self.replayed += 1
        return SweepResult(
            tool=payload["tool"],
            file_path=payload["file_path"],
            function_name=payload["function_name"],
            outcome=payload["outcome"],
            matches=payload.get("matches", []),
            errors=payload.get("errors", []),
            rule_id=payload.get("rule_id"),
            raw_output=payload.get("raw_output"),
            details=payload.get("details"),
        )

    # ── write side ───────────────────────────────────────────────────

    def record(self, key: tuple, result: Any) -> None:
        """Persist one completed sweep unit (best-effort).

        Refuses exactly what ``SweepMemo.put`` refuses (error
        outcomes, errored negative controls) plus everything the
        durable layer cannot round-trip (non-SweepResult objects,
        non-JSON payloads, oversize records). A refusal only means
        the unit recomputes after the next drain — never that it is
        skipped.

        The key's digest dimensions are content hashes minted at the
        dispatch site (``_memoized_sweep_step``'s coccinelle leg):
        ``rule`` = sha256 of the RENDERED rule bytes, ``file`` =
        sha256 of the target file bytes — chosen over mtime+size
        because both hashes are already computed for the in-process
        memo key, so durability costs no extra I/O and inherits the
        memo's exact invalidation semantics (changed rule or changed
        file ⇒ new key ⇒ re-sweep).
        """
        if self._write_failed or not isinstance(result, SweepResult):
            return
        if result.outcome == "error" or result.outcome not in _VALID_OUTCOMES:
            return
        if isinstance(result.details, dict) and result.details.get(
            "negative_control_error",
        ):
            return
        serial = _key_to_parts(key)
        if serial is None:
            return
        tool, parts = serial
        if tool not in CHECKPOINTABLE_TOOLS:
            return
        digest = _key_digest(tool, parts)
        with self._lock:
            if digest in self._persisted:
                return
            self._persisted.add(digest)
        rec = {
            "v": CHECKPOINT_VERSION,
            "tool": tool,
            "parts": parts,
            "result": {
                "tool": result.tool,
                "file_path": result.file_path,
                "function_name": result.function_name,
                "outcome": result.outcome,
                "matches": result.matches,
                "errors": result.errors,
                "rule_id": result.rule_id,
                "raw_output": result.raw_output,
                "details": result.details,
            },
        }
        try:
            line = json.dumps(
                rec, separators=(",", ":"), allow_nan=False,
            )
        except (TypeError, ValueError):
            # This one result is not round-trippable — skip it alone.
            logger.debug(
                "sweep checkpoint: unserialisable result skipped",
                exc_info=True,
            )
            return
        # +1 for the newline append_jsonl adds.
        if len(line.encode("utf-8")) + 1 > self._max_record_bytes:
            logger.debug(
                "sweep checkpoint: oversize record skipped (%d bytes)",
                len(line),
            )
            return
        try:
            from core.json import append_jsonl
            append_jsonl(self._path, rec, compact=True)
        except (OSError, TypeError, ValueError):
            self._write_failed = True
            logger.warning(
                "sweep checkpoint append to %s failed — durable sweep "
                "state disabled for the rest of this segment (the run "
                "continues; a resume re-sweeps what was not persisted)",
                self._path, exc_info=True,
            )
            return
        self.recorded += 1


# ── per-run-dir registry ──────────────────────────────────────────────
# One checkpoint object per run directory per process: the dispatch
# seam (orchestrator._memoized_sweep_step) resolves it lazily so the
# trail loads exactly once, and every worker thread shares the same
# dedup/write state. Values may be None (permanently disabled for the
# dir after a constructor-level failure). Bounded by the number of
# distinct run dirs one process serves — one, in practice.
_registry: dict[str, SweepCheckpoint | None] = {}
_registry_lock = threading.Lock()


def checkpoint_for_run(out_dir: Any) -> SweepCheckpoint | None:
    """The run directory's checkpoint, or None when unavailable."""
    if not out_dir:
        return None
    key = str(out_dir)
    with _registry_lock:
        if key in _registry:
            return _registry[key]
        try:
            cp: SweepCheckpoint | None = SweepCheckpoint(Path(out_dir))
        except Exception:  # noqa: BLE001 — durability is optional
            logger.warning(
                "sweep checkpoint unavailable for %s — sweeps will "
                "not persist across a drain/resume", out_dir,
                exc_info=True,
            )
            cp = None
        _registry[key] = cp
    return cp


def reset_checkpoint_registry() -> None:
    """Drop all cached checkpoints (tests / in-process embedders)."""
    with _registry_lock:
        _registry.clear()
