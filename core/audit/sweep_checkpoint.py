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
  by the same bytes. The load open is ``O_NOFOLLOW | O_NONBLOCK`` with
  a post-open regularity check, so a planted symlink or FIFO at the
  trail path is refused into the same rotation — never followed,
  never blocks the loader (which runs under the registry lock).
* Writes are concurrent-writer safe by construction: every record is
  one fully-formed line appended via ``core.json.append_jsonl``
  (O_APPEND + single ``os.write`` — line-atomic for these record
  sizes, O_NOFOLLOW against planted symlinks). There is no
  read-modify-write of shared file state, so parallel workers — and a
  future cross-file worker pool on the primary pass — compose with
  this trail unchanged.
* Records are AUTHENTICATED. The trail lives in the run directory —
  target-writable during runs — and a replayed record steers tool
  verdicts: a forged ``refuted`` record suppresses a real
  confirmation, a forged ``confirmed`` record mints a tool receipt
  with spatch never having run. The content digests in the key
  authenticate WHAT was swept, not WHO recorded the result — they
  are computable from world-readable inputs. So every appended
  record carries an HMAC-SHA256 token (``integrity`` field) over the
  record's canonical JSON under a per-purpose 32-byte key
  (``$XDG_DATA_HOME/raptor/sweep-checkpoint-mac.key``, the shared
  ``core.security.mac_key`` discipline), domain-separated
  (``sweep-checkpoint-record``) and RUN-BOUND: the MAC message
  includes the run dir's resolved path, so a trail replanted from
  another run's directory fails verification — the same posture as
  the audit-log lane in ``core/coverage/journal_mac.py``. Load
  adopts ONLY verified records; tampered and unstamped records are
  skipped (recompute, never adopt) with one warning carrying
  verified/tampered/unstamped counts. There is no unstamped legacy
  tier: this file format has never existed without record tokens,
  so unstamped means forged-or-foreign, never "old" (no era fence
  needed). A missing or unusable key disables the checkpoint — warn
  once, recompute everything, never crash, never adopt an
  unverified record.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import os
import stat as _stat
import threading
from pathlib import Path
from typing import Any

from core.json.utils import dumps_canonical
from core.security import mac_key

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
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

#: Record field carrying the per-record HMAC token (the review
#: journal's ``TOKEN_KEY`` convention). Excluded from the canonical
#: payload before hashing so the token covers everything else.
TOKEN_KEY = "integrity"

_MAC_KEY_LEN = 32

# Domain separation, per the house per-purpose-key doctrine
# (core/security/mac_key.py, core/coverage/journal_mac.py): this
# trail has its OWN key file and its OWN domain prefix — never the
# journal/checklist keys or domains — so a token minted for another
# artifact class can never verify here even if a key were ever shared
# by mistake, and deleting this key resets only this trail's trust
# surface.
_MAC_DOMAIN = b"sweep-checkpoint-record\x00"

_key_warned: set[str] = set()


def _mac_key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "sweep-checkpoint-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _key_warned:
        logger.debug(
            "sweep checkpoint: suspect MAC key %s (%s)", path, reason,
        )
        return
    _key_warned.add(key)
    logger.warning(
        "sweep checkpoint: refusing MAC key %s — %s. Durable sweep "
        "state is disabled (every sweep recomputes; nothing "
        "unauthenticated is ever adopted) until this is fixed: %s",
        path, reason, remedy,
    )


def _usable_mac_key() -> bytes | None:
    """The per-purpose 32-byte key, lazily created (0700 dir, 0600
    file, ``O_EXCL``) via the shared hardened discipline
    (:func:`core.security.mac_key.load_or_create_key`). ``None`` on
    ANY failure — an existing-but-unusable key file, an unwritable
    data dir — the caller then disables the checkpoint rather than
    crash the run or persist/adopt unauthenticated records."""
    try:
        return mac_key.load_or_create_key(
            _mac_key_path(), key_len=_MAC_KEY_LEN,
            warn=_warn_once_suspect_key,
            recreate_hint="a fresh key is created on the next record",
        )
    except OSError:
        return None


def _run_binding(run_dir: Path) -> str:
    """The run identity bound into record tokens: the run dir's
    resolved path, derived by the consumer from its OWN directory —
    never stored in a record or read from a run-dir artifact (an
    attacker holding the run-dir write grant could plant any STORED
    identity next to a replanted trail; the consumer's own directory
    cannot be forged from inside it). Same derivation rationale as
    the audit-log lane in ``core/coverage/journal_mac.py``."""
    try:
        return str(Path(run_dir).resolve())
    except OSError:
        return str(run_dir)


def _mac_message(rec: dict[str, Any], run_binding: str) -> bytes:
    """Domain prefix + run binding + sha256 hex of the record's
    canonical JSON (token key excluded). The token therefore covers
    the WHOLE record — version, tool, the memo key parts (the
    rule/file content digests), the full result payload — plus WHERE
    it lives: a validly-stamped record replayed under another run
    dir fails verification."""
    scrubbed = {k: v for k, v in rec.items() if k != TOKEN_KEY}
    payload_hex = hashlib.sha256(
        dumps_canonical(scrubbed).encode("utf-8"),
    ).hexdigest()
    return (
        _MAC_DOMAIN
        + run_binding.encode("utf-8", "surrogatepass") + b"\x00"
        + payload_hex.encode("ascii")
    )


def _mint_token(
    key: bytes, rec: dict[str, Any], run_binding: str,
) -> str:
    return hmac.new(
        key, _mac_message(rec, run_binding), hashlib.sha256,
    ).hexdigest()


def _verify_token(
    key: bytes, rec: dict[str, Any], token: Any, run_binding: str,
) -> bool:
    """Constant-time; never raises — any failure is the caller's
    skip-and-recompute path, never an error."""
    if not token or not isinstance(token, str):
        return False
    try:
        return hmac.compare_digest(
            _mint_token(key, rec, run_binding), token.strip().lower(),
        )
    except Exception:  # noqa: BLE001 — verification failure is the skip path
        return False


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
    # dumps_canonical is the one blessed serializer for hash lanes
    # (byte-identical to the previous inline sort_keys/compact form
    # for these str/int payloads).
    canonical = dumps_canonical({"tool": tool, "parts": parts})
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
        self._run_binding = _run_binding(Path(run_dir))
        # Per-record authentication (see the module docstring): the
        # trail sits in the target-writable run dir and its records
        # steer tool verdicts, so nothing is persisted or adopted
        # without a token under the per-purpose key. No usable key ⇒
        # the whole checkpoint is DISABLED for this instance: warn
        # once, recompute every sweep, never crash the run, never
        # fall back to adopting (or writing) unauthenticated records.
        self._disabled = False
        self._mac_key: bytes | None = _usable_mac_key()
        if self._mac_key is None:
            self._disabled = True
            logger.warning(
                "sweep checkpoint MAC key unavailable — durable sweep "
                "state disabled for %s (every sweep recomputes; "
                "unauthenticated records are never adopted)",
                self._path,
            )
            return
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
            # O_NONBLOCK: the trail path lives in a run dir a sandboxed
            # child holds (or held) write on, and an O_RDONLY open of a
            # planted reader-less FIFO otherwise blocks forever — while
            # this constructor runs under the registry lock, wedging
            # every sweep worker behind it. With the flag the FIFO
            # opens immediately and the post-open regularity check
            # below rejects it into the corrupt-trail rotation (the
            # same two-part defence as ``core.json.append_jsonl``'s
            # write side; both flags are no-ops for the regular file
            # every legitimate trail is).
            fd = os.open(
                str(self._path),
                os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK,
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
        key = self._mac_key
        if key is None:  # defensive: __init__ never loads while disabled
            return
        verified = 0
        tampered = 0
        unstamped = 0
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
            if not isinstance(rec, dict):
                self._invalidate("record failed schema validation")
                return
            # Authentication FIRST: only records this install stamped
            # for this run dir are eligible for adoption; everything
            # else is skipped (counted, warned once below) and the
            # unit recomputes — never adopted, and never allowed to
            # drive whole-trail invalidation either (a forger must
            # not be able to rotate away the genuine records around
            # its plant). There is no unstamped legacy tier: this
            # file format has never existed without record tokens,
            # so an unstamped record is forged-or-foreign, not old
            # (no era fence needed).
            token = rec.get(TOKEN_KEY)
            if not token:
                unstamped += 1
                continue
            if not _verify_token(key, rec, token, self._run_binding):
                tampered += 1
                continue
            verified += 1
            # A VERIFIED record failing schema is our own writer drift
            # (only this module mints valid tokens) — the pre-existing
            # fail-open whole-trail invalidation is the right answer.
            if not self._ingest(rec):
                self._invalidate("record failed schema validation")
                return
        if tampered or unstamped:
            logger.warning(
                "sweep checkpoint %s: skipped %d unauthenticated "
                "record(s) (verified=%d tampered=%d unstamped=%d) — "
                "those units re-sweep (recompute, never adopt). The "
                "trail lives in a target-writable directory; an "
                "unauthenticated record there may be a forgery "
                "attempt",
                self._path, tampered + unstamped, verified, tampered,
                unstamped,
            )

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
        if (
            self._disabled or self._write_failed
            or not isinstance(result, SweepResult)
        ):
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
            # sort_keys matches dumps_canonical's failure profile: mixed
            # int/str dict keys raise TypeError on key comparison there,
            # so the probe must sort too or the stamp below would raise
            # on a payload this probe accepted.
            line = json.dumps(
                rec, separators=(",", ":"), allow_nan=False, sort_keys=True,
            )
        except (TypeError, ValueError):
            # This one result is not round-trippable — skip it alone.
            logger.debug(
                "sweep checkpoint: unserialisable result skipped",
                exc_info=True,
            )
            return
        # Stamp AFTER the round-trip probe above proved the payload
        # serialisable: the token authenticates the record's canonical
        # JSON, run-bound, so a future segment adopts it only when it
        # verifies under this install's key in this run dir.
        mac = self._mac_key
        if mac is None:  # unreachable behind _disabled; keeps types honest
            return
        rec[TOKEN_KEY] = _mint_token(mac, rec, self._run_binding)
        line = json.dumps(rec, separators=(",", ":"), allow_nan=False)
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
