"""Frozen-LLM-transcript record/replay for the detection pipeline.

Detection-quality evals need to re-run the CLASSIFICATION code against
the responses a real run produced — hermetically (no network, no cost,
deterministic). This module records every ``LLMClient.generate`` /
``generate_structured`` request/response pair into a JSONL transcript
during a live run, and replays those responses through the SAME client
surface on a later run, so new pipeline code can be evaluated against
frozen model behaviour.

Seam
----
The recorder sits at the ``LLMClient.generate`` / ``generate_structured``
call surface — the same chokepoint the structured-response cache
intercepts — via :class:`TranscriptLLMClient`, an ``LLMClient`` subclass
that wraps the two dispatch methods. Deliberately NOT at the provider
layer: providers see retries, fallbacks, and instructor re-asks as
separate wire calls, but the pipeline's semantic unit is "one client
call, one answer", and that is the unit an eval must replay. Consumers
opt in at construction time through :func:`build_llm_client` (adopted by
``core.llm.factory.get_client`` and the /analyze agent); no provider or
``LLMClient`` internals are touched.

Replay is served exactly where a cache hit is served: before model
resolution and provider dispatch. A replayed response therefore flows
through the same downstream handling a cached (i.e. previously live)
response does — for structured calls that includes the strict schema
floor (``unknown_response_fields``), and every consumer-side
validation (``validate_structured_response`` etc.) runs unchanged.
Replay mode is incapable of network or cost by construction: the
override never reaches model resolution, and ``_get_provider`` is
hard-blocked as belt-and-braces.

Keying
------
Prompts are NOT byte-stable across pipeline versions — that is the
point of the eval (old responses, new code). Matching is therefore
layered, most-specific first; every recorded entry is consumable at
most once (FIFO within each layer):

1. **Exact**: ``(method, sha256(prompt), sha256(system), sha256(schema))``
   — the fast path when nothing changed.
2. **Subject**: ``(method, call_class, subject)`` — ``subject`` is a
   caller-declared identity for the work item (finding id, function
   name), set via the :func:`transcript_subject` context manager.
   Robust to prompt-template changes AND to re-ordering of the work
   queue between record and replay.
3. **Positional**: ``(method, call_class)`` — same call class, served
   in recorded order. Subject-safe: a caller that declared a subject
   may only take subject-LESS entries here — a tagged entry never
   serves a different subject positionally (one new finding at the
   head of the queue would otherwise shift every later finding's
   verdict onto its neighbour); tagged-but-unmatched is a miss.
   Subject-less callers keep the full per-class pool (old
   transcripts / untagged call sites), and break when the replay run
   re-orders work within a call class (documented trade-off — declare
   subjects where ordering is not guaranteed).

Generation kwargs (temperature, max_tokens) and the model name are
deliberately excluded from all keys: an eval must be able to replay a
transcript through a config with no model at all (hermetic CI has no
credentials), and a temperature tweak must not orphan a corpus.
Multi-model panels are the known gap: two models analysing the same
finding share ``(method, call_class, subject)`` and fall back to
recorded order — adding the model alias to layer 2/3 keys is the
/audit-loop follow-up. An unmatched call raises
:class:`TranscriptReplayMiss` with a bounded, escaped miss report —
never a silent live dispatch (replay mode has no providers to
dispatch to).

Security
--------
Transcripts carry target-derived text (hostile) and whatever a run's
prompts contained (possibly secrets):

* **Write time**: every recorded string — response content, structured
  results, error messages, the prompt excerpt — passes through
  ``core.security.redaction.redact_secrets`` (the scorecard's write-
  time redaction chokepoint pattern). Response strings are NOT
  length-bounded (truncation would corrupt replay); the diagnostic
  prompt excerpt is bounded and non-printable-escaped.
* **Replay time**: recorded content re-enters at the cache-hit point
  and is treated as untrusted exactly like a live response — the
  strict schema floor re-runs against the CURRENT schema, and all
  consumer-side validation applies. Nothing from a transcript is
  interpolated into commands, prompts, or logs unescaped.
* A response that contained a secret replays with the ``[REDACTED]``
  placeholder — a deliberate trade-off (verdict fields, not echoed
  secrets, are what evals score).

Operator surface
----------------
``RAPTOR_LLM_TRANSCRIPT=record:<path>`` or ``replay:<path>`` (a
directory gets ``llm-transcript.jsonl`` appended). A garbled value
raises: silently ignoring ``record:`` would waste a paid run, and
silently ignoring ``replay:`` would dispatch live — the one failure
this module exists to prevent.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator

from core.json.jsonl import append_jsonl, load_jsonl
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMProvider, LLMResponse, StructuredResponse
from core.llm.response_validation import unknown_response_fields
from core.security.log_sanitisation import escape_nonprintable
from core.security.redaction import redact_secrets

logger = logging.getLogger(__name__)

__all__ = [
    "TranscriptError",
    "TranscriptLLMClient",
    "TranscriptRecorder",
    "TranscriptReplayMiss",
    "TranscriptReplayedError",
    "TranscriptReplayer",
    "active_transcript",
    "build_llm_client",
    "fence_unadopted_dispatch",
    "reset_active_transcript",
    "transcript_replay_active",
    "transcript_subject",
]

_ENV_VAR = "RAPTOR_LLM_TRANSCRIPT"
_DEFAULT_FILENAME = "llm-transcript.jsonl"
_RECORD_VERSION = 1
# Bounded diagnostic excerpt of the prompt kept per record — replay
# never re-sends prompts, this exists only so a miss report can say
# what the nearest recorded calls looked like.
_EXCERPT_CHARS = 200
# Memory bounds on transcript load. Transcripts travel through CI
# artifact stores, so the replayer must not buffer an arbitrary file:
# an oversize trail loads as empty (then fails the no-usable-entries
# gate loudly), an oversize line is skipped like a malformed one.
# A single record tops out well below 8 MiB (one response plus a
# bounded excerpt); 512 MiB total is thousands of the largest
# realistic records.
_MAX_LINE_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
# Cap on the per-class unconsumed-subject lists quoted into miss and
# leftover reports (diagnostic breadth, bounded output).
_REPORT_SUBJECTS_CAP = 10


class TranscriptError(RuntimeError):
    """Transcript record/replay failure (config, IO, or contract)."""


class TranscriptReplayMiss(TranscriptError):
    """Replay could not match a call to any recorded entry.

    Deliberately loud: replay mode must never fall through to a live
    provider, so an unmatched call is a hard stop for that call. The
    message carries the structured miss report.
    """


class TranscriptReplayedError(TranscriptError):
    """A recorded call FAILED during the live run; replay re-raises.

    Faithful replay of a failed call keeps the positional cursors of
    the surviving calls aligned. The original exception type is not
    reconstructed (arbitrary class instantiation from a transcript
    would be a deserialisation hazard) — callers with type-specific
    handling see this type instead; the original type name rides in
    the message.
    """


# ---------------------------------------------------------------------------
# Subject tagging
# ---------------------------------------------------------------------------

_subject_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "raptor_llm_transcript_subject", default=None,
)


@contextlib.contextmanager
def transcript_subject(subject: str | None) -> Iterator[None]:
    """Tag LLM calls inside the block with a work-item identity.

    The tag is recorded on every transcript entry written inside the
    block and joins the replay matching key (layer 2 — see module
    docstring). No-op-cheap when no transcript is active; safe to
    leave in place on hot paths.
    """
    token = _subject_var.set(subject)
    try:
        yield
    finally:
        _subject_var.reset(token)


def current_subject() -> str | None:
    """The subject tag in effect for the calling context, if any."""
    return _subject_var.get()


# ---------------------------------------------------------------------------
# Hashing / redaction helpers
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _schema_sha256(schema: dict[str, Any] | None) -> str | None:
    if schema is None:
        return None
    try:
        return _sha256(json.dumps(schema, sort_keys=True, default=str))
    except (TypeError, ValueError):
        return None


def _redact_tree(v: Any) -> Any:
    """Secret-redact every string reachable in a JSON-shaped value.

    Same write-time chokepoint idea as the scorecard's tree redaction
    (``core/llm/scorecard/scorecard.py``), minus its length bounding:
    a truncated response would replay corrupt, so transcript strings
    keep their full (redacted) length. Values here come from
    ``json``-parsed provider output, so the JSON types are the whole
    universe; anything exotic is str-coerced then redacted rather
    than written to disk unredacted.
    """
    if isinstance(v, str):
        return redact_secrets(v)
    if isinstance(v, dict):
        return {
            (redact_secrets(k) if isinstance(k, str) else k): _redact_tree(x)
            for k, x in v.items()
        }
    if isinstance(v, (list, tuple)):
        return [_redact_tree(x) for x in v]
    if v is None or isinstance(v, (bool, int, float)):
        return v
    return redact_secrets(str(v))


def _excerpt(text: str | None) -> str:
    """Bounded, redacted, non-printable-escaped prompt excerpt.

    Diagnostic only. Redaction FIRST (so a secret straddling the cut
    is not half-kept), then the bound, then escaping — the excerpt may
    be quoted into terminal-bound miss reports.
    """
    if not text:
        return ""
    redacted = redact_secrets(text)
    if len(redacted) > _EXCERPT_CHARS:
        redacted = redacted[:_EXCERPT_CHARS] + "…[elided]"
    return escape_nonprintable(redacted)


def _call_class(task_type: str | None, kwargs: dict[str, Any]) -> str:
    """Mirror ``LLMClient``'s call-class resolution (label, not popped:
    the real client pops its own copy downstream)."""
    return str(kwargs.get("call_class") or task_type or "unclassified")


# ---------------------------------------------------------------------------
# Recorder
# ---------------------------------------------------------------------------

class TranscriptRecorder:
    """Appends one JSON line per LLM call to the transcript trail.

    Writes go through ``core.json.jsonl.append_jsonl`` — O_APPEND +
    single write keeps concurrent workers line-atomic, O_NOFOLLOW
    refuses symlinked trail paths. All content is redacted at write
    time (see module docstring). Thread-safe.

    ``seq`` is PER-PROCESS (this recorder's own counter): multiple
    recording processes appending to one trail interleave their
    sequences. That is fine by design — replay matching keys on file
    order and the layered keys, never on ``seq``, which exists only
    for human diagnostics and miss reports.
    """

    mode = "record"

    def __init__(self, path: Path) -> None:
        self.path = _resolve_transcript_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._lock = threading.Lock()

    def _next_seq(self) -> int:
        with self._lock:
            seq = self._seq
            self._seq += 1
            return seq

    def _base_record(
        self,
        method: str,
        prompt: str,
        system_prompt: str | None,
        task_type: str | None,
        kwargs: dict[str, Any],
        schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        model_cfg = kwargs.get("model_config")
        return {
            "v": _RECORD_VERSION,
            "seq": self._next_seq(),
            "ts": time.time(),
            "method": method,
            "task_type": task_type,
            "call_class": _call_class(task_type, kwargs),
            "subject": current_subject(),
            "model_requested": getattr(model_cfg, "model_name", None),
            "prompt_sha256": _sha256(prompt),
            "system_sha256": _sha256(system_prompt or ""),
            "schema_sha256": _schema_sha256(schema),
            "prompt_excerpt": _excerpt(prompt),
        }

    def _append(self, record: dict[str, Any]) -> None:
        try:
            append_jsonl(self.path, record)
        except (OSError, TypeError, ValueError) as e:
            # A recording failure must not abort the paid live run —
            # but it must be loud: the transcript is the run's whole
            # point for whoever set record mode.
            logger.error(
                "LLM transcript write failed (%s) — entry seq=%s lost",
                e, record.get("seq"),
            )

    def record_generate(
        self,
        prompt: str,
        system_prompt: str | None,
        task_type: str | None,
        kwargs: dict[str, Any],
        response: LLMResponse,
    ) -> None:
        record = self._base_record(
            "generate", prompt, system_prompt, task_type, kwargs,
        )
        record["response"] = {
            "content": redact_secrets(response.content),
            "model": response.model,
            "provider": response.provider,
            "resolved_model": response.resolved_model,
            "finish_reason": response.finish_reason,
            "tokens_used": response.tokens_used,
            "cost": response.cost,
        }
        self._append(record)

    def record_generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any],
        system_prompt: str | None,
        task_type: str | None,
        kwargs: dict[str, Any],
        response: StructuredResponse,
    ) -> None:
        record = self._base_record(
            "generate_structured", prompt, system_prompt, task_type,
            kwargs, schema=schema,
        )
        record["response"] = {
            "result": _redact_tree(response.result),
            "raw": redact_secrets(response.raw),
            "model": response.model,
            "provider": response.provider,
            "resolved_model": response.resolved_model,
            "tokens_used": response.tokens_used,
            "cost": response.cost,
        }
        self._append(record)

    def record_error(
        self,
        method: str,
        prompt: str,
        system_prompt: str | None,
        task_type: str | None,
        kwargs: dict[str, Any],
        error: BaseException,
        schema: dict[str, Any] | None = None,
    ) -> None:
        """Record a FAILED call so replay stays sequence-faithful."""
        record = self._base_record(
            method, prompt, system_prompt, task_type, kwargs, schema=schema,
        )
        record["error"] = {
            "type": type(error).__name__,
            "message": _excerpt(str(error)),
        }
        self._append(record)


# ---------------------------------------------------------------------------
# Replayer
# ---------------------------------------------------------------------------

class TranscriptReplayer:
    """Serves recorded responses; incapable of live dispatch.

    Entries load once at construction; each is consumable at most once.
    Matching layers are documented in the module docstring. Thread-safe.
    """

    mode = "replay"

    def __init__(self, path: Path) -> None:
        self.path = _resolve_transcript_path(path)
        if not self.path.is_file():
            raise TranscriptError(
                f"transcript replay requested but {self.path} does not "
                "exist — refusing to run (replay mode never dispatches "
                "to a live provider)"
            )
        raw = load_jsonl(
            self.path,
            max_line_bytes=_MAX_LINE_BYTES,
            max_total_bytes=_MAX_TOTAL_BYTES,
        )
        self.entries: list[dict[str, Any]] = [
            e for e in raw
            if isinstance(e, dict) and isinstance(e.get("method"), str)
        ]
        if not self.entries:
            raise TranscriptError(
                f"transcript at {self.path} contains no usable entries"
            )
        dropped = len(raw) - len(self.entries)
        if dropped:
            logger.warning(
                "transcript %s: %d malformed entrie(s) ignored",
                self.path, dropped,
            )
        self._lock = threading.Lock()
        self._consumed: set[int] = set()
        # Misses observed so far — harnesses assert this is empty at
        # the end of an eval (per-finding error handling upstream may
        # swallow the raised TranscriptReplayMiss into an error-status
        # record; this ledger keeps the misses independently visible).
        self.misses: list[dict[str, Any]] = []
        # FIFO index lists per matching layer (entry positions).
        self._by_exact: dict[tuple, list[int]] = {}
        self._by_subject: dict[tuple, list[int]] = {}
        self._by_class: dict[tuple, list[int]] = {}
        # Positional pool for SUBJECT-DECLARING callers: subject-less
        # entries only. A subject-tagged entry must never be served
        # positionally to a DIFFERENT subject — one new finding at the
        # head of the queue would otherwise shift every later
        # finding's verdict onto its neighbour (silently wrong
        # verdicts, not misses). Subject-less callers keep the full
        # per-class pool (old transcripts / untagged call sites).
        self._by_class_untagged: dict[tuple, list[int]] = {}
        for i, entry in enumerate(self.entries):
            method = entry["method"]
            exact = (
                method,
                entry.get("prompt_sha256"),
                entry.get("system_sha256"),
                entry.get("schema_sha256"),
            )
            self._by_exact.setdefault(exact, []).append(i)
            call_class = entry.get("call_class") or "unclassified"
            subject = entry.get("subject")
            if subject is not None:
                key = (method, call_class, subject)
                self._by_subject.setdefault(key, []).append(i)
            else:
                self._by_class_untagged.setdefault(
                    (method, call_class), []).append(i)
            self._by_class.setdefault((method, call_class), []).append(i)

    # -- matching ----------------------------------------------------------

    def _take_first_unconsumed(self, indexes: list[int] | None) -> int | None:
        for i in indexes or ():
            if i not in self._consumed:
                self._consumed.add(i)
                return i
        return None

    def match(
        self,
        method: str,
        prompt: str,
        system_prompt: str | None,
        task_type: str | None,
        kwargs: dict[str, Any],
        schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        call_class = _call_class(task_type, kwargs)
        subject = current_subject()
        exact = (
            method,
            _sha256(prompt),
            _sha256(system_prompt or ""),
            _schema_sha256(schema),
        )
        with self._lock:
            idx = self._take_first_unconsumed(self._by_exact.get(exact))
            layer = "exact"
            if idx is None and subject is not None:
                idx = self._take_first_unconsumed(
                    self._by_subject.get((method, call_class, subject)),
                )
                layer = "subject"
            if idx is None:
                # Positional fallback is subject-safe: a caller that
                # DECLARED a subject may only take subject-less
                # entries here — serving another subject's tagged
                # entry would silently hand it that finding's verdict
                # (see the index comment). Subject-less callers keep
                # the full per-class pool.
                pool = (
                    self._by_class_untagged if subject is not None
                    else self._by_class
                )
                idx = self._take_first_unconsumed(
                    pool.get((method, call_class)),
                )
                layer = "positional"
            if idx is None:
                miss = self._miss_report(method, call_class, subject, prompt)
                self.misses.append(miss)
                raise TranscriptReplayMiss(
                    "transcript replay miss — no recorded entry matches "
                    "this call and replay never dispatches live.\n"
                    + json.dumps(miss, indent=2)
                )
        entry = self.entries[idx]
        if layer != "exact":
            logger.debug(
                "transcript replay: %s matched via %s layer (seq=%s)",
                method, layer, entry.get("seq"),
            )
        return entry

    def _miss_report(
        self,
        method: str,
        call_class: str,
        subject: str | None,
        prompt: str,
    ) -> dict[str, Any]:
        """Structured description of an unmatched call. Everything
        quoted here is bounded + escaped (prompt text is target-
        derived; recorded subjects derive from finding coordinates)."""
        return {
            "transcript": str(self.path),
            "requested_method": method,
            "requested_call_class": call_class,
            "requested_subject": (
                escape_nonprintable(subject) if subject is not None else None
            ),
            "requested_prompt_sha256": _sha256(prompt),
            "requested_prompt_excerpt": _excerpt(prompt),
            "unconsumed_by_class": self._unconsumed_by_class(),
            "unconsumed_subjects_by_class": self._unconsumed_subjects(),
            "consumed": len(self._consumed),
            "total": len(self.entries),
        }

    def _unconsumed_by_class(self) -> dict[str, int]:
        remaining: dict[str, int] = {}
        for (m, cc), idxs in self._by_class.items():
            left = sum(1 for i in idxs if i not in self._consumed)
            if left:
                remaining[f"{m}/{cc}"] = left
        return remaining

    def _unconsumed_subjects(self) -> dict[str, list[str]]:
        """Per-class bounded list of the SUBJECTS still unserved —
        the fastest way to see which findings a miss actually
        orphaned. Escaped (subjects derive from finding coordinates)
        and capped per class with an explicit elision marker."""
        out: dict[str, list[str]] = {}
        for (m, cc), idxs in self._by_class.items():
            subjects: list[str] = []
            extra = 0
            for i in idxs:
                if i in self._consumed:
                    continue
                subj = self.entries[i].get("subject")
                if subj is None:
                    continue
                if len(subjects) < _REPORT_SUBJECTS_CAP:
                    subjects.append(escape_nonprintable(str(subj)))
                else:
                    extra += 1
            if subjects:
                if extra:
                    subjects.append(f"…[+{extra} more]")
                out[f"{m}/{cc}"] = subjects
        return out

    def leftover_report(self) -> dict[str, Any]:
        """Entries never served — the CI gate's second failure signal
        beside ``misses``: a leftover means the replay run issued
        FEWER calls than the recorded run (a stage silently skipped,
        a finding dropped pre-LLM), which a miss-only check cannot
        see. Same bounded/escaped shape as the miss report's
        unconsumed sections."""
        with self._lock:
            return {
                "transcript": str(self.path),
                "consumed": len(self._consumed),
                "total": len(self.entries),
                "leftover": len(self.entries) - len(self._consumed),
                "unconsumed_by_class": self._unconsumed_by_class(),
                "unconsumed_subjects_by_class": self._unconsumed_subjects(),
            }

    # -- response reconstruction -------------------------------------------

    @staticmethod
    def _raise_recorded_error(entry: dict[str, Any]) -> None:
        err = entry.get("error")
        if isinstance(err, dict):
            raise TranscriptReplayedError(
                "recorded call failed during the live run "
                f"(seq={entry.get('seq')}, type="
                f"{escape_nonprintable(str(err.get('type')))}): "
                f"{escape_nonprintable(str(err.get('message')))}"
            )

    def replay_generate(
        self,
        prompt: str,
        system_prompt: str | None,
        task_type: str | None,
        kwargs: dict[str, Any],
    ) -> LLMResponse:
        entry = self.match(
            "generate", prompt, system_prompt, task_type, kwargs,
        )
        self._raise_recorded_error(entry)
        resp = entry.get("response")
        if not isinstance(resp, dict) or not isinstance(
                resp.get("content"), str):
            raise TranscriptReplayMiss(
                f"transcript entry seq={entry.get('seq')} carries no "
                "usable generate response"
            )
        return LLMResponse(
            content=resp["content"],
            model=str(resp.get("model") or ""),
            provider=str(resp.get("provider") or "transcript"),
            tokens_used=0,
            cost=0.0,
            finish_reason=str(resp.get("finish_reason") or "stop"),
            duration=0.0,
            resolved_model=resp.get("resolved_model"),
        )

    def replay_generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any],
        system_prompt: str | None,
        task_type: str | None,
        kwargs: dict[str, Any],
    ) -> StructuredResponse:
        entry = self.match(
            "generate_structured", prompt, system_prompt, task_type,
            kwargs, schema=schema,
        )
        self._raise_recorded_error(entry)
        resp = entry.get("response")
        if not isinstance(resp, dict) or not isinstance(
                resp.get("result"), dict):
            raise TranscriptReplayMiss(
                f"transcript entry seq={entry.get('seq')} carries no "
                "usable structured response"
            )
        result = resp["result"]
        # Strict schema floor — the same last-hop rejection the live
        # and cached paths apply, re-run against the CURRENT schema.
        # Recorded content is untrusted; a transcript written by an
        # older schema (or tampered with) must not smuggle unrequested
        # fields into downstream consumers.
        unknown = unknown_response_fields(result, schema)
        if unknown:
            raise TranscriptReplayMiss(
                f"transcript entry seq={entry.get('seq')} fails the "
                f"strict schema floor (unknown fields "
                f"{[escape_nonprintable(str(u)) for u in unknown]}) — "
                "rejected exactly like a stale cache entry"
            )
        return StructuredResponse(
            result=result,
            raw=str(resp.get("raw") or ""),
            cost=0.0,
            tokens_used=0,
            model=str(resp.get("model") or ""),
            provider=str(resp.get("provider") or "transcript"),
            duration=0.0,
            cached=True,
            resolved_model=resp.get("resolved_model"),
        )


# ---------------------------------------------------------------------------
# Session resolution (env-driven, process-global)
# ---------------------------------------------------------------------------

def _resolve_transcript_path(path: Path) -> Path:
    path = Path(path)
    if path.is_dir():
        return path / _DEFAULT_FILENAME
    return path


def _parse_env(value: str) -> tuple[str, Path]:
    mode, sep, raw_path = value.partition(":")
    mode = mode.strip().lower()
    if not sep or mode not in ("record", "replay") or not raw_path.strip():
        raise TranscriptError(
            f"garbled {_ENV_VAR} value (want record:<path> or "
            "replay:<path>) — refusing to guess: silently dropping "
            "record mode wastes a paid run, silently dropping replay "
            "mode would dispatch live"
        )
    return mode, Path(raw_path.strip())


_active_lock = threading.Lock()
_active: TranscriptRecorder | TranscriptReplayer | None = None
_active_resolved = False


def active_transcript() -> TranscriptRecorder | TranscriptReplayer | None:
    """The process-global transcript session, resolved lazily from
    ``RAPTOR_LLM_TRANSCRIPT``. One session per process so parallel
    workers share the sequence counter (record) and the consumption
    cursors (replay)."""
    global _active, _active_resolved
    with _active_lock:
        if _active_resolved:
            return _active
        value = os.environ.get(_ENV_VAR, "").strip()
        if value:
            mode, path = _parse_env(value)
            if mode == "record":
                _active = TranscriptRecorder(path)
            else:
                _active = TranscriptReplayer(path)
            logger.info(
                "LLM transcript %s mode active: %s", mode, _active.path,
            )
        _active_resolved = True
        return _active


def reset_active_transcript() -> None:
    """Drop the cached session so the next :func:`active_transcript`
    re-reads the environment. For tests and long-lived harnesses that
    flip modes between phases."""
    global _active, _active_resolved
    with _active_lock:
        _active = None
        _active_resolved = False


def fence_unadopted_dispatch(surface: str) -> None:
    """Honesty fence for LLM-dispatch surfaces NOT yet transcript-
    adopted (they construct plain ``LLMClient``s outside the seam).

    Replay: hard refusal — the surface would silently dispatch LIVE
    (network + cost) while the operator believes the run is hermetic.
    Record: loud warning — the run proceeds but the transcript will
    under-record, so a later replay of it through an adopted surface
    would miss. No-op when no transcript session is active.

    ``surface`` is an operator-facing constant naming the code path
    (no target-derived text).
    """
    session = active_transcript()
    if session is None:
        return
    if session.mode == "replay":
        raise TranscriptError(
            f"{surface} is not transcript-adopted — it constructs LLM "
            "clients outside the record/replay seam, so running it "
            "under RAPTOR_LLM_TRANSCRIPT=replay:… would dispatch live "
            "(network + cost) instead of replaying. Use the "
            "sequential /analyze path for transcript replays, or "
            "unset the transcript variable."
        )
    logger.warning(
        "%s constructs LLM clients outside the transcript seam — its "
        "calls will NOT be recorded to %s (the transcript will "
        "under-record this run).", surface, session.path,
    )


def transcript_replay_active() -> bool:
    """True when this process runs in transcript-replay mode.

    Consumers use this to take their external-LLM code path without an
    external provider being configured (hermetic CI eval runs)."""
    session = active_transcript()
    return session is not None and session.mode == "replay"


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

# Inert stand-in primary for replay-mode configs with no provider
# configured. Never dispatched: the replay overrides return before
# model resolution, and ``_get_provider`` is hard-blocked.
_REPLAY_PLACEHOLDER = ModelConfig(
    provider="replay",
    model_name="transcript-replay",
    cost_per_1k_tokens=0.0,
)


class TranscriptLLMClient(LLMClient):
    """``LLMClient`` with the transcript seam on its dispatch surface.

    Record mode delegates to the real client (cache, retries, budget —
    everything unchanged) and appends the request/response pair, or
    the failure, afterwards. Replay mode serves recorded responses
    before model resolution and never reaches a provider.
    """

    def __init__(
        self,
        config: LLMConfig | None = None,
        *,
        session: TranscriptRecorder | TranscriptReplayer,
        **kwargs: Any,
    ) -> None:
        super().__init__(config, **kwargs)
        self.transcript_session = session

    def _get_provider(self, model_config: ModelConfig) -> LLMProvider:
        if self.transcript_session.mode == "replay":
            # Belt-and-braces: no internal or external path may reach
            # a provider in replay mode (replay = no network, no cost).
            raise TranscriptError(
                "transcript replay mode: provider dispatch is forbidden "
                f"(requested {model_config.provider}/"
                f"{model_config.model_name})"
            )
        return super()._get_provider(model_config)

    def generate(self, prompt: str, system_prompt: str | None = None,
                 task_type: str | None = None, **kwargs: Any) -> LLMResponse:
        # isinstance, not `.mode`: narrows the session union so the
        # replay/record method calls below type-check.
        session = self.transcript_session
        if isinstance(session, TranscriptReplayer):
            return session.replay_generate(
                prompt, system_prompt, task_type, kwargs,
            )
        try:
            response = super().generate(
                prompt, system_prompt=system_prompt, task_type=task_type,
                **kwargs,
            )
        except Exception as e:
            session.record_error(
                "generate", prompt, system_prompt, task_type, kwargs, e,
            )
            raise
        session.record_generate(
            prompt, system_prompt, task_type, kwargs, response,
        )
        return response

    def generate_structured(
        self, prompt: str, schema: dict[str, Any],
        system_prompt: str | None = None,
        task_type: str | None = None, **kwargs: Any,
    ) -> StructuredResponse:
        # Same isinstance narrowing as ``generate``.
        session = self.transcript_session
        if isinstance(session, TranscriptReplayer):
            return session.replay_generate_structured(
                prompt, schema, system_prompt, task_type, kwargs,
            )
        try:
            response = super().generate_structured(
                prompt, schema, system_prompt=system_prompt,
                task_type=task_type, **kwargs,
            )
        except Exception as e:
            session.record_error(
                "generate_structured", prompt, system_prompt, task_type,
                kwargs, e, schema=schema,
            )
            raise
        session.record_generate_structured(
            prompt, schema, system_prompt, task_type, kwargs, response,
        )
        return response


def build_llm_client(
    config: LLMConfig | None = None, **kwargs: Any,
) -> LLMClient:
    """Construct an ``LLMClient``, transcript-aware.

    The one construction helper transcript-adopting call sites use:
    with no ``RAPTOR_LLM_TRANSCRIPT`` in the environment this is
    exactly ``LLMClient(config, **kwargs)``. In record mode the client
    additionally appends every call to the transcript; in replay mode
    the client serves recorded responses and needs no provider — a
    config without a primary model gets an inert placeholder so
    banner/budget code paths keep working, with fallbacks and caching
    disabled (nothing to fall back to or cache).
    """
    session = active_transcript()
    if session is None:
        return LLMClient(config, **kwargs)
    if session.mode == "replay":
        cfg = config if config is not None else LLMConfig(
            primary_model=None, fallback_models=[],
        )
        if cfg.primary_model is None:
            cfg = replace(
                cfg,
                primary_model=_REPLAY_PLACEHOLDER,
                fallback_models=[],
                enable_fallback=False,
                enable_caching=False,
            )
        return TranscriptLLMClient(cfg, session=session, **kwargs)
    return TranscriptLLMClient(config, session=session, **kwargs)
